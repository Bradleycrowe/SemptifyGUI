from flask import Flask, render_template, request, redirect, send_file, jsonify, abort, session
import os
from datetime import datetime
import json
import requests
import time
import threading
import hashlib
from collections import deque, defaultdict

# -----------------------------
# Rate limiting (simple sliding window) & config
# -----------------------------
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('ADMIN_RATE_WINDOW', '60'))
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get('ADMIN_RATE_MAX', '60'))  # per window per IP
_RATE_HISTORY = defaultdict(lambda: deque())  # key -> deque[timestamps]
_rate_lock = threading.Lock()

def _rate_limit(key: str) -> bool:
    """Return True if allowed, False if over limit."""
    if RATE_LIMIT_MAX_REQUESTS <= 0:
        return True
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        dq = _RATE_HISTORY[key]
        # Purge old
        while dq and dq[0] < window_start:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        dq.append(now)
    return True

# In-memory metrics (simple counters; reset on restart)
METRICS = {
    'requests_total': 0,
    'admin_requests_total': 0,
    'admin_actions_total': 0,
    'errors_total': 0,
    'releases_total': 0,
    'rate_limited_total': 0,
    'breakglass_used_total': 0,
    'token_rotations_total': 0,
}
_metrics_lock = threading.Lock()

def _inc(metric: str, amt: int = 1):
    with _metrics_lock:
        METRICS[metric] = METRICS.get(metric, 0) + amt

def _metrics_text() -> str:
    """Generate Prometheus-compatible metrics with HELP and TYPE annotations."""
    lines = []
    
    # Metric metadata (HELP and TYPE)
    metrics_meta = {
        'requests_total': {
            'help': 'Total number of HTTP requests received',
            'type': 'counter'
        },
        'admin_requests_total': {
            'help': 'Total number of admin route requests (after successful authorization)',
            'type': 'counter'
        },
        'admin_actions_total': {
            'help': 'Total number of mutating admin operations (releases, workflow triggers)',
            'type': 'counter'
        },
        'errors_total': {
            'help': 'Total number of errors encountered',
            'type': 'counter'
        },
        'releases_total': {
            'help': 'Total number of release tags created',
            'type': 'counter'
        },
        'rate_limited_total': {
            'help': 'Total number of rate-limited requests',
            'type': 'counter'
        },
        'breakglass_used_total': {
            'help': 'Total number of break-glass authentication events',
            'type': 'counter'
        },
        'token_rotations_total': {
            'help': 'Total number of admin token rotations',
            'type': 'counter'
        }
    }
    
    # Output metrics with HELP and TYPE annotations
    for metric_name, metric_value in METRICS.items():
        if metric_name in metrics_meta:
            meta = metrics_meta[metric_name]
            lines.append(f"# HELP {metric_name} {meta['help']}")
            lines.append(f"# TYPE {metric_name} {meta['type']}")
        lines.append(f"{metric_name} {metric_value}")
    
    return "\n".join(lines) + "\n"

app = Flask(__name__)
# Secret key for session/CSRF (set FLASK_SECRET in production)
app.secret_key = os.environ.get('FLASK_SECRET', os.urandom(32))

# Required folders
folders = ["uploads", "logs", "copilot_sync", "final_notices", "security"]

# Create folders if missing
for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)

def _rotate_if_needed(path: str):
    max_bytes = int(os.environ.get('LOG_MAX_BYTES', '1048576'))  # 1 MB default
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size < max_bytes:
            return
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        rotated = f"{path}.{ts}"
        os.rename(path, rotated)
    except Exception:
        pass

def _append_log(line: str):
    log_path_local = os.path.join("logs", "init.log")
    _rotate_if_needed(log_path_local)
    timestamp_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path_local, "a") as f:
        f.write(f"[{timestamp_local}] {line}\n")

def _event_log(event: str, **fields):
    """Structured JSON event log (append-only)."""
    log_path = os.path.join('logs', 'events.log')
    _rotate_if_needed(log_path)
    payload = {
        'ts': datetime.utcnow().isoformat() + 'Z',
        'event': event,
        **fields
    }
    try:
        with open(log_path, 'a') as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        _append_log(f"event_log_error {e}")

# Security mode: "open" (no admin token enforced) or "enforced"
SECURITY_MODE = os.environ.get("SECURITY_MODE", "open").lower()
if SECURITY_MODE not in ("open", "enforced"):
    SECURITY_MODE = "open"

# Log initialization (and security mode)
_append_log(f"SemptifyGUI initialized with folders: {', '.join(folders)} | security_mode={SECURITY_MODE}")

@app.route("/")
def index():
    # Use a Jinja2 template so UI can be extended without changing the route.
    message = "SemptifyGUI is live. Buttons coming next."
    _inc('requests_total')
    
    # Folder descriptions for the landing page
    folder_descriptions = {
        'uploads': 'File uploads and temporary processing',
        'logs': 'Application logs and event history',
        'copilot_sync': 'Copilot synchronization data',
        'final_notices': 'Generated notices and documents',
        'security': 'Token files and security credentials'
    }
    
    return render_template("index.html", 
                         message=message, 
                         folders=folders,
                         folder_descriptions=folder_descriptions)


@app.route("/health")
def health():
    _inc('requests_total')
    return "OK", 200

@app.route("/healthz")
def healthz():
    _inc('requests_total')
    return jsonify({
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
        "folders": folders,
    }), 200

@app.route("/version")
def version():
    _inc('requests_total')
    git_sha = os.environ.get("GIT_SHA", "unknown")
    build_time = os.environ.get("BUILD_TIME", "unknown")
    return jsonify({
        "git_sha": git_sha,
        "build_time": build_time,
        "app": "SemptifyGUI"
    }), 200

@app.route('/metrics')
def metrics():
    _inc('requests_total')
    txt = _metrics_text()
    return txt, 200, { 'Content-Type': 'text/plain; version=0.0.4' }


TOKENS_CACHE = { 'loaded_at': 0, 'tokens': [], 'path': os.path.join('security','admin_tokens.json'), 'mtime': None }

def _hash_token(raw: str) -> str:
    return 'sha256:' + hashlib.sha256(raw.encode('utf-8')).hexdigest()

def _load_tokens(force: bool=False):
    path = TOKENS_CACHE['path']
    try:
        if not os.path.exists(path):
            if force:
                TOKENS_CACHE['tokens'] = []
            return
        mtime = os.path.getmtime(path)
        if force or TOKENS_CACHE['mtime'] != mtime:
            with open(path,'r') as f:
                data = json.load(f)
            # Normalize
            norm = []
            for entry in data:
                if not entry.get('enabled', True):
                    continue
                h = entry.get('hash')
                if not h:
                    continue
                norm.append({
                    'id': entry.get('id','unknown'),
                    'hash': h,
                    'breakglass': entry.get('breakglass', False)
                })
            TOKENS_CACHE['tokens'] = norm
            TOKENS_CACHE['mtime'] = mtime
    except Exception as e:
        _append_log(f"token_load_error {e}")

def _match_token(raw: str):
    if raw is None:
        return None
    _load_tokens()
    h = _hash_token(raw)
    for t in TOKENS_CACHE['tokens']:
        if t['hash'] == h:
            return t
    return None

def _get_admin_token_legacy():
    # Legacy single-token fallback
    return app.config.get('ADMIN_TOKEN') or os.environ.get('ADMIN_TOKEN', 'devtoken')

def _is_authorized(req) -> bool:
    """Authorization logic with multi-token & optional break-glass.

    open mode: always True.
    enforced: verify against tokens file (hash matches). If no file, fallback to legacy single token.
    break-glass: requires security/breakglass.flag present AND token marked breakglass.
    After successful break-glass use, flag file is removed (one-shot) and event logged.
    """
    if SECURITY_MODE == "open":
        return True
    supplied = req.args.get('token') or req.headers.get('X-Admin-Token') or req.form.get('token')
    # Primary multi-token path
    token_entry = _match_token(supplied)
    if token_entry:
        _event_log('admin_auth', method='multi-token', token_id=token_entry['id'], path=req.path, ip=req.remote_addr)
        return True
    # Break-glass path
    flag_path = os.path.join('security','breakglass.flag')
    if os.path.exists(flag_path):
        token_entry = _match_token(supplied)
        if token_entry and token_entry.get('breakglass'):
            try:
                os.remove(flag_path)
            except OSError:
                pass
            _event_log('breakglass_used', token_id=token_entry['id'], path=req.path, ip=req.remote_addr)
            _inc('breakglass_used_total')
            return True
    # Legacy single token fallback (for transitional period)
    legacy = _get_admin_token_legacy()
    if supplied == legacy:
        _event_log('admin_auth', method='legacy-token', token_id='legacy', path=req.path, ip=req.remote_addr)
        return True
    return False

def _require_admin_or_401():
    if not _is_authorized(request):
        _append_log(f"UNAUTHORIZED admin attempt path={request.path} ip={request.remote_addr}")
        _event_log('admin_unauthorized', path=request.path, ip=request.remote_addr)
        _inc('errors_total')
        return False
    # Apply rate limiting AFTER auth so attackers do not cause noise with unauth attempts
    rl_key = f"admin:{request.remote_addr}:{request.path}"
    if not _rate_limit(rl_key):
        _append_log(f"RATE_LIMIT path={request.path} ip={request.remote_addr}")
        _event_log('rate_limited', path=request.path, ip=request.remote_addr)
        _inc('errors_total')
        _inc('rate_limited_total')
        return False
    if SECURITY_MODE == "open":
        # Still log accesses to admin endpoints while open
        _append_log(f"OPEN_MODE admin access path={request.path} ip={request.remote_addr}")
    _inc('admin_requests_total')
    return True

def _get_or_create_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = hashlib.sha256(os.urandom(32)).hexdigest()
        session['_csrf_token'] = token
    return token

def _validate_csrf(req):
    # Only enforce CSRF for state-changing POST requests when enforced mode is active
    if SECURITY_MODE != 'enforced':
        return True
    sent = req.form.get('csrf_token') or req.headers.get('X-CSRF-Token')
    token = session.get('_csrf_token')
    if not token or not sent or sent != token:
        _append_log(f"CSRF_FAIL path={req.path} ip={req.remote_addr}")
        _event_log('csrf_fail', path=req.path, ip=req.remote_addr)
        _inc('errors_total')
        return False
    return True


@app.route('/admin', methods=['GET'])
def admin():
    # Simple token check
    if not _require_admin_or_401():
        return "Unauthorized", 401

    owner = os.environ.get('GITHUB_OWNER', 'Bradleycrowe')
    repo = os.environ.get('GITHUB_REPO', 'SemptifyGUI')
    ci_url = f"https://github.com/{owner}/{repo}/actions"
    pages_url = f"https://{owner}.github.io/{repo}/"
    # Expose token ids (not hashes) for visibility if enforced
    _load_tokens()
    token_ids = [t['id'] + (' (breakglass)' if t.get('breakglass') else '') for t in TOKENS_CACHE['tokens']]
    csrf_token = _get_or_create_csrf_token()
    return render_template('admin.html',
                           ci_url=ci_url,
                           pages_url=pages_url,
                           folders=folders,
                           security_mode=SECURITY_MODE,
                           token_ids=token_ids,
                           admin_token=_get_admin_token_legacy(),
                           csrf_token=csrf_token)

@app.route('/admin/status')
def admin_status():
    if not _require_admin_or_401():
        return "Unauthorized", 401
    _inc('admin_requests_total')
    _load_tokens()
    token_summaries = [{'id': t['id'], 'breakglass': t.get('breakglass', False)} for t in TOKENS_CACHE['tokens']]
    return jsonify({
        'security_mode': SECURITY_MODE,
        'metrics': METRICS,
        'tokens': token_summaries,
        'time': datetime.utcnow().isoformat() + 'Z'
    })


@app.route('/release_now', methods=['POST'])
def release_now():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    if not _require_admin_or_401():
        return "Unauthorized", 401

    # Soft confirmation: require hidden field confirm_release=yes
    if request.form.get('confirm_release') != 'yes':
        return abort(400, description="Missing confirmation field")

    github_token = os.environ.get('GITHUB_TOKEN')
    owner = os.environ.get('GITHUB_OWNER', 'Bradleycrowe')
    repo = os.environ.get('GITHUB_REPO', 'SemptifyGUI')
    if not github_token:
        _append_log('release_now failed: missing GITHUB_TOKEN')
        return "GITHUB_TOKEN not configured on server", 500

    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    # Get latest commit SHA from default branch (main)
    ref_url = f'https://api.github.com/repos/{owner}/{repo}/git/refs/heads/main'
    r = requests.get(ref_url, headers=headers)
    if r.status_code != 200:
        _append_log(f'release_now failed: cannot read ref: {r.status_code}')
        return f'Failed to read ref: {r.status_code}', 500
    sha = r.json().get('object', {}).get('sha')

    # Create a timestamped tag
    tag_name = f'v{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
    create_ref_url = f'https://api.github.com/repos/{owner}/{repo}/git/refs'
    payload = { 'ref': f'refs/tags/{tag_name}', 'sha': sha }
    r = requests.post(create_ref_url, headers=headers, json=payload)
    if r.status_code in (201, 200):
        _append_log(f'Created tag {tag_name} via API')
        _event_log('release_created', tag=tag_name, sha=sha, ip=request.remote_addr)
        _inc('releases_total')
        _inc('admin_actions_total')
        # record release in release-log.json
        log_path = os.path.join('logs', 'release-log.json')
        entry = { 'tag': tag_name, 'sha': sha, 'timestamp': datetime.utcnow().isoformat() }
        try:
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    data = json.load(f)
            else:
                data = []
            data.insert(0, entry)
            with open(log_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            _append_log(f'Failed to write release-log.json: {e}')

        return redirect(f'https://github.com/{owner}/{repo}/releases/tag/{tag_name}')
    else:
        _append_log(f'Failed to create tag: {r.status_code} {r.text}')
        return f'Failed to create tag: {r.status_code}', 500


@app.route('/trigger_workflow', methods=['POST'])
def trigger_workflow():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    if not _require_admin_or_401():
        return "Unauthorized", 401

    if request.form.get('confirm_trigger') != 'yes':
        return abort(400, description="Missing confirmation field")

    workflow = request.form.get('workflow', 'ci.yml')
    ref = request.form.get('ref', 'main')
    github_token = os.environ.get('GITHUB_TOKEN')
    owner = os.environ.get('GITHUB_OWNER', 'Bradleycrowe')
    repo = os.environ.get('GITHUB_REPO', 'SemptifyGUI')
    if not github_token:
        return "GITHUB_TOKEN not configured", 500

    headers = { 'Authorization': f'token {github_token}', 'Accept': 'application/vnd.github.v3+json' }
    dispatch_url = f'https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches'
    payload = { 'ref': ref }
    r = requests.post(dispatch_url, headers=headers, json=payload)
    if r.status_code in (204, 201):
        _append_log(f'Triggered workflow {workflow} on {ref}')
        _event_log('workflow_dispatch', workflow=workflow, ref=ref, ip=request.remote_addr)
        _inc('admin_actions_total')
        return redirect(f'https://github.com/{owner}/{repo}/actions')
    else:
        _append_log(f'Failed to trigger workflow {workflow}: {r.status_code} {r.text}')
        return f'Failed to trigger workflow: {r.status_code}', 500


@app.route('/release_history')
def release_history():
    if not _require_admin_or_401():
        return "Unauthorized", 401
    _inc('admin_requests_total')
    log_path = os.path.join('logs', 'release-log.json')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            data = json.load(f)
    else:
        data = []
    return render_template('release_history.html', data=data)


@app.route('/sbom')
def sbom_list():
    if not _require_admin_or_401():
        return "Unauthorized", 401
    _inc('admin_requests_total')
    sbom_dir = os.path.join('.', 'sbom')
    files = []
    if os.path.exists(sbom_dir):
        files = sorted(os.listdir(sbom_dir), reverse=True)
    supplied = request.args.get('token') or request.form.get('token') or request.headers.get('X-Admin-Token')
    return render_template('sbom_list.html', files=files, token=supplied)


@app.route('/sbom/<path:filename>')
def sbom_get(filename):
    if not _require_admin_or_401():
        return "Unauthorized", 401
    _inc('admin_requests_total')
    sbom_dir = os.path.join('.', 'sbom')
    path = os.path.join(sbom_dir, filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "Not found", 404

@app.route('/offline')
def offline():
    # Simple offline fallback route (also cached by SW if added there)
    _inc('requests_total')
    return "You are offline. Limited functionality.", 200, { 'Content-Type': 'text/plain' }

# -----------------------------
# Token rotation endpoint
# -----------------------------
def _write_tokens(tokens: list):
    path = TOKENS_CACHE['path']
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(tokens, f, indent=2)
        # force reload
        _load_tokens(force=True)
    except Exception as e:
        _append_log(f"token_write_error {e}")

@app.route('/rotate_token', methods=['POST'])
def rotate_token():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    if not _require_admin_or_401():
        return "Unauthorized", 401
    # current auth token already validated; now require target id & new token value
    target_id = request.form.get('target_id')
    new_value = request.form.get('new_value')
    if not target_id or not new_value:
        return "Missing target_id or new_value", 400
    path = TOKENS_CACHE['path']
    if not os.path.exists(path):
        return "Token file missing", 400
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return f"Failed to read tokens: {e}", 500
    found = False
    for entry in data:
        if entry.get('id') == target_id:
            entry['hash'] = _hash_token(new_value)
            found = True
            break
    if not found:
        return "Target token id not found", 404
    _write_tokens(data)
    _event_log('token_rotated', token_id=target_id, ip=request.remote_addr)
    _inc('token_rotations_total')
    return redirect('/admin')

if __name__ == "__main__":
    app.run(debug=True)
