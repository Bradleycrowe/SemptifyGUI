from flask import Flask, render_template, request, redirect, send_file, jsonify, abort, session
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timezone
import json
import requests
import time
import base64
import secrets
import threading
import hashlib
import uuid
from collections import deque, defaultdict
from typing import Optional, Callable

# -----------------------------
# Rate limiting (simple sliding window) & config
# -----------------------------
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('ADMIN_RATE_WINDOW', '60'))
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get('ADMIN_RATE_MAX', '60'))  # per window per IP
RATE_LIMIT_STATUS = int(os.environ.get('ADMIN_RATE_STATUS', '429'))  # HTTP status for rate limiting
RATE_LIMIT_RETRY_AFTER = int(os.environ.get('ADMIN_RATE_RETRY_AFTER', os.environ.get('ADMIN_RATE_WINDOW', '60')))  # seconds clients should wait before retry
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
_START_TIME = time.time()

def _inc(metric: str, amt: int = 1):
    with _metrics_lock:
        METRICS[metric] = METRICS.get(metric, 0) + amt

def _metrics_text() -> str:
    # Expose simple Prometheus style with HELP/TYPE
    help_map = {
        'requests_total': 'Total HTTP requests (all endpoints)',
        'admin_requests_total': 'Total authenticated admin requests',
        'admin_actions_total': 'Total mutating admin actions performed',
        'errors_total': 'Total error responses (admin + general)',
        'releases_total': 'Total release tags created via UI',
        'rate_limited_total': 'Total admin requests blocked by rate limiting',
        'breakglass_used_total': 'Total successful break-glass authentications',
        'token_rotations_total': 'Total admin token rotations executed'
    }
    lines = []
    for k, v in METRICS.items():
        if k in help_map:
            lines.append(f"# HELP {k} {help_map[k]}")
            lines.append(f"# TYPE {k} counter")
        lines.append(f"{k} {v}")
    # Dynamic uptime gauge (not stored in METRICS since it changes continuously)
    uptime = int(time.time() - _START_TIME)
    lines.append("# HELP uptime_seconds Application uptime in seconds")
    lines.append("# TYPE uptime_seconds gauge")
    lines.append(f"uptime_seconds {uptime}")
    return "\n".join(lines) + "\n"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Make template/static paths explicit so deployment environments with different CWDs still resolve correctly
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
# Secret key for session/CSRF (set FLASK_SECRET in production)
app.secret_key = os.environ.get('FLASK_SECRET', os.urandom(32))

# Required folders
folders = ["uploads", "logs", "copilot_sync", "final_notices", "security"]

# Create folders if missing
for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)

def _bootstrap_tokens_if_needed():
    """If in enforced mode and tokens file missing but ADMIN_TOKEN env provided, create a single-entry tokens file.
    This eases first-time hardened deployments without manually crafting JSON. Idempotent: does nothing if file exists.
    """
    if _current_security_mode() != 'enforced':
        return
    path = os.path.join('security','admin_tokens.json')
    if os.path.exists(path):
        return
    legacy = os.environ.get('ADMIN_TOKEN')
    if not legacy:
        return
    entry = [{ 'id': 'legacy-bootstrap', 'hash': _hash_token(legacy), 'enabled': True }]
    try:
        with open(path,'w') as f:
            json.dump(entry, f, indent=2)
        _append_log('Bootstrapped admin_tokens.json from ADMIN_TOKEN env (legacy-bootstrap)')
        _event_log('tokens_bootstrap_created')
    except Exception as e:  # pragma: no cover
        _append_log(f'tokens_bootstrap_failed {e}')

def _utc_now():
    """Return an aware UTC datetime."""
    return datetime.now(timezone.utc)

def _utc_now_iso():
    """Return RFC3339-ish UTC timestamp with trailing Z."""
    return _utc_now().isoformat().replace('+00:00', 'Z')

def _rotate_if_needed(path: str):
    max_bytes = int(os.environ.get('LOG_MAX_BYTES', '1048576'))  # 1 MB default
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size < max_bytes:
            return
        ts = _utc_now().strftime('%Y%m%d%H%M%S')
        rotated = f"{path}.{ts}"
        os.rename(path, rotated)
    except Exception:
        # Silent failure; rotation is best-effort
        pass

def _append_log(line: str):
    log_path_local = os.path.join("logs", "init.log")
    _rotate_if_needed(log_path_local)
    timestamp_local = _utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path_local, "a") as f:
        f.write(f"[{timestamp_local}] {line}\n")

def _event_log(event: str, **fields):
    """Structured JSON event log (append-only)."""
    log_path = os.path.join('logs', 'events.log')
    _rotate_if_needed(log_path)
    payload = {
        'ts': _utc_now_iso(),
        'event': event,
        **fields
    }
    try:
        with open(log_path, 'a') as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        _append_log(f"event_log_error {e}")

def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# -----------------------------
# Users registry for Document Vault
# -----------------------------
USERS_CACHE = {
    'path': os.path.join('security', 'users.json'),
    'mtime': None,
    'users': []  # list of { id, name, hash, enabled }
}

def _load_users(force: bool = False):
    path = USERS_CACHE['path']
    try:
        if not os.path.exists(path):
            if force:
                USERS_CACHE['users'] = []
            return
        mtime = os.path.getmtime(path)
        if force or USERS_CACHE['mtime'] != mtime:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            norm = []
            for u in data:
                if not u.get('enabled', True):
                    continue
                if 'hash' not in u or 'id' not in u:
                    continue
                norm.append({
                    'id': u.get('id'),
                    'name': u.get('name', u.get('id')),
                    'hash': u.get('hash'),
                    'enabled': True
                })
            USERS_CACHE['users'] = norm
            USERS_CACHE['mtime'] = mtime
    except Exception as e:  # pragma: no cover
        _append_log(f"users_load_error {e}")

def _write_users(users: list) -> None:
    path = USERS_CACHE['path']
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
        USERS_CACHE['mtime'] = os.path.getmtime(path)
        USERS_CACHE['users'] = [
            { 'id': u.get('id'), 'name': u.get('name', u.get('id')), 'hash': u.get('hash'), 'enabled': u.get('enabled', True) }
            for u in users if u.get('hash') and u.get('id') and u.get('enabled', True)
        ]
    except Exception as e:  # pragma: no cover
        _append_log(f"users_write_error {e}")

def _match_user_token(raw: Optional[str]):
    if not raw:
        return None
    _load_users()
    h = _hash_token(raw)
    for u in USERS_CACHE['users']:
        if u['hash'] == h:
            return u
    return None

def _require_user_or_401():
    """Authenticate a regular user for the Document Vault.
    Accept token via query, header, or form. Returns user dict or (json,401).
    """
    supplied = request.args.get('user_token') or request.headers.get('X-User-Token') or request.form.get('user_token')
    user = _match_user_token(supplied)
    if not user:
        _event_log('user_unauthorized', path=request.path, ip=request.remote_addr)
        return None
    return user

def _new_user_id() -> str:
    # Timestamp-based id to keep simple and unique enough for MVP
    return f"u{_utc_now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6]}"

def _random_token_urlsafe(nbytes: int = 32) -> str:
    raw = os.urandom(nbytes)
    b64 = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return b64

def _random_digit_key(length: int = 24) -> str:
    # High-entropy digits-only key (length>=24 ~80 bits)
    return ''.join(secrets.choice('0123456789') for _ in range(max(1, length)))

# -----------------------------
# Simple .env loader (no external dependency) executed *before* using env vars in prod runner
# -----------------------------
def load_dotenv(path: str = '.env') -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, 'r') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)  # do not override existing explicit env
    except Exception as e:  # pragma: no cover
        _append_log(f"dotenv_load_error {e}")

# Attempt to load .env from project root (idempotent)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

def _current_security_mode():
    mode = os.environ.get("SECURITY_MODE", "open").lower()
    if mode not in ("open", "enforced"):
        mode = "open"
    return mode

# Optional HTTPS enforcement & HSTS
def _truthy(s: str) -> bool:
    return str(s).lower() in ("1", "true", "yes", "on")

FORCE_HTTPS = _truthy(os.environ.get('FORCE_HTTPS', '0'))
HSTS_MAX_AGE = int(os.environ.get('HSTS_MAX_AGE', '31536000'))  # 1 year
HSTS_PRELOAD = _truthy(os.environ.get('HSTS_PRELOAD', '0'))

# Security mode snapshot used only for initial startup log; all runtime checks call _current_security_mode()
SECURITY_MODE = _current_security_mode()

# Log initialization (and security mode)
_append_log(f"SemptifyGUI initialized with folders: {', '.join(folders)} | security_mode={SECURITY_MODE}")
try:
    # Log a quick inventory of key template & static assets to aid remote diagnostics
    index_tpl = os.path.join(app.template_folder, 'index.html')
    admin_tpl = os.path.join(app.template_folder, 'admin.html')
    manifest_path = os.path.join(app.static_folder, 'manifest.webmanifest')
    _append_log(
        "asset_check "
        f"index_exists={os.path.exists(index_tpl)} "
        f"admin_exists={os.path.exists(admin_tpl)} "
        f"manifest_exists={os.path.exists(manifest_path)}"
    )
except Exception as e:  # pragma: no cover (best effort)
    _append_log(f"asset_check_error {e}")

# -----------------------------
# Security headers middleware
# -----------------------------
@app.after_request
def _set_security_headers(resp):  # pragma: no cover (headers logic simple)
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('X-XSS-Protection', '0')  # modern browsers ignore / CSP recommended
    # Mild default CSP allowing same-origin scripts/styles/images & data: images
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    resp.headers.setdefault('Content-Security-Policy', csp)
    # HSTS only when secure or when forced (useful with local self-signed certs)
    try:
        is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto', '').lower() == 'https'
    except Exception:
        is_secure = False
    if is_secure or FORCE_HTTPS:
        hsts_val = f"max-age={HSTS_MAX_AGE}; includeSubDomains"
        if HSTS_PRELOAD:
            hsts_val += "; preload"
        resp.headers.setdefault('Strict-Transport-Security', hsts_val)
    # Propagate request id
    rid = getattr(request, 'request_id', None)
    if rid:
        resp.headers.setdefault('X-Request-Id', rid)
    # Optional structured access log (enabled by ACCESS_LOG_JSON=1)
    if os.environ.get('ACCESS_LOG_JSON') == '1':
        try:
            started = getattr(request, '_start_time', None)
            dur_ms = None
            if started is not None:
                dur_ms = int((time.time() - started) * 1000)
            _event_log('access',
                       method=request.method,
                       path=request.full_path.rstrip('?'),
                       status=resp.status_code,
                       ip=request.remote_addr,
                       dur_ms=dur_ms,
                       request_id=rid)
        except Exception as e:  # pragma: no cover
            _append_log(f'access_log_error {e}')
    return resp

@app.before_request
def _access_start():  # pragma: no cover (timing capture)
    # Store start timestamp for latency computation if access logging is enabled
    if os.environ.get('ACCESS_LOG_JSON') == '1':
        request._start_time = time.time()  # pylint: disable=protected-access
    # Generate a request id (idempotent if reverse proxy already set one via header)
    incoming = request.headers.get('X-Request-Id')
    request.request_id = incoming or uuid.uuid4().hex  # type: ignore[attr-defined]

@app.before_request
def _enforce_https_redirect():
    """If FORCE_HTTPS is enabled and request is not HTTPS, redirect to HTTPS.
    Honors X-Forwarded-Proto for reverse proxies. Health/metrics still redirect for consistency.
    """
    if not FORCE_HTTPS:
        return None
    # If behind a proxy sending X-Forwarded-Proto, respect it
    xf_proto = request.headers.get('X-Forwarded-Proto', '').lower()
    is_secure = request.is_secure or xf_proto == 'https'
    if is_secure:
        return None
    # If we cannot determine original scheme (missing X-Forwarded-Proto), avoid redirect loops
    if not xf_proto:
        return None
    # Only redirect if Host header exists and scheme is http
    host = request.host
    if not host:
        return None
    # Preserve full path and query string; swap scheme
    new_url = request.url.replace('http://', 'https://', 1)
    return redirect(new_url, code=301)

@app.route("/")
def index():
    # Use a Jinja2 template so UI can be extended without changing the route.
    message = "SemptifyGUI is live. Buttons coming next."
    _inc('requests_total')
    return render_template("index.html", message=message, folders=folders)


@app.route("/health")
def health():
    _inc('requests_total')
    return "OK", 200

@app.route("/healthz")
def healthz():
    _inc('requests_total')
    return jsonify({
        "status": "ok",
        "time": _utc_now_iso(),
        "folders": folders,
    }), 200

@app.route('/readyz')
def readyz():
    """Readiness probe verifying writable runtime dirs & token file load."""
    _inc('requests_total')
    snapshot, status_ok = _readiness_snapshot()
    return jsonify(snapshot), 200 if status_ok else 503

def _readiness_snapshot():
    """Return (snapshot_dict, healthy_bool)."""
    writable = {}
    for d in folders:
        test_file = os.path.join(d, '.readyz.tmp')
        try:
            with open(test_file, 'w') as f:
                f.write('ok')
            os.remove(test_file)
            writable[d] = True
        except Exception:
            writable[d] = False
    tokens_ok = True
    try:
        _load_tokens(force=True)
    except Exception:
        tokens_ok = False
    # Users file optional: do not fail readiness if missing, but record status
    users_ok = True
    try:
        _load_users(force=True)
    except Exception:
        users_ok = False
    status_ok = all(writable.values()) and tokens_ok
    snapshot = {
        'status': 'ready' if status_ok else 'degraded',
        'writable': writable,
        'tokens_load': tokens_ok,
        'users_load': users_ok,
        'time': _utc_now_iso()
    }
    return snapshot, status_ok

def _rate_or_unauth_response():
    """Return a standardized JSON response for rate limited or unauthorized admin access."""
    if getattr(request, '_rate_limited', False):
        return (jsonify({'error': 'rate_limited', 'retry_after': RATE_LIMIT_RETRY_AFTER}),
                RATE_LIMIT_STATUS,
                {'Retry-After': str(RATE_LIMIT_RETRY_AFTER)})
    return jsonify({'error': 'unauthorized'}), 401

@app.errorhandler(500)
def internal_error(e):  # pragma: no cover (framework error path)
    # Provide a lightweight JSON response for API clients while logging root cause
    _append_log(f"ERROR_500 path={request.path} error={e}")
    _event_log('error_500', path=request.path, msg=str(e))
    # If it's a template resolution problem, hint at likely cause
    hint = ''
    if 'TemplateNotFound' in str(e):
        hint = ' (template not found – ensure templates/ directory is deployed)'
    return ("An internal server error occurred" + hint, 500)

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

@app.route('/info')
def info():
    """Aggregated lightweight info: version + readiness + security mode."""
    _inc('requests_total')
    snapshot, _status = _readiness_snapshot()
    git_sha = os.environ.get("GIT_SHA", "unknown")
    build_time = os.environ.get("BUILD_TIME", "unknown")
    return jsonify({
        'app': 'SemptifyGUI',
        'git_sha': git_sha,
        'build_time': build_time,
        'security_mode': _current_security_mode(),
        'readiness': snapshot
    })


TOKENS_CACHE = { 'loaded_at': 0, 'tokens': [], 'path': os.path.join('security','admin_tokens.json'), 'mtime': None }

def _hash_token(raw: str) -> str:
    return 'sha256:' + hashlib.sha256(raw.encode('utf-8')).hexdigest()

# Perform legacy token bootstrap only after required helpers are defined
_bootstrap_tokens_if_needed()

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
    if _current_security_mode() == "open":
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

# -----------------------------
# GitHub API helper with retry/backoff (minimal)
# -----------------------------
def _github_request(method: str, url: str, headers: dict, json_payload: Optional[dict] = None, attempts: int = 3, backoff: float = 0.6):
    for i in range(1, attempts + 1):
        try:
            if method == 'GET':
                r = requests.get(url, headers=headers, timeout=10)
            else:
                r = requests.post(url, headers=headers, json=json_payload, timeout=15)
            if r.status_code >= 500 and i < attempts:
                time.sleep(backoff * i)
                continue
            return r
        except requests.RequestException as e:  # pragma: no cover (network failure path)
            if i == attempts:
                raise
            time.sleep(backoff * i)
    # Should not reach here
    raise RuntimeError('github_request_exhausted')

def _simulate_release_for_test(owner: str, repo: str) -> str:
    tag_name = f"vTEST-{_utc_now().strftime('%Y%m%d%H%M%S')}"
    log_path = os.path.join('logs', 'release-log.json')
    entry = { 'tag': tag_name, 'sha': 'testing-sha', 'timestamp': _utc_now_iso(), 'simulated': True }
    try:
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                data = json.load(f)
        else:
            data = []
        data.insert(0, entry)
        with open(log_path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:  # pragma: no cover
        _append_log(f'sim_release_write_fail {e}')
    _append_log(f'Simulated release tag {tag_name} (TESTING mode)')
    _event_log('release_simulated', tag=tag_name)
    return tag_name

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
        # Store marker so caller can translate to proper HTTP status
        request._rate_limited = True  # pylint: disable=protected-access
        return False
    if _current_security_mode() == "open":
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
    if _current_security_mode() != 'enforced':
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
        return _rate_or_unauth_response()

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
                           security_mode=_current_security_mode(),
                           token_ids=token_ids,
                           admin_token=_get_admin_token_legacy(),
                           csrf_token=csrf_token)

@app.route('/admin/status')
def admin_status():
    if not _require_admin_or_401():
        return _rate_or_unauth_response()
    _inc('admin_requests_total')
    _load_tokens()
    token_summaries = [{'id': t['id'], 'breakglass': t.get('breakglass', False)} for t in TOKENS_CACHE['tokens']]
    return jsonify({
        'security_mode': _current_security_mode(),
        'metrics': METRICS,
        'tokens': token_summaries,
        'time': _utc_now_iso()
    })


@app.route('/release_now', methods=['POST'])
def release_now():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    if not _require_admin_or_401():
        return _rate_or_unauth_response()

    # Soft confirmation: require hidden field confirm_release=yes
    if request.form.get('confirm_release') != 'yes':
        return abort(400, description="Missing confirmation field")

    github_token = os.environ.get('GITHUB_TOKEN')
    owner = os.environ.get('GITHUB_OWNER', 'Bradleycrowe')
    repo = os.environ.get('GITHUB_REPO', 'SemptifyGUI')
    if not github_token:
        # In test mode simulate a successful release so tests can pass without secret
        if app.config.get('TESTING'):
            tag_name = _simulate_release_for_test(owner, repo)
            _inc('releases_total')
            _inc('admin_actions_total')
            return redirect(f'https://github.com/{owner}/{repo}/releases/tag/{tag_name}')
        _append_log('release_now failed: missing GITHUB_TOKEN')
        return "GITHUB_TOKEN not configured on server", 500

    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    # Get latest commit SHA from default branch (main)
    ref_url = f'https://api.github.com/repos/{owner}/{repo}/git/refs/heads/main'
    r = _github_request('GET', ref_url, headers=headers)
    if r.status_code != 200:
        _append_log(f'release_now failed: cannot read ref: {r.status_code}')
        return f'Failed to read ref: {r.status_code}', 500
    sha = r.json().get('object', {}).get('sha')

    # Create a timestamped tag
    tag_name = f'v{_utc_now().strftime("%Y%m%d%H%M%S")}'
    create_ref_url = f'https://api.github.com/repos/{owner}/{repo}/git/refs'
    payload = { 'ref': f'refs/tags/{tag_name}', 'sha': sha }
    r = _github_request('POST', create_ref_url, headers=headers, json_payload=payload)
    if r.status_code in (201, 200):
        _append_log(f'Created tag {tag_name} via API')
        _event_log('release_created', tag=tag_name, sha=sha, ip=request.remote_addr)
        _inc('releases_total')
        _inc('admin_actions_total')
        # record release in release-log.json
        log_path = os.path.join('logs', 'release-log.json')
        entry = { 'tag': tag_name, 'sha': sha, 'timestamp': _utc_now_iso() }
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
        return _rate_or_unauth_response()

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
        return _rate_or_unauth_response()
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
        return _rate_or_unauth_response()
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
        return _rate_or_unauth_response()
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
# Resources: witness statements and filing packet checklist
# -----------------------------

@app.route('/resources')
def resources():
    _inc('requests_total')
    return render_template('resources.html')

@app.route('/resources/download/<name>.txt')
def resources_download(name: str):
    _inc('requests_total')
    # Whitelist known templates
    allowed = {
        'witness_statement': os.path.join(BASE_DIR, 'docs', 'templates', 'witness_statement_template.txt'),
        'filing_packet_checklist': os.path.join(BASE_DIR, 'docs', 'templates', 'filing_packet_checklist.txt'),
        'filing_packet_timeline': os.path.join(BASE_DIR, 'docs', 'templates', 'filing_packet_timeline.txt')
    }
    path = allowed.get(name)
    if not path or not os.path.exists(path):
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=f"{name}.txt")

# -----------------------------
# Fillable forms: Witness Statement and Filing Packet Builder
# -----------------------------

def _render_csrf():
    return _get_or_create_csrf_token()
@app.route('/register', methods=['GET'])
def register_page():
    _inc('requests_total')
    return render_template('register.html', csrf_token=_get_or_create_csrf_token())

@app.route('/register', methods=['POST'])
def register_submit():
    # Simple rate limit per IP
    rl_key = f"register:{request.remote_addr}"
    if not _rate_limit(rl_key):
        _inc('rate_limited_total')
        return jsonify({'error': 'rate_limited'}), RATE_LIMIT_STATUS, {'Retry-After': str(RATE_LIMIT_RETRY_AFTER)}
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    name = (request.form.get('name') or '').strip()
    _load_users()
    # Create user
    uid = _new_user_id()
    # Anonymous, digit-key accounts by default
    token = _random_digit_key(24)
    hashed = _hash_token(token)
    full = USERS_CACHE.get('users', [])
    # Store full list including disabled or others if file exists
    existing = []
    try:
        if os.path.exists(USERS_CACHE['path']):
            with open(USERS_CACHE['path'],'r', encoding='utf-8') as f:
                existing = json.load(f)
    except Exception:
        existing = []
    payload = { 'id': uid, 'hash': hashed, 'enabled': True }
    if name:
        payload['name'] = name
    existing.append(payload)
    _write_users(existing)
    _event_log('user_registered', user_id=uid, ip=request.remote_addr)
    # Show token once
    return render_template('register_success.html', user_id=uid, token=token)

# -----------------------------
# AI Copilot MVP
# -----------------------------

def _ai_provider() -> str:
    return (os.environ.get('AI_PROVIDER') or 'none').strip().lower()

def _copilot_call_openai(prompt: str) -> str:
    api_key = os.environ.get('OPENAI_API_KEY')
    model = os.environ.get('OPENAI_MODEL') or 'gpt-4o-mini'
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY not configured')
    url = os.environ.get('OPENAI_BASE_URL') or 'https://api.openai.com/v1/chat/completions'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are Semptify Copilot, a helpful assistant for tenant-justice automation.'},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.2
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f'OpenAI error {r.status_code}: {r.text[:200]}')
    data = r.json()
    return data['choices'][0]['message']['content']

def _copilot_call_azure(prompt: str) -> str:
    endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    api_key = os.environ.get('AZURE_OPENAI_API_KEY')
    deployment = os.environ.get('AZURE_OPENAI_DEPLOYMENT')
    api_version = os.environ.get('AZURE_OPENAI_API_VERSION') or '2024-02-15-preview'
    if not endpoint or not api_key or not deployment:
        raise RuntimeError('Azure OpenAI env not configured')
    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    headers = {'api-key': api_key, 'Content-Type': 'application/json'}
    payload = {
        'messages': [
            {'role': 'system', 'content': 'You are Semptify Copilot, a helpful assistant for tenant-justice automation.'},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.2
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f'Azure OpenAI error {r.status_code}: {r.text[:200]}')
    data = r.json()
    return data['choices'][0]['message']['content']

def _copilot_call_ollama(prompt: str) -> str:
    host = os.environ.get('OLLAMA_HOST') or 'http://localhost:11434'
    model = os.environ.get('OLLAMA_MODEL') or 'llama3.1'
    url = f"{host.rstrip('/')}/api/generate"
    payload = {'model': model, 'prompt': prompt, 'stream': False, 'options': {'temperature': 0.2}}
    r = requests.post(url, json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f'Ollama error {r.status_code}: {r.text[:200]}')
    data = r.json()
    return data.get('response') or ''

def _copilot_generate(prompt: str) -> tuple[str, int]:
    provider = _ai_provider()
    if provider in ('', 'none'):
        return ('AI Copilot is not configured. Set AI_PROVIDER and provider-specific environment variables.', 501)
    try:
        if provider == 'openai':
            out = _copilot_call_openai(prompt)
        elif provider in ('azure', 'azure-openai'):
            out = _copilot_call_azure(prompt)
        elif provider == 'ollama':
            out = _copilot_call_ollama(prompt)
        else:
            return (f'Unknown AI_PROVIDER: {provider}', 400)
        return (out, 200)
    except Exception as e:
        _append_log(f"copilot_error {e}")
        return (f'Error from provider: {e}', 502)

@app.route('/copilot', methods=['GET'])
def copilot_page():
    _inc('requests_total')
    csrf = _render_csrf()
    provider = _ai_provider()
    return render_template('copilot.html', csrf_token=csrf, provider=provider)

@app.route('/api/copilot', methods=['POST'])
def copilot_api():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'
    if not _rate_limit(f"copilot:{ip}"):
        _inc('rate_limited_total')
        return jsonify({'error': 'rate_limited'}), RATE_LIMIT_STATUS, {'Retry-After': str(RATE_LIMIT_RETRY_AFTER)}
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    data = request.get_json(silent=True) or {}
    prompt = (data.get('prompt') or '').strip()
    if not prompt:
        return jsonify({'error': 'missing_prompt'}), 400
    
    # Check if this is an evidence-enhanced request
    location = (data.get('location') or '').strip()
    timestamp = (data.get('timestamp') or '').strip()
    form_type = (data.get('form_type') or '').strip()
    form_data = data.get('form_data', {})
    
    # Enhance prompt with evidence context if provided
    if location or timestamp or form_type:
        enhanced_prompt = _build_evidence_prompt(prompt, location, timestamp, form_type, form_data)
        _event_log('evidence_copilot_request', ip=ip, location=location[:50] if location else None, form_type=form_type)
    else:
        enhanced_prompt = prompt
    
    text, code = _copilot_generate(enhanced_prompt)
    return jsonify({'provider': _ai_provider(), 'output': text}), code

def _build_evidence_prompt(base_prompt: str, location: str, timestamp: str, form_type: str, form_data: dict) -> str:
    """Build enhanced prompt with evidence collection context"""
    enhanced = "You are an AI assistant specializing in tenant rights and evidence collection. "
    
    if timestamp:
        enhanced += f"Current time: {timestamp}. "
    
    if location and location != 'Location unavailable':
        enhanced += f"User location: {location}. "
    
    if form_type and form_type != 'general_form':
        enhanced += f"User is working on: {form_type.replace('_', ' ')}. "
    
    if form_data and isinstance(form_data, dict) and form_data:
        # Add relevant form data context
        relevant_fields = []
        for key, value in form_data.items():
            if value and len(str(value).strip()) > 0 and key not in ['csrf_token', 'user_token']:
                relevant_fields.append(f"{key}: {str(value)[:100]}")
        if relevant_fields:
            enhanced += f"Form context: {'; '.join(relevant_fields[:3])}. "
    
    enhanced += "\n\nUser request: " + base_prompt
    enhanced += "\n\nPlease provide specific, actionable guidance for tenant rights documentation and evidence collection. Focus on:"
    enhanced += "\n1. What evidence to collect for this situation"
    enhanced += "\n2. Legal considerations and tenant rights"
    enhanced += "\n3. Best practices for documentation"
    enhanced += "\n4. Recommended next steps"
    
    return enhanced

@app.route('/resources/witness_statement', methods=['GET'])
def witness_form():
    _inc('requests_total')
    return render_template('witness_form.html', csrf_token=_render_csrf())

@app.route('/resources/witness_statement_preview', methods=['POST'])
def witness_preview():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    _inc('requests_total')
    data = {
        'full_name': (request.form.get('full_name') or '').strip(),
        'contact': (request.form.get('contact') or '').strip(),
        'statement': (request.form.get('statement') or '').strip(),
        'date': (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip(),
        'sig_name': (request.form.get('sig_name') or '').strip(),
        'sig_consented': 'yes' if (request.form.get('sig_consented') in ('on','yes','true','1')) else 'no'
    }
    user_token = request.form.get('user_token') or ''
    return render_template('witness_preview.html', data=data, user_token=user_token, csrf_token=_render_csrf())

@app.route('/resources/witness_statement_save', methods=['POST'])
def witness_save():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    # Compose text content
    full_name = (request.form.get('full_name') or '').strip()
    contact = (request.form.get('contact') or '').strip()
    statement = (request.form.get('statement') or '').strip()
    date = (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip()
    sig_name = (request.form.get('sig_name') or '').strip()
    sig_consented = request.form.get('sig_consented') in ('on','yes','true','1')
    if not sig_name or not sig_consented:
        return "Electronic signature consent and typed name are required to save", 400
    content = (
        "Witness Statement\n"
        "==================\n\n"
        f"Full name: {full_name}\n"
        f"Contact: {contact}\n\n"
        f"Statement (dated {date}):\n{statement}\n\n"
        "Unsworn Declaration (28 U.S.C. § 1746):\n"
        "I declare under penalty of perjury that the foregoing is true and correct.\n"
        f"Executed on {date}.\n\n"
        f"Signature (typed): {sig_name}\n"
        f"Printed Name: {full_name}\n"
    )
    # Save to user's vault
    ts = _utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"witness_{ts}.txt"
    dest = os.path.join(_vault_user_dir(user['id']), filename)
    try:
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content)
        # Extract evidence collection data
        evidence_timestamp = (request.form.get('evidence_timestamp') or '').strip()
        evidence_location = (request.form.get('evidence_location') or '').strip()
        location_accuracy = (request.form.get('location_accuracy') or '').strip()
        evidence_user_agent = (request.form.get('evidence_user_agent') or '').strip()
        
        # Write certificate JSON with hash and context
        cert = {
            'type': 'witness_statement',
            'file': filename,
            'sha256': _sha256_hex(content),
            'user_id': user['id'],
            'executed_date': date,
            'sig_name': sig_name,
            'sig_consented': True,
            'ts': _utc_now_iso(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(request, 'request_id', None),
            'evidence_collection': {
                'timestamp': evidence_timestamp or _utc_now_iso(),
                'location': evidence_location or 'Not provided',
                'location_accuracy': location_accuracy or 'Unknown',
                'collection_user_agent': evidence_user_agent or request.headers.get('User-Agent'),
                'has_location_data': bool(evidence_location),
                'collection_method': 'semptify_evidence_system'
            }
        }
        cert_path = os.path.join(_vault_user_dir(user['id']), f"witness_{ts}.json")
        with open(cert_path, 'w', encoding='utf-8') as cf:
            json.dump(cert, cf, indent=2)
        _event_log('witness_saved', user_id=user['id'], filename=filename, size=os.path.getsize(dest), sha256=cert['sha256'])
    except Exception as e:  # pragma: no cover
        _append_log(f"witness_save_error {e}")
        return "Failed to save file", 500
    token = request.form.get('user_token') or ''
    return redirect(f"/vault?user_token={token}")

@app.route('/resources/filing_packet', methods=['GET'])
def packet_form():
    _inc('requests_total')
    return render_template('packet_form.html', csrf_token=_render_csrf())

@app.route('/resources/filing_packet_preview', methods=['POST'])
def packet_preview():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    _inc('requests_total')
    data = {
        'title': (request.form.get('title') or '').strip(),
        'summary': (request.form.get('summary') or '').strip(),
        'issues': (request.form.get('issues') or '').strip(),
        'parties': (request.form.get('parties') or '').strip(),
        'date': (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip(),
        'sig_name': (request.form.get('sig_name') or '').strip(),
        'sig_consented': 'yes' if (request.form.get('sig_consented') in ('on','yes','true','1')) else 'no'
    }
    user_token = request.form.get('user_token') or ''
    return render_template('packet_preview.html', data=data, user_token=user_token, csrf_token=_render_csrf())

@app.route('/resources/filing_packet_save', methods=['POST'])
def packet_save():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    title = (request.form.get('title') or '').strip()
    summary = (request.form.get('summary') or '').strip()
    issues = (request.form.get('issues') or '').strip()
    parties = (request.form.get('parties') or '').strip()
    date = (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip()
    sig_name = (request.form.get('sig_name') or '').strip()
    sig_consented = request.form.get('sig_consented') in ('on','yes','true','1')
    if not sig_name or not sig_consented:
        return "Electronic signature consent and typed name are required to save", 400
    content = (
        "Filing Packet Summary\n"
        "=====================\n\n"
        f"Title: {title}\n"
        f"Date: {date}\n"
        f"Parties: {parties}\n\n"
        "Summary:\n"
        f"{summary}\n\n"
        "Key Issues:\n"
        f"{issues}\n\n"
        "Checklist:\n"
        "- Cover Page\n- Summary Sheet\n- Evidence Index\n- Exhibits\n- Timeline\n- Witness Statements\n- Final Page (signature/date)\n\n"
        "Attestation:\n"
        "I declare under penalty of perjury that this summary accurately reflects the attached materials to the best of my knowledge.\n\n"
        f"Signature (typed): {sig_name}\n"
    )
    ts = _utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"packet_{ts}.txt"
    dest = os.path.join(_vault_user_dir(user['id']), filename)
    try:
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content)
        cert = {
            'type': 'filing_packet_summary',
            'file': filename,
            'sha256': _sha256_hex(content),
            'user_id': user['id'],
            'executed_date': date,
            'sig_name': sig_name,
            'sig_consented': True,
            'ts': _utc_now_iso(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(request, 'request_id', None)
        }
        cert_path = os.path.join(_vault_user_dir(user['id']), f"packet_{ts}.json")
        with open(cert_path, 'w', encoding='utf-8') as cf:
            json.dump(cert, cf, indent=2)
        _event_log('packet_saved', user_id=user['id'], filename=filename, size=os.path.getsize(dest), sha256=cert['sha256'])
    except Exception as e:  # pragma: no cover
        _append_log(f"packet_save_error {e}")
        return "Failed to save file", 500
    token = request.form.get('user_token') or ''
    return redirect(f"/vault?user_token={token}")

# -----------------------------
# Service Animal (Reasonable Accommodation) Request Letter
# -----------------------------

@app.route('/resources/service_animal', methods=['GET'])
def sa_form():
    _inc('requests_total')
    return render_template('service_animal_form.html', csrf_token=_render_csrf())

@app.route('/resources/service_animal_preview', methods=['POST'])
def sa_preview():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    _inc('requests_total')
    data = {
        'tenant_name': (request.form.get('tenant_name') or '').strip(),
        'landlord_name': (request.form.get('landlord_name') or '').strip(),
        'property_address': (request.form.get('property_address') or '').strip(),
        'date': (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip(),
        'animal_description': (request.form.get('animal_description') or '').strip(),
        'need_summary': (request.form.get('need_summary') or '').strip(),
        'sig_name': (request.form.get('sig_name') or '').strip(),
        'sig_consented': 'yes' if (request.form.get('sig_consented') in ('on','yes','true','1')) else 'no'
    }
    user_token = request.form.get('user_token') or ''
    return render_template('service_animal_preview.html', data=data, user_token=user_token, csrf_token=_render_csrf())

@app.route('/resources/service_animal_save', methods=['POST'])
def sa_save():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    tenant_name = (request.form.get('tenant_name') or '').strip()
    landlord_name = (request.form.get('landlord_name') or '').strip()
    property_address = (request.form.get('property_address') or '').strip()
    date = (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip()
    animal_description = (request.form.get('animal_description') or '').strip()
    need_summary = (request.form.get('need_summary') or '').strip()
    sig_name = (request.form.get('sig_name') or '').strip()
    sig_consented = request.form.get('sig_consented') in ('on','yes','true','1')
    if not sig_name or not sig_consented:
        return "Electronic signature consent and typed name are required to save", 400
    content = (
        "Reasonable Accommodation Request (Service/Support Animal)\n"
        "=========================================================\n\n"
        f"Date: {date}\n"
        f"To: {landlord_name}\n"
        f"Property: {property_address}\n\n"
        f"I, {tenant_name}, request a reasonable accommodation to keep my service or support animal described as: {animal_description}.\n"
        f"This accommodation is necessary because: {need_summary}.\n\n"
        "This request is made pursuant to applicable fair housing laws.\n\n"
        "Attestation:\n"
        "I declare under penalty of perjury that the above is true and correct to the best of my knowledge.\n\n"
        f"Signature (typed): {sig_name}\n"
        f"Printed Name: {tenant_name}\n"
    )
    ts = _utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"service_animal_{ts}.txt"
    dest = os.path.join(_vault_user_dir(user['id']), filename)
    try:
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content)
        cert = {
            'type': 'service_animal_request',
            'file': filename,
            'sha256': _sha256_hex(content),
            'user_id': user['id'],
            'executed_date': date,
            'sig_name': sig_name,
            'sig_consented': True,
            'ts': _utc_now_iso(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(request, 'request_id', None)
        }
        cert_path = os.path.join(_vault_user_dir(user['id']), f"service_animal_{ts}.json")
        with open(cert_path, 'w', encoding='utf-8') as cf:
            json.dump(cert, cf, indent=2)
        _event_log('service_animal_saved', user_id=user['id'], filename=filename, sha256=cert['sha256'])
    except Exception as e:  # pragma: no cover
        _append_log(f"sa_save_error {e}")
        return "Failed to save file", 500
    token = request.form.get('user_token') or ''
    return redirect(f"/vault?user_token={token}")

# -----------------------------
# Move-in / Move-out Checklist
# -----------------------------

@app.route('/resources/move_checklist', methods=['GET'])
def move_form():
    _inc('requests_total')
    return render_template('move_checklist_form.html', csrf_token=_render_csrf())

@app.route('/resources/move_checklist_preview', methods=['POST'])
def move_preview():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    _inc('requests_total')
    items = request.form.getlist('items')
    data = {
        'address': (request.form.get('address') or '').strip(),
        'date': (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip(),
        'notes': (request.form.get('notes') or '').strip(),
        'items': items,
        'sig_name': (request.form.get('sig_name') or '').strip(),
        'sig_consented': 'yes' if (request.form.get('sig_consented') in ('on','yes','true','1')) else 'no'
    }
    user_token = request.form.get('user_token') or ''
    return render_template('move_checklist_preview.html', data=data, user_token=user_token, csrf_token=_render_csrf())

@app.route('/resources/move_checklist_save', methods=['POST'])
def move_save():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    address = (request.form.get('address') or '').strip()
    date = (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip()
    notes = (request.form.get('notes') or '').strip()
    items = request.form.getlist('items')
    sig_name = (request.form.get('sig_name') or '').strip()
    sig_consented = request.form.get('sig_consented') in ('on','yes','true','1')
    if not sig_name or not sig_consented:
        return "Electronic signature consent and typed name are required to save", 400
    lines = [
        "Move-in/Move-out Checklist",
        "===========================",
        f"Address: {address}",
        f"Date: {date}",
        "",
        "Checked Items:" 
    ] + [f"- {it}" for it in items] + [
        "",
        "Notes:",
        notes,
        "",
        "Attestation:",
        "I declare under penalty of perjury that this checklist accurately reflects the observed condition.",
        "",
        f"Signature (typed): {sig_name}"
    ]
    content = "\n".join(lines) + "\n"
    ts = _utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"move_checklist_{ts}.txt"
    dest = os.path.join(_vault_user_dir(user['id']), filename)
    try:
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content)
        cert = {
            'type': 'move_checklist',
            'file': filename,
            'sha256': _sha256_hex(content),
            'user_id': user['id'],
            'executed_date': date,
            'sig_name': sig_name,
            'sig_consented': True,
            'ts': _utc_now_iso(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(request, 'request_id', None)
        }
        cert_path = os.path.join(_vault_user_dir(user['id']), f"move_checklist_{ts}.json")
        with open(cert_path, 'w', encoding='utf-8') as cf:
            json.dump(cert, cf, indent=2)
        _event_log('move_checklist_saved', user_id=user['id'], filename=filename, sha256=cert['sha256'])
    except Exception as e:  # pragma: no cover
        _append_log(f"move_save_error {e}")
        return "Failed to save file", 500
    token = request.form.get('user_token') or ''
    return redirect(f"/vault?user_token={token}")

# -----------------------------
# Rent Ledger (minimal)
# -----------------------------

def _ledger_user_dir(user_id: str) -> str:
    base = os.path.join('uploads', 'ledger', user_id)
    os.makedirs(base, exist_ok=True)
    return base

def _ledger_path(user_id: str) -> str:
    return os.path.join(_ledger_user_dir(user_id), 'ledger.json')

def _ledger_load(user_id: str) -> list:
    path = _ledger_path(user_id)
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:  # pragma: no cover
        return []

def _ledger_save(user_id: str, entries: list):
    path = _ledger_path(user_id)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)

@app.route('/resources/rent_ledger', methods=['GET'])
def ledger_view():
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    entries = _ledger_load(user['id'])
    # calculate totals
    total_rent = sum(e.get('amount', 0) for e in entries if e.get('type') == 'rent')
    total_fees = sum(e.get('amount', 0) for e in entries if e.get('type') == 'fee')
    total_payments = sum(e.get('amount', 0) for e in entries if e.get('type') == 'payment')
    balance = (total_rent + total_fees) - total_payments
    csrf_token = _get_or_create_csrf_token()
    return render_template('ledger.html', entries=entries, total_rent=total_rent, total_fees=total_fees, total_payments=total_payments, balance=balance, csrf_token=csrf_token, user=user)

@app.route('/resources/rent_ledger_add', methods=['POST'])
def ledger_add():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    try:
        date = (request.form.get('date') or _utc_now().strftime('%Y-%m-%d')).strip()
        typ = (request.form.get('type') or 'rent').strip()
        amount = float(request.form.get('amount'))
        note = (request.form.get('note') or '').strip()
    except Exception:
        return "Invalid input", 400
    entries = _ledger_load(user['id'])
    entries.append({'date': date, 'type': typ, 'amount': amount, 'note': note})
    # sort by date then by type
    try:
        entries.sort(key=lambda e: (e.get('date',''), e.get('type','')))
    except Exception:
        pass
    _ledger_save(user['id'], entries)
    _event_log('ledger_entry_added', user_id=user['id'], date=date, type=typ, amount=amount)
    token = request.form.get('user_token') or ''
    return redirect(f"/resources/rent_ledger?user_token={token}")

# -----------------------------
# Document Vault (per-user storage)
# -----------------------------

def _vault_user_dir(user_id: str) -> str:
    base = os.path.join('uploads', 'vault', user_id)
    os.makedirs(base, exist_ok=True)
    return base

@app.route('/vault', methods=['GET'])
def vault_home():
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    # List user's files
    user_dir = _vault_user_dir(user['id'])
    files = []
    try:
        for name in sorted(os.listdir(user_dir)):
            full = os.path.join(user_dir, name)
            if os.path.isfile(full):
                files.append({
                    'name': name,
                    'size': os.path.getsize(full)
                })
    except Exception as e:  # pragma: no cover
        _append_log(f"vault_list_error {e}")
    csrf_token = _get_or_create_csrf_token()
    return render_template('vault.html', user=user, files=files, csrf_token=csrf_token)

@app.route('/vault/upload', methods=['POST'])
def vault_upload():
    if not _validate_csrf(request):
        return "CSRF validation failed", 400
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    f = request.files.get('file')
    if not f or f.filename is None or f.filename.strip() == '':
        return "No file provided", 400
    filename = secure_filename(f.filename)
    if not filename:
        return "Invalid filename", 400
    user_dir = _vault_user_dir(user['id'])
    dest = os.path.join(user_dir, filename)
    try:
        f.save(dest)
        _event_log('vault_upload', user_id=user['id'], filename=filename, size=os.path.getsize(dest))
    except Exception as e:  # pragma: no cover
        _append_log(f"vault_upload_error {e}")
        return "Failed to save file", 500
    return redirect(f"/vault?user_token=" + (request.form.get('user_token') or ''))

@app.route('/vault/download/<path:filename>', methods=['GET'])
def vault_download(filename):
    user = _require_user_or_401()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    safe = secure_filename(filename)
    if not safe or safe != filename:
        return "Invalid filename", 400
    path = os.path.join(_vault_user_dir(user['id']), safe)
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(path, as_attachment=True)

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
        return _rate_or_unauth_response()
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

# -----------------------------
# Virtual Office: Meeting Rooms and Assistance
# -----------------------------

@app.route('/office', methods=['GET'])
def virtual_office():
    """Virtual office landing page - meeting rooms and AI assistant access."""
    _inc('requests_total')
    return render_template('office.html')

@app.route('/office/meeting', methods=['GET'])
def virtual_meeting():
    """Virtual meeting room with integrated AI assistance."""
    _inc('requests_total')
    csrf = _render_csrf()
    provider = _ai_provider()
    return render_template('meeting.html', csrf_token=csrf, provider=provider)

if __name__ == "__main__":
    app.run(debug=True)
