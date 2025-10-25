# filepath: d:\Semptify\Semptify\security.py
import os, json, time, uuid, hashlib
from flask import session, request, abort, make_response

ADMIN_FILE = os.path.join("security","admin_tokens.json")
USERS_FILE = os.path.join("security","users.json")

def _load_json(p):
    try:
        if os.path.exists(p):
            return json.load(open(p,"r",encoding="utf-8"))
    except:
        pass
    return {}

# metrics
_metrics = {"requests_total":0,"admin_requests_total":0,"releases_total":0,"rate_limited_total":0}
def incr_metric(name, amount=1):
    _metrics[name] = _metrics.get(name,0) + int(amount)
def get_metrics():
    return _metrics

# CSRF
def _get_or_create_csrf_token():
    if "csrf" not in session:
        session["csrf"] = uuid.uuid4().hex
    return session["csrf"]

# admin auth simple
def _require_admin_or_401():
    t = request.headers.get("X-Admin-Token") or request.args.get("admin_token")
    if not t and os.getenv("SECURITY_MODE","open") == "open":
        return True
    if not t:
        abort(401)
    entries = _load_json(ADMIN_FILE).get("tokens", [])
    for e in entries:
        if hashlib.sha256(t.encode()).hexdigest() == e.get("hash"):
            incr_metric("admin_requests_total")
            return True
    legacy = os.getenv("ADMIN_TOKEN")
    if legacy and t == legacy:
        incr_metric("admin_requests_total")
        return True
    abort(401)

# basic user token save
def save_user_token(plain=None):
    if not plain:
        plain = str(int(time.time()))[-6:]
    h = hashlib.sha256(plain.encode()).hexdigest()
    data = _load_json(USERS_FILE)
    if not isinstance(data, list):
        data = []
    user_id = f"u{time.strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6]}"
    entry = {
        "id": user_id,
        "hash": f"sha256:{h}",
        "enabled": True,
        "name": "Test User"
    }
    data.append(entry)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return plain

