# SemptifyGUI

![CI](https://github.com/Bradleycrowe/SemptifyGUI/actions/workflows/ci.yml/badge.svg)
![Pages](https://github.com/Bradleycrowe/SemptifyGUI/actions/workflows/pages.yml/badge.svg)

Small Flask-based GUI for tenant-justice automation. This repository includes a development server, a production runner (`run_prod.py` using waitress), Docker support, tests, and CI workflows.

Getting started (development)

```powershell
Set-Location -LiteralPath 'd:\Semptify\SemptifyGUI'
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\SemptifyGUI.py
```

Running in production (waitress)

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\run_prod.py
```

Docker

```powershell
docker build -t semptifygui:latest .
docker run --rm -p 8080:8080 semptifygui:latest
```

Tests

```powershell
.\.venv\Scripts\Activate.ps1
pip install pytest
python -m pytest -q
```

CI and Releases

- GitHub Actions runs tests and builds images on push/PR.
- On tag pushes the workflow scans the image with Trivy, generates an SBOM with Syft, publishes images to GHCR (and optionally Docker Hub), and creates a GitHub Release with artifacts (image-info, SBOM, Trivy SARIF).

If you need me to add deploy manifests (Kubernetes/Helm) or automated tagging, tell me and I will add them.

## Security Modes

`SECURITY_MODE` controls admin protection:

- `open` (default): Admin routes do not require the `ADMIN_TOKEN`, but each access is logged with an `OPEN_MODE` entry.
- `enforced`: Admin routes require the `ADMIN_TOKEN` (passed as `?token=...` or `X-Admin-Token` header).

Change mode by setting the environment variable before starting the app or updating the Render service env vars.

### Multi-Token & Break-Glass (Advanced)

Create `security/admin_tokens.json` (not committed) with entries:

```jsonc
[
  { "id": "primary", "hash": "sha256:<hash-of-token>", "enabled": true },
  { "id": "ops-breakglass", "hash": "sha256:<hash-of-token>", "enabled": true, "breakglass": true }
]
```

Generate a hash (PowerShell example):

```powershell
$raw = 'SuperSecretTokenValue'
$hash = (python - <<'PY'
import hashlib,os
print('sha256:' + hashlib.sha256(os.environ['RAW'].encode()).hexdigest())
PY
)
```

Or via Python directly in a REPL:

```python
import hashlib
print('sha256:' + hashlib.sha256(b'SuperSecretTokenValue').hexdigest())
```

Break-glass activation: create an empty file `security/breakglass.flag` on the server. The next request using a token marked `"breakglass": true` will authenticate and remove the flag (one-shot). All events append structured JSON lines in `logs/events.log`.

### CSRF Protection (Enforced Mode)

When `SECURITY_MODE=enforced`, all state-changing admin POST routes (`/release_now`, `/trigger_workflow`, `/rotate_token`) require a valid session CSRF token:

1. Browser (or test client) first performs a GET to `/admin` with a valid admin token to establish a session.
2. A hidden field `csrf_token` is included in the admin forms.
3. POST requests missing or with an invalid CSRF token return `400 CSRF validation failed`.

In `open` mode CSRF validation is skipped to keep friction low during early adoption / public demo.

### Rate Limiting

Admin routes apply a sliding-window rate limit (default 60 requests / 60 seconds / (IP, path) tuple). Configure via env vars:

```
ADMIN_RATE_WINDOW=60   # window seconds
ADMIN_RATE_MAX=60      # max requests per window
```

When exceeded the attempt is logged (`rate_limited`) and increments `rate_limited_total`.

### Extended Metrics

The `/metrics` endpoint (Prometheus plaintext) now exposes:

- `requests_total`
- `admin_requests_total`
- `admin_actions_total` (mutating operations)
- `errors_total`
- `releases_total`
- `rate_limited_total`
- `breakglass_used_total`
- `token_rotations_total`

### Admin Status Endpoint

`/admin/status` (GET) returns a JSON snapshot (requires auth in enforced mode):

```jsonc
{
  "security_mode": "enforced",
  "metrics": { "requests_total": 42, ... },
  "tokens": [ { "id": "primary", "breakglass": false } ],
  "time": "2025-10-08T12:34:56.789Z"
}
```

### Token Rotation

Rotate an existing entry in `security/admin_tokens.json` via the admin UI Rotate Token form. This updates the token hash atomically and increments `token_rotations_total`. (In enforced mode, CSRF + admin token are both required.)

## Render Deployment

The `render.yaml` describes the service. Key env vars:

- `SEMPTIFY_PORT`: internal port (default 8080)
- `ADMIN_TOKEN`: only required once you switch to enforced mode
- `SECURITY_MODE`: `open` or `enforced`

After a push to `main`, Render auto deploys (if configured). Health check: `/health`.

### Post-Deploy Smoke Test

Use the provided PowerShell script:

```powershell
.\n+RenderSmokeTest.ps1 -BaseUrl https://semptifygui.onrender.com
```

If in enforced mode:

```powershell
RenderSmokeTest.ps1 -BaseUrl https://semptifygui.onrender.com -AdminToken YOUR_ADMIN_TOKEN
```

Outputs will confirm health, version metadata, and admin banner (OPEN or ENFORCED).

### Sample Admin Automation (CI / Status Polling)

Poll `/admin/status` for real-time dashboards:

```powershell
Invoke-RestMethod "https://<your-app>/admin/status?token=$env:ADMIN_TOKEN" | ConvertTo-Json -Depth 4
```

### Offline / PWA Support

The app ships a service worker + manifest. The `/offline` route serves a fallback message when the network is unavailable. Future iterations may add richer offline caching.

---

## Roadmap (Open Doors → Fully Functional)

- [x] Multi-token & break-glass auth
- [x] CSRF protection (enforced mode)
- [x] Rate limiting + metrics
- [x] Structured event logging
- [x] PWA manifest + service worker offline fallback
- [x] Real PWA icons (192, 256, 384, 512, maskable)
- [x] Enhanced landing page with feature sections and anchor navigation
- [x] SBOM diff workflow for supply-chain change tracking
- [x] Prometheus HELP/TYPE metrics annotations
- [x] Comprehensive test coverage (breakglass, rate limiting, CSRF, token rotation)
- [ ] Rich offline admin panel subset (read-only)
- [ ] Semantic version tagging automation
- [ ] Additional security hardening (SameSite cookies, CSP headers)

---

## "Open Doors" Deployment Checklist

Use this checklist to ensure Semptify is production-ready and fully functional for public access.

### Pre-Deployment Setup

- [ ] **Security Mode Configuration**
  - Set `SECURITY_MODE=enforced` in production environment
  - Create `security/admin_tokens.json` with hashed tokens
  - Set `FLASK_SECRET` environment variable for stable CSRF sessions
  - Configure `ADMIN_RATE_WINDOW` and `ADMIN_RATE_MAX` for expected traffic

- [ ] **GitHub Integration**
  - Set `GITHUB_TOKEN` secret for release/workflow automation
  - Configure repository access for CI/CD workflows
  - Verify webhook triggers for auto-deployment

- [ ] **Infrastructure**
  - Confirm health check endpoint: `/health`
  - Set up monitoring for `/metrics` (Prometheus/Grafana)
  - Configure log aggregation for `logs/events.log`
  - Ensure persistent storage for `security/` folder

### Deployment Verification

Run these checks after deployment to verify full functionality:

#### 1. Core Health Checks

```bash
# Basic health
curl https://your-app.com/health
# Expected: "OK" with 200 status

# Detailed health with metadata
curl https://your-app.com/healthz | jq
# Expected: JSON with status, time, folders

# Version info
curl https://your-app.com/version | jq
# Expected: git_sha, build_time, app name
```

#### 2. Landing Page & PWA

```bash
# Landing page loads
curl -I https://your-app.com/
# Expected: 200 status, content-type: text/html

# Manifest is accessible
curl https://your-app.com/static/manifest.webmanifest | jq
# Expected: Valid JSON with icons array

# Service worker registered
curl -I https://your-app.com/static/js/service-worker.js
# Expected: 200 status, content-type: application/javascript
```

#### 3. Security & Authentication

```bash
# Admin requires auth in enforced mode
curl -I https://your-app.com/admin
# Expected: 401 Unauthorized (without token)

# Admin accessible with token
curl "https://your-app.com/admin?token=YOUR_TOKEN"
# Expected: 200 with admin panel HTML

# Status endpoint (enforced mode)
curl "https://your-app.com/admin/status?token=YOUR_TOKEN" | jq
# Expected: JSON with security_mode, metrics, tokens, time
```

#### 4. Metrics & Observability

```bash
# Prometheus metrics with HELP/TYPE
curl https://your-app.com/metrics
# Expected: Metrics with annotations like:
# # HELP requests_total Total number of HTTP requests received
# # TYPE requests_total counter
# requests_total 123

# Verify all expected metrics present
curl https://your-app.com/metrics | grep -E "requests_total|admin_requests_total|rate_limited_total|breakglass_used_total|token_rotations_total"
```

#### 5. PWA Installation Test

Open browser DevTools:

1. Navigate to `https://your-app.com/`
2. Application tab → Manifest: Should show valid manifest with all icon sizes
3. Application tab → Service Workers: Should show registered worker
4. Install prompt should appear on mobile (or use Chrome's "Install App" menu)
5. After installation, app should work offline (shows `/offline` route when disconnected)

#### 6. Rate Limiting Verification

```bash
# Trigger rate limit (requires low ADMIN_RATE_MAX setting)
for i in {1..65}; do 
  curl -s "https://your-app.com/admin?token=YOUR_TOKEN" > /dev/null
  echo "Request $i"
done

# Check metrics for rate_limited_total increment
curl "https://your-app.com/metrics" | grep rate_limited_total
```

#### 7. SBOM & Supply Chain

```bash
# Check if SBOM diff workflow ran (after merge/tag)
# Visit: https://github.com/YOUR_ORG/SemptifyGUI/actions/workflows/sbom-diff.yml

# Download latest SBOM artifact
# Expected: diff report showing added/removed packages
```

### Post-Deployment Monitoring

Set up alerts for:

- `/health` endpoint failing (service down)
- `errors_total` metric increasing rapidly
- `rate_limited_total` spiking (potential attack)
- SBOM diff showing unexpected dependency changes

### Troubleshooting Common Issues

| Issue | Check | Fix |
|-------|-------|-----|
| Admin returns 401 with valid token | Token hash mismatch | Regenerate hash: `sha256:` + SHA256 of raw token |
| CSRF validation fails | `FLASK_SECRET` not set or changed | Set persistent secret in env vars |
| Metrics missing | Prometheus scrape config | Point scraper to `/metrics` endpoint |
| PWA install doesn't work | Manifest or icons missing | Verify `/static/manifest.webmanifest` and icon files exist |
| SBOM diff not running | Workflow permissions | Check `contents: read` permission in workflow |

### Render-Specific Deployment

1. **Environment Variables** (via Render Dashboard):
   ```
   SECURITY_MODE=enforced
   FLASK_SECRET=<random-32-byte-hex>
   ADMIN_RATE_WINDOW=60
   ADMIN_RATE_MAX=100
   GIT_SHA=${RENDER_GIT_COMMIT}
   BUILD_TIME=${RENDER_DEPLOY_TIME}
   ```

2. **Secrets** (via Render Secret Files):
   - Create `security/admin_tokens.json` as a secret file
   - Format: `[{"id":"primary","hash":"sha256:...","enabled":true}]`

3. **Post-Deploy Verification**:
   ```powershell
   .\RenderSmokeTest.ps1 -BaseUrl https://semptifygui.onrender.com -AdminToken $env:ADMIN_TOKEN
   ```

### Success Criteria ("Open Doors")

Semptify is considered **"Open Doors"** when:

- ✅ All health checks pass (endpoints return 200)
- ✅ Landing page renders with feature sections and is installable as PWA
- ✅ Admin portal accessible with proper authentication
- ✅ Metrics endpoint returns all counters with HELP/TYPE annotations
- ✅ CSRF protection active in enforced mode
- ✅ Rate limiting prevents abuse
- ✅ Event logs capture admin actions
- ✅ SBOM diff workflow runs on releases
- ✅ All tests pass (17 tests covering auth, CSRF, rate limiting, breakglass)
- ✅ Documentation complete and accurate

---

Contributions or feature requests: open an issue or describe the desired end-user workflow and the automation you want.
