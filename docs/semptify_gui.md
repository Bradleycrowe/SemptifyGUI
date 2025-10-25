# Semptify GUI Scaffold

This document explains the integrated Semptify GUI scaffold added to the project and how to run and extend it.

Overview
- The GUI is mounted as a Flask Blueprint at `/semptify-gui`.
- Blueprint module: `semptify_gui.py` (exports `semptify_gui_bp`).
- Templates for the GUI are in `templates/semptify_gui/`.
- Static assets for the GUI are in `static/semptify_gui/` (CSS/JS demo).
- Module stubs live under `semptify_gui_modules/` and are intended as placeholders for real logic.

Key files
- `Semptify.py` — main Flask app. It auto-imports `semptify_gui` and registers `semptify_gui_bp`.
- `semptify_gui.py` — blueprint + routes + `/api/complaint` demo endpoint.
- `templates/semptify_gui/index.html` — landing page and demo form.
- `static/semptify_gui/app.js` — demo JS that POSTs to `/semptify-gui/api/complaint`.
- `semptify_gui_modules/` — package with module stubs (complaint_generator, escalation_engine, etc.).

Running locally (Windows PowerShell)
1. Open PowerShell and change to the repo root (where `Semptify.py` lives):

```powershell
Set-Location 'h:\Semptify\Semptify'
```

2. Create and activate a virtual environment (optional but recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
# If you only want to run tests, also install pytest
pip install pytest
```

4. Run the app in development mode:

```powershell
# (from repo root)
python .\Semptify.py
```

5. Open a browser and visit: http://127.0.0.1:5000/semptify-gui/

Testing
- Unit tests were added under `tests/` for the GUI index and API demo endpoints.
- Run all tests with:

```powershell
pytest -q
```

Extending the scaffold
- Add or replace logic in `semptify_gui_modules/`.
- Add templates under `templates/semptify_gui/` and static assets under `static/semptify_gui/`.
- To expose a new route or API, update `semptify_gui.py` or create additional blueprints and register them through the same import pattern used by `Semptify.py`.

Notes
- The repo's `Semptify.py` dynamically imports modules named in its import loop. To expose a new blueprint without changing `Semptify.py`, name the new module and give it a `<module>_bp` attribute.
- This scaffold is intentionally minimal and intended to be expanded. Do not commit real secrets into `security/` or uploads into `uploads/`.

Troubleshooting
- If `python` or `pytest` are not recognized on Windows, enable the App execution aliases (or install Python from python.org) and ensure the venv activation script runs in PowerShell.
- If a route is 404, confirm the blueprint is registered (look in `Semptify.py` for the import of `semptify_gui`) and that templates exist under `templates/semptify_gui/`.

Contact
- For further wiring (example: wire a dashboard page to `fraud_exposure_dashboard`), tell me which module to implement and I will add a demo endpoint and UI.
