# Run Semptify GUI demo (PowerShell)
# Creates venv (if missing), activates it, installs requirements and runs the Flask app.

$root = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Set-Location $root

if (-not (Test-Path .venv)) {
    Write-Host "Creating virtual environment .venv..."
    python -m venv .venv
}

Write-Host "Activating virtual environment..."
. .\.venv\Scripts\Activate.ps1

Write-Host "Installing requirements (if requirements.txt exists)..."
if (Test-Path requirements.txt) {
    pip install -r requirements.txt
}

Write-Host "Starting Semptify in development mode..."
python .\Semptify.py
