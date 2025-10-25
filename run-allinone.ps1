# PowerShell script: All-in-one for Semptify and Axis static preview

# Start Flask development server
$env:FLASK_APP = "Semptify.py"
$env:FLASK_ENV = "development"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python Semptify.py"

# Wait for server to start
Start-Sleep -Seconds 2

# Open Semptify homepage
Start-Process "http://localhost:5000"

# Open Axis static preview
Start-Process "http://localhost:5000/static/samople/Axis/index.html"

# Optionally, open shell.html for live editing
Start-Process "c:\Semptify\Semptify\templates\shell.html"
