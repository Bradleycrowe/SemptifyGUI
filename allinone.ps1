# All-in-one PowerShell script for Semptify production workflow

# 1. Start production server (Waitress)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python run_prod.py"

# 2. Wait for server to start
Start-Sleep -Seconds 2

# 3. Open Semptify homepage in browser
Start-Process "http://localhost:8080"

# 4. Open shell.html for live editing
Start-Process "c:\Semptify\Semptify\templates\shell.html"

# 5. Show completion message
Write-Host "Semptify production server started and homepage opened. Shell.html ready for editing."
