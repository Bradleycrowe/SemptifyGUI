# PowerShell script to start Flask and open shell.html in default browser
$env:FLASK_APP = "Semptify.py"
$env:FLASK_ENV = "development"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python Semptify.py"
Start-Sleep -Seconds 2
Start-Process "http://localhost:5000"
Start-Process "c:\Semptify\Semptify\templates\shell.html"
