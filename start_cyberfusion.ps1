Write-Host "Starting CyberFusion XDR Enterprise Services..." -ForegroundColor Cyan

# 1. Central Backend Server (Port 8000)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; `$env:PYTHONPATH='backend'; .\venv\Scripts\python -m uvicorn app.main:app --port 8000 --host 0.0.0.0"
Write-Host "[+] Backend launching on http://127.0.0.1:8000" -ForegroundColor Green

# 2. Frontend SOC Console (Port 5173)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev -- --host 127.0.0.1 --port 5173"
Write-Host "[+] Frontend SOC Console launching on http://127.0.0.1:5173" -ForegroundColor Green

# 3. Live EDR Endpoint Agent
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; `$env:PYTHONPATH='.'; .\venv\Scripts\python agent\cyberfusion_agent.py"
Write-Host "[+] Live EDR Endpoint Agent launching..." -ForegroundColor Green

Write-Host "`n[✓] All services spawned in dedicated windows. Open: http://127.0.0.1:5173" -ForegroundColor Cyan
