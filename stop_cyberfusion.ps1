# Stop all Python processes running the agent or uvicorn
Get-CimInstance Win32_Process | Where-Object { 
    $_.CommandLine -like "*cyberfusion_agent.py*" -or 
    $_.CommandLine -like "*uvicorn app.main:app*" 
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Free Ports 8000, 5173, and 1514
@(8000, 5173, 1514) | ForEach-Object {
    $port = $_
    Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[✓] All CyberFusion services and ports stopped successfully." -ForegroundColor Green
