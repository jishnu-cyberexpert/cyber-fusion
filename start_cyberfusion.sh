#!/usr/bin/env bash
echo "Starting CyberFusion XDR Enterprise Services..."

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Central Backend Server
export PYTHONPATH="backend"
if [ -f "$ROOT_DIR/venv/Scripts/python" ]; then
    PYTHON_BIN="$ROOT_DIR/venv/Scripts/python"
elif [ -f "$ROOT_DIR/venv/bin/python" ]; then
    PYTHON_BIN="$ROOT_DIR/venv/bin/python"
else
    PYTHON_BIN="python"
fi

$PYTHON_BIN -m uvicorn app.main:app --port 8000 --host 0.0.0.0 > "$ROOT_DIR/backend.log" 2>&1 &
echo "[+] Backend started on http://127.0.0.1:8000 (PID: $!)"

# 2. Frontend SOC Console
cd "$ROOT_DIR/frontend" || exit
npm run dev -- --host 127.0.0.1 --port 5173 > "$ROOT_DIR/frontend.log" 2>&1 &
echo "[+] Frontend SOC Console started on http://127.0.0.1:5173 (PID: $!)"
cd "$ROOT_DIR" || exit

# 3. Live EDR Endpoint Agent
export PYTHONPATH="."
$PYTHON_BIN agent/cyberfusion_agent.py > "$ROOT_DIR/agent.log" 2>&1 &
echo "[+] Live EDR Agent started (PID: $!)"

echo "[✓] All services running in background! Access UI at http://127.0.0.1:5173"
