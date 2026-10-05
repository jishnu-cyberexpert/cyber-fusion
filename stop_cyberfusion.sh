#!/usr/bin/env bash
echo "Shutting down CyberFusion XDR Enterprise services..."

# Free Ports 8000 and 5173
fuser -k 8000/tcp 2>/dev/null || lsof -ti:8000 | xargs kill -9 2>/dev/null
fuser -k 5173/tcp 2>/dev/null || lsof -ti:5173 | xargs kill -9 2>/dev/null

# Terminate Python processes for agent and uvicorn
pkill -f "cyberfusion_agent.py" 2>/dev/null
pkill -f "uvicorn app.main:app" 2>/dev/null

echo "[✓] All CyberFusion XDR services stopped."
