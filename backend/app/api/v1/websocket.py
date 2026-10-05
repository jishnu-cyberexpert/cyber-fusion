"""
CyberFusion XDR Enterprise - Real-Time SOC WebSocket Channel
Broadcasts live EPS, telemetry streams, alerts, and incidents to authenticated SOC dashboards.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import logging
import asyncio

logger = logging.getLogger("cyberfusion.ws")

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"SOC Console connected via WebSocket. Active sessions: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"SOC Console disconnected. Active sessions: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast live security data plane event to all connected SOC consoles."""
        if not self.active_connections:
            return
        payload = json.dumps(message, default=str)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

ws_manager = ConnectionManager()

@router.websocket("/ws/soc")
async def soc_websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive / ping-pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket session terminated: {e}")
        ws_manager.disconnect(websocket)
