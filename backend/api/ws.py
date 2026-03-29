from __future__ import annotations

import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("clawguard.ws")


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.debug("WebSocket client connected (%d total)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.remove(websocket)
        logger.debug("WebSocket client disconnected (%d remaining)", len(self.active_connections))

    async def broadcast(self, message: dict) -> None:
        data = json.dumps(message, default=str)
        disconnected: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                logger.warning("Failed to send WS message, removing client", exc_info=True)
                disconnected.append(connection)
        for conn in disconnected:
            self.active_connections.remove(conn)


manager = ConnectionManager()
