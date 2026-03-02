from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active: dict[str, WebSocket] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active[scan_id] = websocket

    async def send(self, scan_id: str, message: str):
        conn = self.active.get(scan_id)
        if conn:
            await conn.send_text(message)


manager = ConnectionManager()
