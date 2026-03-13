"""WebSocket signaling server.

Minimal signaling server that relays SDP offers/answers and ICE candidates
between peers in the same room.  This is the only public-facing component.

Rooms are identified by a string key.  Each room holds exactly two peers.
Messages from one peer are forwarded to the other.
"""

import json
import logging
from collections import defaultdict

try:
    from aiohttp import web, WSMsgType  # noqa
except:  # noqa
    raise ImportError('ImportError: aiohttp is not installed')


logger = logging.getLogger(__name__)


class SignalingServer:
    """WebSocket signaling server with room-based routing."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        self._host = host
        self._port = port
        self._app = web.Application()
        self._app.router.add_get("/ws/{room}", self._websocket_handler)
        self._app.router.add_get("/health", self._health)
        # room_id → list of websocket connections
        self._rooms: dict[str, list[web.WebSocketResponse]] = defaultdict(list)

    async def _health(self, request: web.Request) -> web.Response:  # noqa
        rooms_info = {k: len(v) for k, v in self._rooms.items()}
        return web.json_response({"status": "ok", "rooms": rooms_info})

    async def _websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        room = request.match_info["room"]
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        peers = self._rooms[room]

        if len(peers) >= 2:
            await ws.send_json({"error": "Room full"})
            await ws.close()
            return ws

        peers.append(ws)
        peer_idx = len(peers) - 1
        logger.info("Peer %d joined room '%s' (%d/2)", peer_idx, room, len(peers))

        # Notify peer of their role
        await ws.send_json({"type": "joined", "peer_index": peer_idx, "room": room})

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    # Relay to other peer(s) in room
                    for other in peers:
                        if other is not ws and not other.closed:
                            await other.send_json(data)
                elif msg.type == WSMsgType.ERROR:
                    logger.error(
                        "WebSocket error in room '%s': %s",
                        room, ws.exception()
                    )
        finally:
            peers.remove(ws)
            if not peers:
                del self._rooms[room]
            logger.info("Peer left room '%s' (%d remaining)", room, len(self._rooms.get(room, [])))

        return ws

    async def start(self) -> None:
        """Start the signaling server."""
        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()
        logger.info("Signaling server listening on %s:%d", self._host, self._port)

    def run(self) -> None:
        """Run the signaling server (blocking)."""
        web.run_app(self._app, host=self._host, port=self._port)
