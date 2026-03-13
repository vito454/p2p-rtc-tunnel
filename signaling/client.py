"""WebSocket signaling client.

Connects to the signaling server and provides send/receive methods
for SDP and ICE candidate exchange.
"""

import asyncio
import json
import logging

try:
    import aiohttp  # noqa
except:  # noqa
    raise ImportError('ImportError: aiohttp is not installed')


logger = logging.getLogger(__name__)


class SignalingClient:
    """WebSocket client for signaling.

    Usage:
        async with SignalingClient("ws://server:9000", "myroom") as sig:
            await sig.send({"type": "offer", "sdp": "..."})
            msg = await sig.receive()
    """

    def __init__(self, url: str, room: str) -> None:
        # Ensure URL ends with /ws/{room}
        self._url = f"{url.rstrip('/')}/ws/{room}"
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._receive_queue: asyncio.Queue[dict] = asyncio.Queue()
        self._connected = False

    async def connect(self) -> None:
        """Connect to the signaling server."""
        self._session = aiohttp.ClientSession()
        self._ws = await self._session.ws_connect(self._url)
        self._connected = True

        # Start background reader
        asyncio.create_task(self._reader())

        # Wait for join confirmation
        msg = await self._receive_queue.get()
        if msg.get("type") == "joined":
            logger.info(
                "Joined room '%s' as peer %d",
                msg.get("room"), msg.get("peer_index")
            )
        elif "error" in msg:
            raise ConnectionError(f"Signaling error: {msg['error']}")

    async def _reader(self) -> None:
        """Background task reading WebSocket messages."""
        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    await self._receive_queue.put(data)
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception as e:
            logger.error("Signaling reader error: %s", e)
        finally:
            self._connected = False

    async def send(self, data: dict) -> None:
        """Send a JSON message to the signaling server."""
        if not self._ws or self._ws.closed:
            raise ConnectionError("Not connected to signaling server")
        await self._ws.send_json(data)

    async def receive(self, timeout: float | None = None) -> dict:
        """Receive the next message from the signaling server."""
        return await asyncio.wait_for(self._receive_queue.get(), timeout=timeout)

    async def close(self) -> None:
        """Disconnect."""
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session:
            await self._session.close()
        self._connected = False

    async def __aenter__(self) -> "SignalingClient":
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
