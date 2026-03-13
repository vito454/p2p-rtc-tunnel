"""Local HTTP proxy server.

Accepts HTTP requests from the local browser and tunnels them through
the P2P WebRTC connection to the remote peer, which fulfills them and
sends responses back.

Supports:
  - HTTP/1.1 GET, POST, PUT, DELETE, etc.
  - CONNECT method for HTTPS tunneling
  - Chunked transfer encoding
  - Streaming responses

The request/response is serialized into a simple binary format,
passed through the crypto pipeline, and sent over the P2P tunnel.
"""

import asyncio
import base64
import json
import logging
from uuid import uuid4

from crypto.pipeline import CryptoPipeline
from protocol.multiplexer import Multiplexer
from protocol.reliable import ReliableChannel


logger = logging.getLogger(__name__)


# --- Wire format for HTTP request/response over tunnel ---
#
# Request (regular HTTP):
#   { "type": "request", "id": "uuid", "method": "GET", "url": "http://...",
#     "headers": {...}, "body_b64": "..." }
#
# Response (regular HTTP):
#   { "type": "response", "id": "uuid", "status": int, "headers": {...},
#     "body_b64": "..." }
#
# CONNECT request:
#   { "type": "connect", "host": "example.com", "port": 443 }
#
# CONNECT response:
#   { "type": "connect_ok" }  or  { "type": "connect_error", "error": "..." }
#
# After connect_ok, the channel carries raw encrypted byte chunks.


def serialize_request(request_id: str, method: str, url: str,
                      headers: dict, body: bytes) -> bytes:
    """Serialize an HTTP request for tunnel transport."""
    msg = {
        "id": request_id,
        "type": "request",
        "method": method,
        "url": url,
        "headers": dict(headers),
        "body_b64": base64.b64encode(body).decode() if body else "",
    }
    return json.dumps(msg).encode()


def serialize_response(request_id: str, status: int, headers: dict,
                       body: bytes) -> bytes:
    """Serialize an HTTP response for tunnel transport."""
    msg = {
        "id": request_id,
        "type": "response",
        "status": status,
        "headers": dict(headers),
        "body_b64": base64.b64encode(body).decode() if body else "",
    }
    return json.dumps(msg).encode()


def deserialize_message(data: bytes) -> dict:
    """Deserialize a tunnel message."""
    msg = json.loads(data)
    if msg.get("body_b64"):
        msg["body"] = base64.b64decode(msg["body_b64"])
    else:
        msg["body"] = b""
    return msg


class HTTPProxyServer:
    """Local HTTP proxy that tunnels requests through P2P.

    Uses a raw asyncio TCP server to support both regular HTTP proxying
    and HTTPS CONNECT tunneling.

    Usage:
        proxy = HTTPProxyServer(
            pipeline=crypto_pipeline,
            multiplexer=mux,
            port=8080,
        )
        await proxy.start()
    """

    def __init__(
        self,
        pipeline: CryptoPipeline,
        multiplexer: Multiplexer,
        port: int = 8080,
        bind: str = "127.0.0.1",
    ) -> None:
        self._pipeline = pipeline
        self._mux = multiplexer
        self._port = port
        self._bind = bind
        self._server = None

    async def start(self) -> None:
        """Start the local HTTP proxy."""
        self._server = await asyncio.start_server(
            self._handle_client, self._bind, self._port,
        )
        logger.info("HTTP proxy listening on %s:%d", self._bind, self._port)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one client connection (could be HTTP or CONNECT)."""
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                return

            parts = request_line.decode("utf-8", errors="replace").strip().split(" ", 2)
            if len(parts) != 3:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            method, target, _version = parts

            # Read headers
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    key, value = decoded.split(":", 1)
                    headers[key.strip()] = value.strip()

            if method.upper() == "CONNECT":
                await self._handle_connect(target, headers, reader, writer)
            else:
                await self._handle_http(method, target, headers, reader, writer)

        except asyncio.TimeoutError:
            logger.debug("Client connection timed out")
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error("Client handler error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa
                pass

    # Regular HTTP proxying:
    async def _handle_http(
        self,
        method: str,
        url: str,
        headers: dict,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Proxy a regular HTTP request through the tunnel."""
        # Read body if present
        body = b""
        cl = headers.get("Content-Length", "")
        if cl.isdigit() and int(cl) > 0:
            body = await asyncio.wait_for(
                reader.readexactly(int(cl)), timeout=30,
            )

        request_id = uuid4().hex

        # Serialize, encrypt, send through tunnel
        raw = serialize_request(request_id, method, url, headers, body)
        encrypted = self._pipeline.process(raw)  # noqa

        channel = self._mux.open_channel()
        future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

        async def on_response(data: bytes) -> None:
            if not future.done():
                future.set_result(data)

        channel.on_message = on_response
        await channel.send(encrypted)

        # Wait for response from remote peer
        try:
            encrypted_response = await asyncio.wait_for(future, timeout=60)
        except asyncio.TimeoutError:
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n"
                         b"Content-Length: 0\r\n\r\n")
            await writer.drain()
            return

        # Decrypt and forward to client
        raw_response = self._pipeline.unprocess(encrypted_response)
        msg = deserialize_message(raw_response)

        status = msg["status"]
        resp_body = msg["body"]

        # Build raw HTTP response
        writer.write(f"HTTP/1.1 {status} OK\r\n".encode())
        resp_headers = msg.get("headers", {})
        # Replace content-length with actual body length; drop hop-by-hop
        skip = {"transfer-encoding", "content-length", "connection"}
        for k, v in resp_headers.items():
            if k.lower() not in skip:
                writer.write(f"{k}: {v}\r\n".encode())
        writer.write(f"Content-Length: {len(resp_body)}\r\n".encode())
        writer.write(b"\r\n")
        writer.write(resp_body)
        await writer.drain()

    # HTTPS CONNECT tunneling:
    async def _handle_connect(
        self,
        target: str,
        headers: dict,  # noqa  # TODO: future.
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle CONNECT method — establish an encrypted byte relay."""
        # Parse host:port
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = target, 443

        logger.info("CONNECT %s:%d", host, port)

        # Ask the remote peer to open a TCP connection to the target
        connect_msg = json.dumps({
            "type": "connect",
            "host": host,
            "port": port,
        }).encode()
        encrypted = self._pipeline.process(connect_msg)  # noqa

        channel = self._mux.open_channel()
        reply_future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

        async def on_first_msg(data: bytes) -> None:
            if not reply_future.done():
                reply_future.set_result(data)

        channel.on_message = on_first_msg
        await channel.send(encrypted)

        # Wait for connect confirmation
        try:
            encrypted_reply = await asyncio.wait_for(reply_future, timeout=30)
        except asyncio.TimeoutError:
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await writer.drain()
            return

        reply = json.loads(self._pipeline.unprocess(encrypted_reply))
        if reply.get("type") != "connect_ok":
            err = reply.get("error", "tunnel refused")
            writer.write(f"HTTP/1.1 502 Bad Gateway\r\n"
                         f"Content-Length: {len(err)}\r\n\r\n{err}".encode())
            await writer.drain()
            return

        # Tell the client the tunnel is up
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Bidirectional relay: client <-> encrypted channel
        closed = asyncio.Event()

        async def client_to_tunnel():
            try:
                while not closed.is_set():
                    data = await reader.read(65536)
                    if not data:
                        break
                    encrypted_chunk = self._pipeline.process(data)
                    await channel.send(encrypted_chunk)
            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                logger.debug("client_to_tunnel ended: %s", e)
            finally:
                closed.set()

        async def tunnel_to_client():
            relay_queue: asyncio.Queue[bytes] = asyncio.Queue()

            async def on_relay(data: bytes) -> None:
                await relay_queue.put(data)

            channel.on_message = on_relay

            try:
                while not closed.is_set():
                    encrypted_chunk = await asyncio.wait_for(
                        relay_queue.get(), timeout=120,
                    )
                    raw_data = self._pipeline.unprocess(encrypted_chunk)
                    writer.write(raw_data)
                    await writer.drain()
            except asyncio.TimeoutError:
                logger.debug("CONNECT relay idle timeout")
            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                logger.debug("tunnel_to_client ended: %s", e)
            finally:
                closed.set()

        await asyncio.gather(
            client_to_tunnel(),
            tunnel_to_client(),
            return_exceptions=True,
        )


class RemoteRequestHandler:
    """Handles incoming tunnel requests on the remote peer.

    Receives encrypted requests from the tunnel, decrypts them,
    makes the actual HTTP request, and sends the response back.
    Also handles CONNECT requests by opening TCP connections to targets.
    """

    def __init__(
        self,
        pipeline: CryptoPipeline,
        multiplexer: Multiplexer,
    ) -> None:
        self._pipeline = pipeline
        self._mux = multiplexer
        self._session = None  # aiohttp.ClientSession, created lazily

    async def setup(self) -> None:
        """Register handler for incoming channels."""
        try:
            import aiohttp  # noqa
        except:  # noqa
            raise ImportError("Unable to import aiohttp")
        self._session = aiohttp.ClientSession()

        async def on_channel(channel: ReliableChannel) -> None:
            async def on_message(data: bytes) -> None:
                await self._dispatch(channel, data)
            channel.on_message = on_message

        self._mux.on_channel = on_channel

    async def _dispatch(
        self, channel: ReliableChannel, encrypted_data: bytes,
    ) -> None:
        """Route incoming message to the right handler."""
        try:
            raw = self._pipeline.unprocess(encrypted_data)
            msg = json.loads(raw)
        except Exception as e:
            logger.error("Failed to decrypt/parse tunnel message: %s", e)
            return

        msg_type = msg.get("type")
        if msg_type == "connect":
            await self._handle_connect(channel, msg)
        elif msg_type == "request":
            # Decode body for HTTP requests
            if msg.get("body_b64"):
                msg["body"] = base64.b64decode(msg["body_b64"])
            else:
                msg["body"] = b""
            await self._handle_http_request(channel, msg)
        else:
            logger.warning("Unknown tunnel message type: %s", msg_type)

    # ── Regular HTTP ──────────────────────────────────────────────────

    async def _handle_http_request(
        self, channel: ReliableChannel, msg: dict,
    ) -> None:
        """Decrypt request, fetch from internet, encrypt response, send back."""
        try:
            import aiohttp  # noqa
        except:  # noqa
            raise ImportError("Unable to import aiohttp")

        try:
            logger.info("Proxying %s %s", msg["method"], msg["url"])

            async with self._session.request(
                method=msg["method"],
                url=msg["url"],
                headers={k: v for k, v in msg.get("headers", {}).items()
                         if k.lower() not in (
                             "host", "connection", "proxy-connection",
                         )},
                data=msg["body"] or None,
                timeout=aiohttp.ClientTimeout(total=55),
            ) as resp:
                body = await resp.read()
                raw_response = serialize_response(
                    request_id=msg["id"],
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                )

            encrypted_response = self._pipeline.process(raw_response)
            await channel.send(encrypted_response)

        except Exception as e:
            logger.error("Error proxying %s: %s", msg.get("url"), e)
            try:
                error_resp = serialize_response(
                    request_id=msg.get("id", "unknown"),
                    status=502,
                    headers={"Content-Type": "text/plain"},
                    body=f"Proxy error: {e}".encode(),
                )
                encrypted_error = self._pipeline.process(error_resp)
                await channel.send(encrypted_error)
            except Exception as inner:
                logger.error("Failed to send error response: %s", inner)

    # ── CONNECT tunneling ─────────────────────────────────────────────

    async def _handle_connect(
        self, channel: ReliableChannel, msg: dict,
    ) -> None:
        """Open TCP to target and relay bytes through the encrypted channel."""
        host = msg["host"]
        port = msg["port"]
        logger.info("CONNECT tunnel to %s:%d", host, port)

        # Open TCP connection to the target
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=30,
            )
        except Exception as e:
            logger.error("CONNECT to %s:%d failed: %s", host, port, e)
            reply = json.dumps({"type": "connect_error", "error": str(e)}).encode()
            await channel.send(self._pipeline.process(reply))
            return

        # Tell the offerer the connection is up
        reply = json.dumps({"type": "connect_ok"}).encode()
        await channel.send(self._pipeline.process(reply))

        # Bidirectional relay: encrypted channel <-> target TCP
        closed = asyncio.Event()

        async def tunnel_to_target():
            relay_queue: asyncio.Queue[bytes] = asyncio.Queue()

            async def on_data(data: bytes) -> None:
                await relay_queue.put(data)

            channel.on_message = on_data

            try:
                while not closed.is_set():
                    encrypted_chunk = await asyncio.wait_for(
                        relay_queue.get(), timeout=120,
                    )
                    raw = self._pipeline.unprocess(encrypted_chunk)
                    target_writer.write(raw)
                    await target_writer.drain()
            except asyncio.TimeoutError:
                logger.debug("CONNECT relay idle timeout")
            except Exception as wait_for_e:
                logger.debug("tunnel_to_target ended: %s", wait_for_e)
            finally:
                closed.set()

        async def target_to_tunnel():
            try:
                while not closed.is_set():
                    data = await target_reader.read(65536)
                    if not data:
                        break
                    encrypted_chunk = self._pipeline.process(data)
                    await channel.send(encrypted_chunk)
            except Exception as reader_e:
                logger.debug("target_to_tunnel ended: %s", reader_e)
            finally:
                closed.set()

        await asyncio.gather(
            tunnel_to_target(),
            target_to_tunnel(),
            return_exceptions=True,
        )

        try:
            target_writer.close()
            await target_writer.wait_closed()
        except Exception:  # noqa
            pass

    async def close(self) -> None:
        if self._session:
            await self._session.close()
