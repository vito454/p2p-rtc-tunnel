"""P2P Tunnel Proxy — main entry point.

Modes:
  signaling  — Run the signaling server (public host)
  peer       — Run a peer proxy (behind NAT)
"""
import sys  # noqa
import asyncio
import logging
import signal

from config import parse_args, SignalingConfig, PeerConfig
from crypto.pipeline import CryptoPipeline
from signaling.server import SignalingServer
from signaling.client import SignalingClient
from transport.peer import PeerConnection
from protocol.multiplexer import Multiplexer
from proxy.http_server import HTTPProxyServer, RemoteRequestHandler


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("p2p-tunnel")


async def run_signaling(config: SignalingConfig, stop: asyncio.Event) -> None:
    """Run the signaling server."""
    server = SignalingServer(host=config.host, port=config.port)
    await server.start()
    logger.info("Signaling server running. Press Ctrl+C to stop.")
    await stop.wait()


async def run_peer(config: PeerConfig, stop: asyncio.Event) -> None:
    """Run a peer proxy node."""

    # 1. Build crypto pipeline
    pipeline = CryptoPipeline.from_config(
        secret=config.secret,
        cipher_names=config.crypto_chain,
        compressor_names=config.compression_chain,
    )
    logger.info("Crypto pipeline: %s", pipeline)

    # 2. Connect to signaling server
    signaling = SignalingClient(config.signaling_url, config.room)
    await signaling.connect()

    # 3. Establish WebRTC connection
    peer = PeerConnection(
        stun_servers=config.stun_servers,
        turn_servers=config.turn_servers,
        use_cover_track=True,
    )

    if config.role == "offer":
        tunnel = await peer.connect_as_offerer(signaling)
    else:
        tunnel = await peer.connect_as_answerer(signaling)

    logger.info("WebRTC tunnel established")

    # 4. Create multiplexer over the tunnel
    mux = Multiplexer(
        send_raw=tunnel.send,
        mtu=config.mtu,
        window_size=config.window_size,
        is_offerer=(config.role == "offer"),
    )

    # Wire tunnel receive to multiplexer
    tunnel.on_receive = mux.handle_raw

    # 5. Start HTTP proxy (local browser interface)
    http_proxy = HTTPProxyServer(
        pipeline=pipeline,
        multiplexer=mux,
        port=config.proxy_port,
    )
    await http_proxy.start()

    # 6. Start remote request handler (serves requests from the other peer)
    remote_handler = RemoteRequestHandler(
        pipeline=pipeline,
        multiplexer=mux,
    )
    await remote_handler.setup()

    logger.info(
        "Peer ready — HTTP proxy on localhost:%d — role: %s",
        config.proxy_port, config.role,
    )

    # Run forever
    try:
        await stop.wait()
    except asyncio.CancelledError:
        pass
    finally:
        await remote_handler.close()
        await mux.close_all()
        await peer.close()
        await signaling.close()


def main() -> None:
    mode, config = parse_args()

    loop = asyncio.new_event_loop()

    async def _run():
        shutdown_event = asyncio.Event()

        def _shutdown():
            logger.info("Shutting down...")
            shutdown_event.set()

        for sig_name in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig_name, _shutdown)  # noqa
            except NotImplementedError:
                pass

        if mode == "signaling":
            await run_signaling(config, shutdown_event)
        elif mode == "peer":
            await run_peer(config, shutdown_event)

    try:
        loop.run_until_complete(_run())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Exiting.")
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    main()
