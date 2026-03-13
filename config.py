"""Configuration and CLI argument parsing."""

import argparse
from dataclasses import dataclass, field


@dataclass
class SignalingConfig:
    host: str = "0.0.0.0"
    port: int = 9000


@dataclass
class PeerConfig:
    role: str = "offer"  # "offer" or "answer"
    signaling_url: str = "ws://localhost:9000"
    room: str = "default"
    secret: str = "change-me"
    proxy_port: int = 8080
    crypto_chain: list[str] = field(default_factory=lambda: ["aes-256-gcm"])
    compression_chain: list[str] = field(default_factory=lambda: ["zstd"])
    stun_servers: list[str] = field(
        default_factory=lambda: ["stun:stun.l.google.com:19302"]
    )
    turn_servers: list[str] = field(default_factory=list)
    mtu: int = 1200
    window_size: int = 64
    max_retransmits: int = 5
    retransmit_timeout_ms: int = 200


def parse_args() -> tuple[str, SignalingConfig | PeerConfig]:
    """Parse CLI arguments, return (mode, config)."""
    parser = argparse.ArgumentParser(
        description="P2P Tunnel Proxy — encrypted WebRTC tunnel with HTTP proxy"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # Signaling server mode
    sig = sub.add_parser("signaling", help="Run signaling server")
    sig.add_argument("--host", default="0.0.0.0")
    sig.add_argument("--port", type=int, default=9000)

    # Peer mode
    peer = sub.add_parser("peer", help="Run peer proxy")
    peer.add_argument("--role", choices=["offer", "answer"], required=True)
    peer.add_argument("--signaling", default="ws://localhost:9000")
    peer.add_argument("--room", default="default")
    peer.add_argument("--secret", required=True, help="Shared secret for E2E crypto")
    peer.add_argument("--proxy-port", type=int, default=8080)
    peer.add_argument(
        "--crypto",
        default="aes-256-gcm",
        help="Comma-separated cipher chain (e.g. aes-256-gcm,chacha20-poly1305)",  # noqa
    )
    peer.add_argument(
        "--compression",
        default="zstd",
        help="Comma-separated compressor chain (e.g. zstd,lz4)",
    )
    peer.add_argument("--stun", default="stun:stun.l.google.com:19302")
    peer.add_argument("--turn", default="", help="TURN server URI")
    peer.add_argument("--mtu", type=int, default=1200)
    peer.add_argument("--window-size", type=int, default=64)

    args = parser.parse_args()

    if args.mode == "signaling":
        return "signaling", SignalingConfig(host=args.host, port=args.port)
    else:
        stun = [s.strip() for s in args.stun.split(",") if s.strip()]
        turn = [s.strip() for s in args.turn.split(",") if s.strip()] if args.turn else []
        return "peer", PeerConfig(
            role=args.role,
            signaling_url=args.signaling,
            room=args.room,
            secret=args.secret,
            proxy_port=args.proxy_port,
            crypto_chain=[c.strip() for c in args.crypto.split(",")],
            compression_chain=[c.strip() for c in args.compression.split(",")],
            stun_servers=stun,
            turn_servers=turn,
            mtu=args.mtu,
            window_size=args.window_size,
        )
