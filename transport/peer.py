"""WebRTC peer connection management.

Wraps aiortc RTCPeerConnection to handle:
  - ICE configuration (STUN/TURN servers)
  - SDP offer/answer exchange via signaling
  - DataChannel creation
  - Optional video track for traffic cover
  - Connection state management
"""

import asyncio  # noqa
import logging
from typing import Callable, Awaitable  # noqa

try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer  # noqa
    from aiortc.contrib.signaling import object_to_string, object_from_string  # noqa
except:  # noqa
    raise ImportError('Import Error: aiortc not installed')

from .rtp_channel import RTPTunnel


logger = logging.getLogger(__name__)


class PeerConnection:
    """Manages a WebRTC peer connection with tunnel transport.

    Usage:
        peer = PeerConnection(config)
        tunnel = await peer.connect(signaling_client)
        # tunnel is now ready to send/receive
    """

    def __init__(
        self,
        stun_servers: list[str] | None = None,
        turn_servers: list[str] | None = None,
        use_cover_track: bool = True,
    ) -> None:
        ice_servers = []
        for url in (stun_servers or []):
            ice_servers.append(RTCIceServer(urls=[url]))
        for url in (turn_servers or []):
            ice_servers.append(RTCIceServer(urls=[url]))

        self._config = RTCConfiguration(iceServers=ice_servers)
        self._pc: RTCPeerConnection | None = None  # noqa
        self._tunnel = RTPTunnel()
        self._use_cover = use_cover_track
        self._closed = False

    @property
    def tunnel(self) -> RTPTunnel:
        return self._tunnel

    async def connect_as_offerer(self, signaling) -> RTPTunnel:
        """Create offer, exchange SDP, establish connection.

        Args:
            signaling: SignalingClient instance with send/receive methods
        """
        self._pc = RTCPeerConnection(configuration=self._config)
        self._setup_event_handlers()

        # Add cover video track
        if self._use_cover:
            cover = self._tunnel.create_cover_track()
            self._pc.addTrack(cover)

        # Create DataChannel
        dc = self._pc.createDataChannel(
            "tunnel",
            ordered=True,
            protocol="binary",
        )
        self._tunnel.bind_datachannel(dc)

        # Create and send offer
        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)

        await signaling.send({
            "type": "offer",
            "sdp": self._pc.localDescription.sdp,
        })

        logger.info("Sent offer, waiting for answer...")

        # Wait for answer
        msg = await signaling.receive()
        answer = RTCSessionDescription(sdp=msg["sdp"], type=msg["type"])
        await self._pc.setRemoteDescription(answer)

        logger.info("Got answer, connection establishing...")

        await self._tunnel.wait_ready()
        logger.info("Tunnel ready")
        return self._tunnel

    async def connect_as_answerer(self, signaling) -> RTPTunnel:
        """Wait for offer, create answer, establish connection.

        Args:
            signaling: SignalingClient instance with send/receive methods
        """
        self._pc = RTCPeerConnection(configuration=self._config)
        self._setup_event_handlers()

        # Register datachannel handler BEFORE setRemoteDescription to
        # avoid missing the event if negotiation completes quickly.
        @self._pc.on("datachannel")
        def on_datachannel(channel):
            logger.info("Received DataChannel: %s", channel.label)
            if channel.label == "tunnel":
                self._tunnel.bind_datachannel(channel)

        # Wait for offer
        logger.info("Waiting for offer...")
        msg = await signaling.receive()
        offer = RTCSessionDescription(sdp=msg["sdp"], type=msg["type"])
        await self._pc.setRemoteDescription(offer)

        # Add cover video track (answerer side)
        if self._use_cover:
            cover = self._tunnel.create_cover_track()
            self._pc.addTrack(cover)

        # Create and send answer
        answer = await self._pc.createAnswer()
        await self._pc.setLocalDescription(answer)

        await signaling.send({
            "type": "answer",
            "sdp": self._pc.localDescription.sdp,
        })

        logger.info("Sent answer, connection establishing...")

        await self._tunnel.wait_ready()
        logger.info("Tunnel ready")
        return self._tunnel

    def _setup_event_handlers(self) -> None:
        @self._pc.on("connectionstatechange")
        async def on_state_change():
            state = self._pc.connectionState
            logger.info("Connection state: %s", state)
            if state == "failed":
                await self.close()

        @self._pc.on("iceconnectionstatechange")
        async def on_ice_state():
            logger.info("ICE state: %s", self._pc.iceConnectionState)

        @self._pc.on("track")
        def on_track(track):
            logger.debug("Received track: %s (%s)", track.kind, track.id)
            # We ignore incoming video — it's just cover traffic

    async def close(self) -> None:
        if self._pc and not self._closed:
            self._closed = True
            await self._pc.close()
            logger.info("Peer connection closed")
