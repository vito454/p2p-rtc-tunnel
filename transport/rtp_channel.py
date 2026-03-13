"""Custom RTP tunnel — encodes arbitrary data as RTP media packets.

This module creates a fake video MediaStreamTrack that aiortc will
negotiate and wrap in SRTP.  Instead of real video frames, we inject
our custom protocol frames as the RTP payload.

From a DPI perspective, the traffic looks like:
  - Standard DTLS-SRTP handshake
  - RTP packets with dynamic payload type (96+), consistent with VP8
  - Regular packet cadence
  - Encrypted payload (SRTP)

The key insight: aiortc MediaStreamTrack pipeline encodes frames,
but we bypass the codec entirely by providing pre-encoded "frames"
that are actually our tunnel data, using a custom codec or by
intercepting at the right level.

Implementation approach:
  We use aiortc DataChannel internally (SCTP over DTLS) for the actual
  data transport, BUT we also establish a dummy video track to generate
  realistic-looking SRTP traffic.  Alternatively, we can use the
  lower-level RTP APIs.

  For maximum stealth, we use a custom VideoStreamTrack that generates
  frames containing our data, combined with Insertable Streams-like
  interception.

  In practice, the simplest robust approach with aiortc is:
  1. Use DataChannel for actual data (reliable, ordered via SCTP)
  2. Add a dummy video track for traffic cover
  3. The DataChannel traffic is already encrypted via DTLS
  4. Our crypto pipeline adds E2E encryption on top
"""

import asyncio
import logging
import struct  # noqa
import time
from typing import Callable, Awaitable

try:
    from aiortc import VideoStreamTrack  # noqa
except:  # noqa
    raise ImportError('Import error: aiortc not installed')

try:
    from av import VideoFrame  # noqa
except:  # noqa
    raise ImportError('Import error: av not installed')
import numpy as np

logger = logging.getLogger(__name__)


class DummyVideoTrack(VideoStreamTrack):
    """Generates noise video frames to create realistic SRTP traffic.

    This track produces frames that look like a real (low quality) video
    stream.  The actual data is carried on the DataChannel; this track
    exists solely to make the SRTP traffic pattern look like a video call.
    """

    kind = "video"

    def __init__(self, fps: int = 15, width: int = 320, height: int = 240) -> None:
        super().__init__()
        self._fps = fps
        self._width = width
        self._height = height
        self._frame_count = 0
        self._start = time.time()

    async def recv(self) -> VideoFrame:
        """Generate next video frame (noise)."""
        pts, time_base = await self.next_timestamp()

        # Generate noise that looks somewhat like a real video frame
        # (not just random — we use low-frequency noise for compressibility)
        rng = np.random.default_rng(self._frame_count)
        # Start from a base color and add noise
        base = rng.integers(40, 60, dtype=np.uint8)
        noise = rng.integers(-20, 20, size=(self._height, self._width, 3), dtype=np.int16)
        arr = np.clip(base + noise, 0, 255).astype(np.uint8)

        frame = VideoFrame.from_ndarray(arr, format="rgb24")
        frame.pts = pts
        frame.time_base = time_base
        self._frame_count += 1

        return frame


class RTPTunnel:
    """Manages the RTP tunnel — provides send/receive over WebRTC.

    Wraps a DataChannel for actual data transport and optionally
    a video track for traffic cover.

    Usage:
        tunnel = RTPTunnel()
        # After WebRTC connection is established:
        tunnel.bind_datachannel(dc)
        tunnel.on_receive = my_handler

        await tunnel.send(data)
    """

    def __init__(self) -> None:
        self._dc = None  # aiortc DataChannel
        self._send_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.on_receive: Callable[[bytes], Awaitable[None]] | None = None
        self._ready = asyncio.Event()

    @staticmethod
    def _handle_task_exception(task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception():
            logger.error("Unhandled error in receive handler: %s", task.exception())

    def bind_datachannel(self, dc) -> None:
        """Bind to an aiortc DataChannel."""
        self._dc = dc

        @dc.on("open")
        def on_open():
            logger.info("DataChannel open")
            self._ready.set()

        # If the DataChannel is already open (common on the answerer side),
        # the "open" event won't fire again — set _ready immediately.
        if dc.readyState == "open":
            logger.info("DataChannel already open")
            self._ready.set()

        @dc.on("message")
        def on_message(message):
            if isinstance(message, str):
                message = message.encode()
            if self.on_receive:
                task = asyncio.ensure_future(self.on_receive(message))
                task.add_done_callback(self._handle_task_exception)

        @dc.on("close")
        def on_close():
            logger.info("DataChannel closed")
            self._ready.clear()

    async def wait_ready(self) -> None:
        """Wait until the DataChannel is open."""
        await self._ready.wait()

    async def send(self, data: bytes) -> None:
        """Send raw bytes over the DataChannel."""
        await self._ready.wait()
        # DataChannel has a max message size; aiortc handles SCTP
        # fragmentation internally, but we chunk to be safe
        MAX_DC_MSG = 64 * 1024  # 64KB per DC message  # noqa
        for i in range(0, len(data), MAX_DC_MSG):
            chunk = data[i : i + MAX_DC_MSG]
            self._dc.send(chunk)

    def create_cover_track(self, fps: int = 15) -> DummyVideoTrack:  # noqa
        """Create a dummy video track for traffic cover."""
        return DummyVideoTrack(fps=fps)
