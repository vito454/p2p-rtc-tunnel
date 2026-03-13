"""Reliability layer over unreliable RTP transport.

Provides:
  - Sequencing and ordering
  - ACK-based acknowledgment
  - Retransmission with exponential backoff
  - Sliding window flow control
  - Message fragmentation and reassembly

This is essentially a simplified TCP-like layer on top of our custom RTP
frames, but optimized for our use case (lower overhead, no connection
setup handshake beyond WebRTC's own ICE/DTLS).
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Awaitable

from .frames import Frame, FrameType, FrameFlags, HEADER_SIZE

logger = logging.getLogger(__name__)


@dataclass
class UnackedFrame:
    """A 'sent' frame waiting for acknowledgment."""
    frame: Frame
    sent_at: float
    retransmit_count: int = 0
    next_retransmit: float = 0.0


@dataclass
class ReassemblyBuffer:
    """Collects fragments of a multi-frame message."""
    fragments: dict[int, bytes] = field(default_factory=dict)
    expected_last_seq: int | None = None


class ReliableChannel:
    """Reliable ordered delivery over a single logical channel.

    Usage:
        ch = ReliableChannel(
            channel_id=1,
            send_raw=transport.send_rtp_payload,
            mtu=1200,
            window_size=64,
        )
        # Sending:
        await ch.send(b"some large message")

        # Receiving (register callback):
        ch.on_message = my_handler  # async def my_handler(data: bytes)

        # Feed incoming frames:
        await ch.handle_frame(frame)

        # Run retransmission loop:
        asyncio.create_task(ch.retransmit_loop())
    """

    def __init__(
        self,
        channel_id: int,
        send_raw: Callable[[bytes], Awaitable[None]],
        mtu: int = 1200,
        window_size: int = 64,
        max_retransmits: int = 10,
        base_rto_ms: int = 200,
    ) -> None:
        self.channel_id = channel_id
        self._send_raw = send_raw
        self._mtu = mtu
        self._max_payload = mtu - HEADER_SIZE
        self._window_size = window_size
        self._max_retransmits = max_retransmits
        self._base_rto = base_rto_ms / 1000.0

        # Sending state
        self._send_seq: int = 0
        self._send_window: dict[int, UnackedFrame] = {}
        self._send_lock = asyncio.Lock()
        self._window_available = asyncio.Event()
        self._window_available.set()

        # Receiving state
        self._recv_next_seq: int = 0
        self._recv_buffer: dict[int, Frame] = {}
        self._reassembly: dict[int, list[bytes]] = defaultdict(list)

        # Callbacks
        self.on_message: Callable[[bytes], Awaitable[None]] | None = None

        # Control
        self._closed = False
        self._srtt: float = 0.1  # Smoothed RTT estimate  # noqa

    async def send(self, data: bytes) -> None:
        """Send a message, fragmenting if necessary."""
        fragments = self._fragment(data)

        for i, frag_data in enumerate(fragments):
            is_last = i == len(fragments) - 1
            flags = 0 if is_last else FrameFlags.MORE_FRAGMENTS

            await self._send_frame(
                FrameType.DATA, flags=flags, payload=frag_data
            )

    async def _send_frame(
        self,
        ftype: FrameType,  # noqa
        flags: int = 0,
        payload: bytes = b"",
    ) -> None:
        """Send a single frame with reliability."""
        # Wait for window space
        while len(self._send_window) >= self._window_size:
            self._window_available.clear()
            await self._window_available.wait()

        async with self._send_lock:
            seq = self._send_seq
            self._send_seq += 1

        frame = Frame(
            type=ftype,
            flags=flags,
            channel_id=self.channel_id,
            seq=seq,
            ack=self._recv_next_seq,
            payload=payload,
        )

        now = time.monotonic()
        self._send_window[seq] = UnackedFrame(
            frame=frame,
            sent_at=now,
            next_retransmit=now + self._base_rto,
        )

        raw = frame.serialize()
        await self._send_raw(raw)

    async def _send_ack(self, ack_seq: int) -> None:
        """Send a standalone ACK (no payload, not tracked for retransmit)."""
        frame = Frame(
            type=FrameType.ACK,
            flags=0,
            channel_id=self.channel_id,
            seq=0,
            ack=ack_seq,
        )
        await self._send_raw(frame.serialize())

    async def handle_frame(self, frame: Frame) -> None:
        """Process an incoming frame from the transport."""
        if frame.type == FrameType.ACK:
            self._process_ack(frame.ack)
            return

        if frame.type == FrameType.PING:
            pong = Frame(
                type=FrameType.PONG, flags=0,
                channel_id=self.channel_id,
                seq=0, ack=frame.seq,
            )
            await self._send_raw(pong.serialize())
            return

        if frame.type == FrameType.DATA:
            await self._process_data(frame)

    async def _process_data(self, frame: Frame) -> None:
        """Process incoming data frame, handle ordering and reassembly."""
        seq = frame.seq

        # Send ACK immediately
        await self._send_ack(seq + 1)

        # Duplicate check
        if seq < self._recv_next_seq:
            return

        # Buffer out-of-order
        self._recv_buffer[seq] = frame

        # Deliver in-order frames
        while self._recv_next_seq in self._recv_buffer:
            f = self._recv_buffer.pop(self._recv_next_seq)
            self._recv_next_seq += 1

            # Reassembly
            self._reassembly[self.channel_id].append(f.payload)

            if not f.has_more_fragments:
                # Complete message
                full_data = b"".join(self._reassembly[self.channel_id])
                self._reassembly[self.channel_id] = []

                if self.on_message:
                    await self.on_message(full_data)

    def _process_ack(self, ack_seq: int) -> None:
        """Process cumulative ACK — all frames with seq < ack_seq are confirmed."""
        acked = [s for s in self._send_window if s < ack_seq]
        for s in acked:
            unacked = self._send_window.pop(s)
            # Update RTT estimate
            rtt = time.monotonic() - unacked.sent_at
            self._srtt = 0.8 * self._srtt + 0.2 * rtt  # noqa

        if len(self._send_window) < self._window_size:
            self._window_available.set()

    def _fragment(self, data: bytes) -> list[bytes]:
        """Split data into MTU-sized fragments."""
        if len(data) <= self._max_payload:
            return [data]
        chunks = []
        for i in range(0, len(data), self._max_payload):
            chunks.append(data[i : i + self._max_payload])
        return chunks

    async def retransmit_loop(self) -> None:
        """Background task: retransmit unacked frames."""
        while not self._closed:
            await asyncio.sleep(0.05)  # Check every 50ms
            now = time.monotonic()

            frames_to_resend = []
            for seq, unacked in list(self._send_window.items()):
                if now >= unacked.next_retransmit:
                    if unacked.retransmit_count >= self._max_retransmits:
                        logger.error(
                            "Frame seq=%d exceeded max retransmits, dropping", seq
                        )
                        self._send_window.pop(seq)
                        continue

                    unacked.retransmit_count += 1
                    # Exponential backoff
                    rto = self._base_rto * (2 ** unacked.retransmit_count)
                    unacked.next_retransmit = now + rto
                    frames_to_resend.append(unacked.frame)

            for frame in frames_to_resend:
                logger.debug("Retransmitting seq=%d", frame.seq)
                await self._send_raw(frame.serialize())

    async def close(self) -> None:
        """Close the channel."""
        self._closed = True
        await self._send_frame(FrameType.FIN)
