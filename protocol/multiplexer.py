"""Channel multiplexer.

Multiplexes multiple logical channels (each a ReliableChannel) over
a single RTP transport.  Each HTTP request/response gets its own channel_id,
allowing concurrent transfers.
"""

import asyncio
import logging
from typing import Callable, Awaitable

from .frames import Frame
from .reliable import ReliableChannel

logger = logging.getLogger(__name__)


class Multiplexer:
    """Multiplexes reliable channels over one raw transport.

    Usage:
        mux = Multiplexer(send_raw=transport.send_rtp_payload, mtu=1200)

        # Create a channel for a request
        ch = mux.open_channel()
        await ch.send(request_data)

        # Feed incoming raw data
        await mux.handle_raw(data)
    """

    def __init__(
        self,
        send_raw: Callable[[bytes], Awaitable[None]],
        mtu: int = 1200,
        window_size: int = 64,
        is_offerer: bool = True,
    ) -> None:
        self._send_raw = send_raw
        self._mtu = mtu
        self._window_size = window_size
        self._channels: dict[int, ReliableChannel] = {}
        # Offerer uses odd IDs (1, 3, 5, ...), answerer uses even (2, 4, 6, ...)
        # This prevents channel ID collisions when both peers proxy.
        self._next_channel_id: int = 1 if is_offerer else 2
        self._channel_step: int = 2
        self._lock = asyncio.Lock()

        # Callback for new incoming channels (remote opened)
        self.on_channel: Callable[[ReliableChannel], Awaitable[None]] | None = None

    def open_channel(self) -> ReliableChannel:
        """Create and register a new outgoing channel."""
        ch_id = self._next_channel_id
        self._next_channel_id += self._channel_step

        ch = ReliableChannel(
            channel_id=ch_id,
            send_raw=self._send_raw,
            mtu=self._mtu,
            window_size=self._window_size,
        )
        self._channels[ch_id] = ch
        asyncio.create_task(ch.retransmit_loop())
        logger.debug("Opened local channel %d", ch_id)
        return ch

    def _get_or_create_remote_channel(self, ch_id: int) -> tuple["ReliableChannel", bool]:
        """Get or create a channel for incoming data from remote peer.

        Returns (channel, is_new).
        """
        if ch_id not in self._channels:
            ch = ReliableChannel(
                channel_id=ch_id,
                send_raw=self._send_raw,
                mtu=self._mtu,
                window_size=self._window_size,
            )
            self._channels[ch_id] = ch
            asyncio.create_task(ch.retransmit_loop())
            logger.debug("Created remote channel %d", ch_id)
            return ch, True

        return self._channels[ch_id], False

    async def handle_raw(self, data: bytes) -> None:
        """Demultiplex an incoming raw frame to the right channel."""
        try:
            frame = Frame.deserialize(data)
        except (ValueError, KeyError) as e:
            logger.warning("Failed to deserialize frame: %s", e)
            return

        ch, is_new = self._get_or_create_remote_channel(frame.channel_id)

        # Await on_channel before processing the first frame so that
        # ch.on_message is set before handle_frame delivers the payload.
        if is_new and self.on_channel:
            await self.on_channel(ch)

        await ch.handle_frame(frame)

    def get_channel(self, channel_id: int) -> ReliableChannel | None:
        return self._channels.get(channel_id)

    async def close_all(self) -> None:
        """Close all channels."""
        for ch in self._channels.values():
            await ch.close()
        self._channels.clear()
