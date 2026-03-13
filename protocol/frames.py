"""Wire protocol frame definitions.

These frames are the payload inside RTP packets (which are then wrapped
in SRTP by the WebRTC transport).

Frame format (binary, big-endian):

  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┐
  │ type (1) │ flags(1) │ chan (2) │ seq (4)  │ ack (4)  │ len (2)      │
  ├──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┤
  │ payload (0 ... len bytes)                                           │
  └─────────────────────────────────────────────────────────────────────┘

  Total header: 14 bytes

Frame types:
  DATA    = 0x01  — carries payload data
  ACK     = 0x02  — acknowledges received seq
  SYN     = 0x03  — open channel
  FIN     = 0x04  — close channel
  RST     = 0x05  — reset channel
  PING    = 0x06  — keepalive
  PONG    = 0x07  — keepalive response

Flags:
  MORE_FRAGMENTS = 0x01  — more fragments follow for this message
  COMPRESSED     = 0x02  — payload is compressed (handled by pipeline)
  ENCRYPTED      = 0x04  — payload is encrypted (handled by pipeline)
  PRIORITY       = 0x08  — high priority frame
"""

import struct
from enum import IntEnum
from dataclasses import dataclass

HEADER_FORMAT = ">BBHIIH"  # noqa
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 14 bytes

assert HEADER_SIZE == 14


class FrameType(IntEnum):
    DATA = 0x01
    ACK = 0x02
    SYN = 0x03
    FIN = 0x04
    RST = 0x05
    PING = 0x06
    PONG = 0x07


class FrameFlags:
    MORE_FRAGMENTS = 0x01
    COMPRESSED = 0x02
    ENCRYPTED = 0x04
    PRIORITY = 0x08


@dataclass(slots=True)
class Frame:
    """A single protocol frame."""

    type: FrameType
    flags: int
    channel_id: int
    seq: int
    ack: int
    payload: bytes = b""

    def serialize(self) -> bytes:
        """Serialize to bytes for transmission."""
        header = struct.pack(
            HEADER_FORMAT,
            self.type,
            self.flags,
            self.channel_id,
            self.seq,
            self.ack,
            len(self.payload),
        )
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> "Frame":
        """Deserialize from raw bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Frame too short: {len(data)} < {HEADER_SIZE}")

        ftype, flags, chan, seq, ack, length = struct.unpack(  # noqa
            HEADER_FORMAT, data[:HEADER_SIZE]
        )

        payload = data[HEADER_SIZE : HEADER_SIZE + length]
        if len(payload) != length:
            raise ValueError(
                f"Payload truncated: expected {length}, got {len(payload)}"
            )

        return cls(
            type=FrameType(ftype),
            flags=flags,
            channel_id=chan,
            seq=seq,
            ack=ack,
            payload=payload,
        )

    @property
    def total_size(self) -> int:
        return HEADER_SIZE + len(self.payload)

    @property
    def is_data(self) -> bool:
        return self.type == FrameType.DATA

    @property
    def has_more_fragments(self) -> bool:
        return bool(self.flags & FrameFlags.MORE_FRAGMENTS)

    def __repr__(self) -> str:
        return (
            f"Frame({self.type.name}, ch={self.channel_id}, "
            f"seq={self.seq}, ack={self.ack}, "
            f"payload={len(self.payload)}B)"
        )
