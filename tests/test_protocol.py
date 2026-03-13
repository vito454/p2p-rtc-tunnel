"""Tests for protocol framing, serialization, and reliability logic."""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from protocol.frames import Frame, FrameType, FrameFlags, HEADER_SIZE


class TestFrameSerialization(unittest.TestCase):
    """Test frame serialize/deserialize roundtrip."""

    def test_data_frame_roundtrip(self):
        frame = Frame(
            type=FrameType.DATA,
            flags=0,
            channel_id=42,
            seq=1000,
            ack=999,
            payload=b"Hello, tunnel!",
        )
        raw = frame.serialize()
        self.assertEqual(len(raw), HEADER_SIZE + len(frame.payload))

        restored = Frame.deserialize(raw)
        self.assertEqual(restored.type, FrameType.DATA)
        self.assertEqual(restored.channel_id, 42)
        self.assertEqual(restored.seq, 1000)
        self.assertEqual(restored.ack, 999)
        self.assertEqual(restored.payload, b"Hello, tunnel!")

    def test_ack_frame(self):
        frame = Frame(
            type=FrameType.ACK, flags=0,
            channel_id=1, seq=0, ack=500,
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.type, FrameType.ACK)
        self.assertEqual(restored.ack, 500)
        self.assertEqual(restored.payload, b"")

    def test_flags(self):
        frame = Frame(
            type=FrameType.DATA,
            flags=FrameFlags.MORE_FRAGMENTS | FrameFlags.PRIORITY,
            channel_id=1, seq=0, ack=0,
            payload=b"frag",
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertTrue(restored.has_more_fragments)
        self.assertTrue(restored.flags & FrameFlags.PRIORITY)

    def test_empty_payload(self):
        frame = Frame(
            type=FrameType.PING, flags=0,
            channel_id=0, seq=1, ack=0,
        )
        raw = frame.serialize()
        self.assertEqual(len(raw), HEADER_SIZE)
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.type, FrameType.PING)
        self.assertEqual(restored.payload, b"")

    def test_max_channel_id(self):
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=0xFFFF, seq=0, ack=0,
            payload=b"x",
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.channel_id, 0xFFFF)

    def test_max_seq(self):
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=1, seq=0xFFFFFFFF, ack=0xFFFFFFFF,
            payload=b"x",
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.seq, 0xFFFFFFFF)
        self.assertEqual(restored.ack, 0xFFFFFFFF)

    def test_large_payload(self):
        payload = os.urandom(1200)
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=1, seq=0, ack=0,
            payload=payload,
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.payload, payload)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            Frame.deserialize(b"\x00" * 5)

    def test_truncated_payload_raises(self):
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=1, seq=0, ack=0,
            payload=b"full payload here",
        )
        raw = frame.serialize()
        # Truncate the payload
        with self.assertRaises(ValueError):
            Frame.deserialize(raw[:HEADER_SIZE + 3])

    def test_all_frame_types(self):
        for ftype in FrameType:  # noqa
            frame = Frame(
                type=ftype, flags=0,
                channel_id=1, seq=0, ack=0,
            )
            raw = frame.serialize()
            restored = Frame.deserialize(raw)
            self.assertEqual(restored.type, ftype)

    def test_header_size_is_14(self):
        self.assertEqual(HEADER_SIZE, 14)

    def test_total_size(self):
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=1, seq=0, ack=0,
            payload=b"12345",
        )
        self.assertEqual(frame.total_size, HEADER_SIZE + 5)

    def test_binary_data_in_payload(self):
        payload = bytes(range(256))
        frame = Frame(
            type=FrameType.DATA, flags=0,
            channel_id=1, seq=0, ack=0,
            payload=payload,
        )
        raw = frame.serialize()
        restored = Frame.deserialize(raw)
        self.assertEqual(restored.payload, payload)


class TestReliableChannel(unittest.TestCase):
    """Test the reliability layer (without network)."""

    def test_fragmentation(self):
        """Test that large messages are split into MTU-sized chunks."""
        from protocol.reliable import ReliableChannel

        sent_frames: list[bytes] = []

        async def fake_send(data: bytes):  # noqa
            sent_frames.append(data)

        ch = ReliableChannel(
            channel_id=1,
            send_raw=fake_send,
            mtu=100,  # Small MTU for testing
        )

        # Fragment manually
        data = os.urandom(500)
        fragments = ch._fragment(data)

        # With MTU 100 and header 14, max payload = 86
        expected_count = (500 + 85) // 86  # ceil division
        self.assertEqual(len(fragments), expected_count)

        # Reassemble
        reassembled = b"".join(fragments)
        self.assertEqual(reassembled, data)

    def test_fragment_small_data(self):
        """Data smaller than MTU should not be fragmented."""
        from protocol.reliable import ReliableChannel

        async def fake_send(data: bytes):  # noqa
            pass

        ch = ReliableChannel(channel_id=1, send_raw=fake_send, mtu=1200)
        fragments = ch._fragment(b"small")
        self.assertEqual(len(fragments), 1)
        self.assertEqual(fragments[0], b"small")


class TestMultiplexer(unittest.TestCase):
    """Test channel multiplexing."""

    def test_open_channel_ids_no_collision(self):
        from protocol.multiplexer import Multiplexer

        async def _run():
            async def fake_send(data: bytes):
                pass

            # Offerer uses odd IDs
            mux_offerer = Multiplexer(send_raw=fake_send, is_offerer=True)
            ch1 = mux_offerer.open_channel()
            ch2 = mux_offerer.open_channel()
            self.assertEqual(ch1.channel_id % 2, 1)  # Odd
            self.assertEqual(ch2.channel_id % 2, 1)
            self.assertNotEqual(ch1.channel_id, ch2.channel_id)

            # Answerer uses even IDs
            mux_answerer = Multiplexer(send_raw=fake_send, is_offerer=False)
            ch3 = mux_answerer.open_channel()
            ch4 = mux_answerer.open_channel()
            self.assertEqual(ch3.channel_id % 2, 0)  # Even
            self.assertEqual(ch4.channel_id % 2, 0)
            self.assertNotEqual(ch3.channel_id, ch4.channel_id)

            # No collision between offerer and answerer IDs
            offerer_ids = {ch1.channel_id, ch2.channel_id}
            answerer_ids = {ch3.channel_id, ch4.channel_id}
            self.assertFalse(offerer_ids & answerer_ids)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
