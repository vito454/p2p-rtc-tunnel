"""No-op compressor — passes data through unchanged."""

from ..base import CompressorBase


class NullCompressor(CompressorBase):
    name = "null"

    def compress(self, data: bytes) -> bytes:
        return data

    def decompress(self, data: bytes) -> bytes:
        return data
