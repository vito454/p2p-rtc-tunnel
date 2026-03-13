"""LZ4 compressor — fastest, moderate ratio."""

import lz4.frame as _lz4
from ..base import CompressorBase


class LZ4Compressor(CompressorBase):
    name = "lz4"

    def compress(self, data: bytes) -> bytes:
        return _lz4.compress(data)  # noqa

    def decompress(self, data: bytes) -> bytes:
        return _lz4.decompress(data)  # noqa
