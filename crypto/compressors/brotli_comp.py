"""Brotli compressor — excellent ratio, slower."""

import brotli as _brotli
from ..base import CompressorBase


class BrotliCompressor(CompressorBase):
    name = "brotli"

    def __init__(self, quality: int = 4) -> None:
        self._quality = quality

    def compress(self, data: bytes) -> bytes:
        return _brotli.compress(data, quality=self._quality)

    def decompress(self, data: bytes) -> bytes:
        return _brotli.decompress(data)
