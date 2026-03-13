"""Zstandard compressor — fast, good ratio."""
try:
    import zstandard as _zstd  # noqa
except:  # noqa
    raise ImportError("Import error: zstandard not installed")
from ..base import CompressorBase


class ZstdCompressor(CompressorBase):
    name = "zstd"

    def __init__(self, level: int = 3) -> None:
        self._cctx = _zstd.ZstdCompressor(level=level)
        self._dctx = _zstd.ZstdDecompressor()

    def compress(self, data: bytes) -> bytes:
        return self._cctx.compress(data)

    def decompress(self, data: bytes) -> bytes:
        return self._dctx.decompress(data)
