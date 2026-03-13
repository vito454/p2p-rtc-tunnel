# Lazy registry — compressors are only imported when actually used.
# This avoids ImportError when optional libs (zstandard, brotli, lz4) aren't installed.

__all__ = [
    "ZstdCompressor",
    "BrotliCompressor",
    "LZ4Compressor",
    "NullCompressor",
    "COMPRESSOR_REGISTRY",
]

def _build_registry() -> dict[str, type]:
    """Build registry, including only compressors whose libs are available."""
    registry: dict[str, type] = {}
    try:
        from .zstd_comp import ZstdCompressor
        registry["zstd"] = ZstdCompressor
    except ImportError:
        pass
    try:
        from .brotli_comp import BrotliCompressor
        registry["brotli"] = BrotliCompressor
    except ImportError:
        pass
    try:
        from .lz4_comp import LZ4Compressor
        registry["lz4"] = LZ4Compressor
    except ImportError:
        pass
    from .null import NullCompressor
    registry["null"] = NullCompressor
    return registry

COMPRESSOR_REGISTRY: dict[str, type] = _build_registry()
