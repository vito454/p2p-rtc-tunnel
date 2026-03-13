# Lazy imports to avoid pulling in optional dependencies at import time.
# Use: from crypto.pipeline import CryptoPipeline
# Or:  from crypto.base import CipherBase

__all__ = ["CryptoPipeline", "CipherBase", "CompressorBase"]

def __getattr__(name):
    if name == "CryptoPipeline":
        from .pipeline import CryptoPipeline
        return CryptoPipeline
    if name == "CipherBase":
        from .base import CipherBase
        return CipherBase
    if name == "CompressorBase":
        from .base import CompressorBase
        return CompressorBase
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
