"""Chained crypto + compression pipeline.

Inspired by TrueCrypt/VeraCrypt cascaded encryption: data passes through
multiple independent ciphers in sequence, each with its own key derived
from the shared secret via HKDF with a unique label.

Encryption order:  compress_1 → compress_2 → ... → cipher_1 → cipher_2 → ...
Decryption order:  ... → cipher_2⁻¹ → cipher_1⁻¹ → ... → decompress_2⁻¹ → decompress_1⁻¹

This means:
  - Compression is applied first (works on plaintext: best ratio)
  - Encryption layers wrap one inside another
  - To decrypt, you peel off the outermost cipher first

Key derivation:
  Each cipher in the chain gets its own key via:
    HKDF-SHA256(secret, salt=b"p2p-tunnel", info=b"cipher:<name>:<index>")
  This ensures that even if two ciphers are the same algorithm, they get
  different keys when at different positions in the chain.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .base import CipherBase, CompressorBase
from .ciphers import CIPHER_REGISTRY
from .compressors import COMPRESSOR_REGISTRY


class CryptoPipeline:
    """Chained compression + encryption pipeline.

    Usage:
        pipeline = CryptoPipeline.from_config(
            secret=b"shared-secret",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],
            compressor_names=["zstd"],
        )
        encrypted = pipeline.process(plaintext)
        plaintext = pipeline.unprocess(encrypted)
    """

    def __init__(
        self,
        ciphers: list[CipherBase],
        compressors: list[CompressorBase],
    ) -> None:
        self._ciphers = ciphers
        self._compressors = compressors

    @classmethod
    def from_config(
        cls,
        secret: str | bytes,
        cipher_names: list[str],
        compressor_names: list[str],
    ) -> "CryptoPipeline":
        """Build pipeline from config names, deriving keys from shared secret."""
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        # Instantiate compressors (no key needed)
        compressors: list[CompressorBase] = []
        for name in compressor_names:
            if name not in COMPRESSOR_REGISTRY:
                raise ValueError(
                    f"Unknown compressor '{name}'. "
                    f"Available: {list(COMPRESSOR_REGISTRY.keys())}"
                )
            compressors.append(COMPRESSOR_REGISTRY[name]())

        # Instantiate ciphers with derived keys
        ciphers: list[CipherBase] = []
        for idx, name in enumerate(cipher_names):
            if name not in CIPHER_REGISTRY:
                raise ValueError(
                    f"Unknown cipher '{name}'. "
                    f"Available: {list(CIPHER_REGISTRY.keys())}"
                )
            cipher_cls = CIPHER_REGISTRY[name]
            key = cls._derive_key(secret, name, idx, cipher_cls.key_size())  # noqa
            ciphers.append(cipher_cls(key))

        return cls(ciphers=ciphers, compressors=compressors)

    @staticmethod
    def _derive_key(secret: bytes, cipher_name: str, index: int, length: int) -> bytes:
        """Derive a unique key for each cipher in the chain using HKDF."""
        if length == 0:
            return b""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=b"p2p-tunnel-v1",
            info=f"cipher:{cipher_name}:{index}".encode(),
        )
        return hkdf.derive(secret)

    def process(self, data: bytes) -> bytes:
        """Compress then encrypt (forward direction)."""
        # 1. Apply compression chain in order
        for comp in self._compressors:
            data = comp.compress(data)

        # 2. Apply cipher chain in order (innermost first)
        for cipher in self._ciphers:
            data = cipher.encrypt(data)

        return data

    def unprocess(self, data: bytes) -> bytes:
        """Decrypt then decompress (reverse direction)."""
        # 1. Remove cipher layers in reverse order (outermost first)
        for cipher in reversed(self._ciphers):
            data = cipher.decrypt(data)

        # 2. Remove compression layers in reverse order
        for comp in reversed(self._compressors):
            data = comp.decompress(data)

        return data

    def overhead_per_chunk(self) -> int:
        """Total byte overhead added per chunk by all ciphers."""
        return sum(c.overhead() for c in self._ciphers)

    @property
    def cipher_names(self) -> list[str]:
        return [c.name for c in self._ciphers]

    @property
    def compressor_names(self) -> list[str]:
        return [c.name for c in self._compressors]

    def __repr__(self) -> str:
        comp = " → ".join(self.compressor_names) or "none"
        ciph = " → ".join(self.cipher_names) or "none"
        return f"CryptoPipeline(compress=[{comp}], encrypt=[{ciph}])"
