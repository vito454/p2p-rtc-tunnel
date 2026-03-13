"""Abstract base classes for pluggable ciphers and compressors.

Every cipher and compressor must implement these interfaces.  The pipeline
chains them in order, so each implementation only needs to handle a single
layer — composition is handled externally.

Cipher contract:
  - encrypt(plaintext) → ciphertext  (includes nonce + tag, self-contained)
  - decrypt(ciphertext) → plaintext
  - Each call to encrypt must produce a message that decrypt can reverse
    with no external state (nonce is embedded in the ciphertext blob).

Compressor contract:
  - compress(data) → compressed
  - decompress(compressed) → data
"""

from abc import ABC, abstractmethod


class CipherBase(ABC):
    """Base class for symmetric ciphers."""

    # Human-readable name, used in config
    name: str = "base"

    @abstractmethod
    def __init__(self, key: bytes) -> None:  # noqa
        """Initialize with a raw key (appropriate length for the cipher)."""
        ...

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext, returning nonce‖ciphertext‖tag."""
        ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt nonce‖ciphertext‖tag blob, returning plaintext."""
        ...

    @classmethod
    @abstractmethod
    def key_size(cls) -> int:
        """Required key size in bytes."""
        ...

    @classmethod
    @abstractmethod
    def nonce_size(cls) -> int:
        """Nonce size in bytes (for documentation / overhead calculation)."""
        ...

    @classmethod
    @abstractmethod
    def tag_size(cls) -> int:
        """Authentication tag size in bytes."""
        ...

    @classmethod
    def overhead(cls) -> int:
        """Total overhead added per encrypt call (nonce + tag)."""
        return cls.nonce_size() + cls.tag_size()


class CompressorBase(ABC):
    """Base class for compressors."""

    name: str = "base"

    @abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Compress data."""
        ...

    @abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Decompress data."""
        ...
