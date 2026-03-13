from .aes_gcm import AES256GCMCipher
from .chacha20 import ChaCha20Poly1305Cipher
from .camellia import Camellia256GCMCipher
from .null import NullCipher


# Registry: name → class
CIPHER_REGISTRY: dict[str, type] = {
    "aes-256-gcm": AES256GCMCipher,
    "chacha20-poly1305": ChaCha20Poly1305Cipher,
    "camellia-256-gcm": Camellia256GCMCipher,
    "null": NullCipher,
}

__all__ = [
    "AES256GCMCipher",
    "ChaCha20Poly1305Cipher",
    "Camellia256GCMCipher",
    "NullCipher",
    "CIPHER_REGISTRY",
]
