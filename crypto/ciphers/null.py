"""No-op cipher — passes data through unchanged. For testing only (be CAREFUL)"""

from ..base import CipherBase


class NullCipher(CipherBase):
    name = "null"

    def __init__(self, key: bytes) -> None:
        pass  # Key ignored

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext

    @classmethod
    def key_size(cls) -> int:
        return 0

    @classmethod
    def nonce_size(cls) -> int:
        return 0

    @classmethod
    def tag_size(cls) -> int:
        return 0
