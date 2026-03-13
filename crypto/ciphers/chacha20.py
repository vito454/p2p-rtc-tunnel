"""ChaCha20-Poly1305 authenticated encryption cipher."""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..base import CipherBase


class ChaCha20Poly1305Cipher(CipherBase):
    """ChaCha20-Poly1305 with 96-bit nonce and 128-bit Poly1305 tag.

    Wire format:  nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)
    """

    name = "chacha20-poly1305"  # noqa

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size():
            raise ValueError(
                f"ChaCha20-Poly1305 requires {self.key_size()} byte key, got {len(key)}"
            )
        self._cipher = ChaCha20Poly1305(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.nonce_size())
        ct = self._cipher.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[: self.nonce_size()]
        ct = ciphertext[self.nonce_size() :]
        return self._cipher.decrypt(nonce, ct, associated_data=None)

    @classmethod
    def key_size(cls) -> int:
        return 32

    @classmethod
    def nonce_size(cls) -> int:
        return 12

    @classmethod
    def tag_size(cls) -> int:
        return 16
