"""AES-256-GCM authenticated encryption cipher."""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..base import CipherBase


class AES256GCMCipher(CipherBase):
    """AES-256-GCM with 96-bit nonce and 128-bit tag.

    Wire format:  nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)
    The tag is appended by AESGCM automatically.
    """

    name = "aes-256-gcm"

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size():
            raise ValueError(f"AES-256-GCM requires {self.key_size()} byte key, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.nonce_size())
        ct = self._aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ct  # ct already includes tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[: self.nonce_size()]
        ct = ciphertext[self.nonce_size() :]
        return self._aesgcm.decrypt(nonce, ct, associated_data=None)

    @classmethod
    def key_size(cls) -> int:
        return 32

    @classmethod
    def nonce_size(cls) -> int:
        return 12

    @classmethod
    def tag_size(cls) -> int:
        return 16
