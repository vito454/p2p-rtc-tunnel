"""Camellia-256-CBC with HMAC-SHA256 for authenticated encryption.

The `cryptography` library supports Camellia in CBC mode but not GCM.
We build Encrypt-then-MAC: CBC encrypt, then HMAC-SHA256 over (nonce ‖ ct).

Wire format:  iv (16 bytes) ‖ hmac (32 bytes) ‖ ciphertext (padded)
"""

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from ..base import CipherBase


class Camellia256GCMCipher(CipherBase):
    """Camellia-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).

    Despite the class name containing 'GCM' for registry consistency,
    this is actually CBC + HMAC since the cryptography lib lacks
    Camellia-GCM support.  The security properties (authenticated
    encryption) are equivalent.
    """

    name = "camellia-256-gcm"

    _IV_SIZE = 16
    _HMAC_SIZE = 32

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size():
            raise ValueError(
                f"Camellia-256 requires {self.key_size()} byte key, got {len(key)}"
            )
        # Split 64-byte key: first 32 for Camellia, last 32 for HMAC
        self._enc_key = key[:32]
        self._mac_key = key[32:]

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(self._IV_SIZE)

        # Pad plaintext (PKCS7, block size 128 bits = 16 bytes)
        padder = PKCS7(128).padder()  # noqa
        padded = padder.update(plaintext) + padder.finalize()

        # CBC encrypt
        cipher = Cipher(algorithms.Camellia(self._enc_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()

        # HMAC over iv + ct
        mac = hmac.new(self._mac_key, iv + ct, hashlib.sha256).digest()

        return iv + mac + ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[: self._IV_SIZE]
        mac_received = ciphertext[self._IV_SIZE : self._IV_SIZE + self._HMAC_SIZE]
        ct = ciphertext[self._IV_SIZE + self._HMAC_SIZE :]

        # Verify HMAC first (constant-time)
        mac_computed = hmac.new(self._mac_key, iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_received, mac_computed):
            raise ValueError("Camellia HMAC verification failed — data corrupted or tampered")

        # CBC decrypt
        cipher = Cipher(algorithms.Camellia(self._enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()

        # Un-pad
        unpadder = PKCS7(128).unpadder()  # noqa
        return unpadder.update(padded) + unpadder.finalize()

    @classmethod
    def key_size(cls) -> int:
        # 32 bytes Camellia + 32 bytes HMAC
        return 64

    @classmethod
    def nonce_size(cls) -> int:
        return 16  # IV

    @classmethod
    def tag_size(cls) -> int:
        return 32  # HMAC-SHA256
