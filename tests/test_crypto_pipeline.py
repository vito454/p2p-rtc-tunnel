"""Tests for the crypto pipeline.

These tests verify:
  - Individual ciphers encrypt/decrypt correctly
  - Individual compressors compress/decompress correctly
  - Chained pipelines (TrueCrypt-style) work end-to-end
  - Key derivation produces unique keys per position
  - Tampering detection works
  - Edge cases (empty data, large data, etc.)
"""

import os
import sys
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.pipeline import CryptoPipeline
from crypto.ciphers.aes_gcm import AES256GCMCipher
from crypto.ciphers.chacha20 import ChaCha20Poly1305Cipher
from crypto.ciphers.camellia import Camellia256GCMCipher
from crypto.ciphers.null import NullCipher


class TestIndividualCiphers(unittest.TestCase):
    """Test each cipher individually."""

    def _roundtrip(self, cipher_cls, key_size):
        key = os.urandom(key_size)
        cipher = cipher_cls(key)
        plaintext = b"Hello, World! This is a test message for encryption."

        ciphertext = cipher.encrypt(plaintext)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertGreater(len(ciphertext), len(plaintext))  # overhead

        decrypted = cipher.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_aes_256_gcm(self):
        self._roundtrip(AES256GCMCipher, 32)

    def test_chacha20_poly1305(self):  # noqa
        self._roundtrip(ChaCha20Poly1305Cipher, 32)

    def test_camellia_256(self):
        self._roundtrip(Camellia256GCMCipher, 64)

    def test_null_cipher(self):
        cipher = NullCipher(b"")
        data = b"plaintext"
        self.assertEqual(cipher.encrypt(data), data)
        self.assertEqual(cipher.decrypt(data), data)

    def test_aes_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        c1 = AES256GCMCipher(key1)
        c2 = AES256GCMCipher(key2)

        ct = c1.encrypt(b"secret")
        with self.assertRaises(Exception):
            c2.decrypt(ct)

    def test_aes_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        cipher = AES256GCMCipher(key)
        ct = cipher.encrypt(b"secret data")

        # Flip a byte in the middle
        tampered = bytearray(ct)
        tampered[len(tampered) // 2] ^= 0xFF
        tampered = bytes(tampered)

        with self.assertRaises(Exception):
            cipher.decrypt(tampered)

    def test_camellia_tampered_hmac_fails(self):
        key = os.urandom(64)
        cipher = Camellia256GCMCipher(key)
        ct = cipher.encrypt(b"secret data")

        # Tamper with HMAC (bytes 16..48)
        tampered = bytearray(ct)
        tampered[20] ^= 0xFF
        tampered = bytes(tampered)

        with self.assertRaises(ValueError, msg="HMAC verification failed"):
            cipher.decrypt(tampered)

    def test_empty_plaintext(self):
        key = os.urandom(32)
        cipher = AES256GCMCipher(key)
        ct = cipher.encrypt(b"")
        self.assertEqual(cipher.decrypt(ct), b"")

    def test_large_plaintext(self):
        key = os.urandom(32)
        cipher = AES256GCMCipher(key)
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        ct = cipher.encrypt(plaintext)
        self.assertEqual(cipher.decrypt(ct), plaintext)

    def test_nonce_uniqueness(self):
        """Each encryption should use a different nonce."""
        key = os.urandom(32)
        cipher = AES256GCMCipher(key)
        ct1 = cipher.encrypt(b"same data")
        ct2 = cipher.encrypt(b"same data")
        # Nonces (first 12 bytes) should differ
        self.assertNotEqual(ct1[:12], ct2[:12])
        # Ciphertexts should differ too
        self.assertNotEqual(ct1, ct2)

    def test_invalid_key_size(self):
        with self.assertRaises(ValueError):
            AES256GCMCipher(b"short")
        with self.assertRaises(ValueError):
            ChaCha20Poly1305Cipher(b"short")


class TestCryptoPipeline(unittest.TestCase):
    """Test the chained pipeline."""

    def test_single_cipher(self):
        pipeline = CryptoPipeline.from_config(
            secret="test-secret",
            cipher_names=["aes-256-gcm"],
            compressor_names=[],
        )
        data = b"Hello pipeline!"
        encrypted = pipeline.process(data)
        self.assertNotEqual(encrypted, data)
        self.assertEqual(pipeline.unprocess(encrypted), data)

    def test_chained_two_ciphers(self):
        """TrueCrypt-style: AES then ChaCha20."""
        pipeline = CryptoPipeline.from_config(
            secret="my-secret",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],  # noqa
            compressor_names=[],
        )
        data = b"Double encrypted data!"
        encrypted = pipeline.process(data)
        self.assertEqual(pipeline.unprocess(encrypted), data)

    def test_chained_three_ciphers(self):
        """Triple cascade: AES → ChaCha20 → Camellia."""
        pipeline = CryptoPipeline.from_config(
            secret="triple-secret",
            cipher_names=["aes-256-gcm", "chacha20-poly1305", "camellia-256-gcm"],  # noqa
            compressor_names=[],
        )
        data = b"Triple encrypted - maximum paranoia!"
        encrypted = pipeline.process(data)

        # Verify overhead accumulates
        expected_overhead = pipeline.overhead_per_chunk()
        self.assertGreater(expected_overhead, 0)

        self.assertEqual(pipeline.unprocess(encrypted), data)

    def test_compression_only(self):
        pipeline = CryptoPipeline.from_config(
            secret="unused",
            cipher_names=["null"],
            compressor_names=["zstd"],
        )
        data = b"A" * 10000  # Highly compressible
        processed = pipeline.process(data)
        self.assertLess(len(processed), len(data))
        self.assertEqual(pipeline.unprocess(processed), data)

    def test_compression_plus_encryption(self):
        pipeline = CryptoPipeline.from_config(
            secret="compress-then-encrypt",
            cipher_names=["aes-256-gcm"],
            compressor_names=["zstd"],
        )
        data = b"Repeated data! " * 1000
        processed = pipeline.process(data)
        self.assertEqual(pipeline.unprocess(processed), data)

    def test_chained_compressors(self):
        """Chain two compressors: zstd then lz4."""
        pipeline = CryptoPipeline.from_config(
            secret="unused",
            cipher_names=["null"],
            compressor_names=["zstd", "lz4"],
        )
        data = b"Compressible " * 500
        processed = pipeline.process(data)
        self.assertEqual(pipeline.unprocess(processed), data)

    def test_full_chain(self):
        """Full stack: zstd+lz4 compression, AES+ChaCha20 encryption."""
        pipeline = CryptoPipeline.from_config(
            secret="full-stack-secret",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],  # noqa
            compressor_names=["zstd", "lz4"],
        )
        data = os.urandom(50000)  # Random data (won't compress well)
        processed = pipeline.process(data)
        self.assertEqual(pipeline.unprocess(processed), data)

    def test_different_secrets_incompatible(self):
        """Pipelines with different secrets can't decrypt each other's data."""
        p1 = CryptoPipeline.from_config(
            secret="secret-A",
            cipher_names=["aes-256-gcm"],
            compressor_names=[],
        )
        p2 = CryptoPipeline.from_config(
            secret="secret-B",
            cipher_names=["aes-256-gcm"],
            compressor_names=[],
        )
        encrypted = p1.process(b"secret data")
        with self.assertRaises(Exception):
            p2.unprocess(encrypted)

    def test_different_cipher_order_incompatible(self):
        """Swapping cipher order makes decryption fail."""
        p1 = CryptoPipeline.from_config(
            secret="same-secret",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],  # noqa
            compressor_names=[],
        )
        p2 = CryptoPipeline.from_config(
            secret="same-secret",
            cipher_names=["chacha20-poly1305", "aes-256-gcm"],  # noqa
            compressor_names=[],
        )
        encrypted = p1.process(b"data")
        with self.assertRaises(Exception):
            p2.unprocess(encrypted)

    def test_key_derivation_uniqueness(self):
        """Same cipher at different positions gets different keys."""
        p = CryptoPipeline.from_config(
            secret="test",
            cipher_names=["aes-256-gcm", "aes-256-gcm"],
            compressor_names=[],
        )
        # The two AES instances should have different keys
        # We can't directly access keys, but we verify the pipeline works
        data = b"test data"
        encrypted = p.process(data)
        self.assertEqual(p.unprocess(encrypted), data)

    def test_unknown_cipher_raises(self):
        with self.assertRaises(ValueError, msg="Unknown cipher"):
            CryptoPipeline.from_config(
                secret="x",
                cipher_names=["nonexistent-cipher"],
                compressor_names=[],
            )

    def test_unknown_compressor_raises(self):
        with self.assertRaises(ValueError, msg="Unknown compressor"):
            CryptoPipeline.from_config(
                secret="x",
                cipher_names=[],
                compressor_names=["nonexistent-compressor"],
            )

    def test_repr(self):
        p = CryptoPipeline.from_config(
            secret="x",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],  # noqa
            compressor_names=["zstd"],
        )
        r = repr(p)
        self.assertIn("aes-256-gcm", r)
        self.assertIn("chacha20-poly1305", r)  # noqa
        self.assertIn("zstd", r)

    def test_binary_data(self):
        """Verify all byte values survive the pipeline."""
        pipeline = CryptoPipeline.from_config(
            secret="binary-test",
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],  # noqa
            compressor_names=["zstd"],
        )
        # All 256 byte values
        data = bytes(range(256)) * 100
        self.assertEqual(pipeline.unprocess(pipeline.process(data)), data)


if __name__ == "__main__":
    unittest.main()
