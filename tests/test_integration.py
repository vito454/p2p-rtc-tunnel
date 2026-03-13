"""Integration tests — full pipeline simulation without network.

Tests the complete flow: HTTP request → serialize → encrypt → decrypt → deserialize.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.pipeline import CryptoPipeline
from proxy.http_server import serialize_request, serialize_response, deserialize_message


class TestHTTPSerialization(unittest.TestCase):
    """Test HTTP request/response serialization."""

    def test_request_roundtrip(self):
        raw = serialize_request(
            request_id="abc123",
            method="GET",
            url="http://example.com/page",  # noqa
            headers={"User-Agent": "TestBrowser", "Accept": "text/html"},
            body=b"",
        )
        msg = deserialize_message(raw)
        self.assertEqual(msg["id"], "abc123")
        self.assertEqual(msg["type"], "request")
        self.assertEqual(msg["method"], "GET")
        self.assertEqual(msg["url"], "http://example.com/page")  # noqa
        self.assertEqual(msg["headers"]["User-Agent"], "TestBrowser")
        self.assertEqual(msg["body"], b"")

    def test_request_with_body(self):
        body = b'{"key": "value"}'
        raw = serialize_request(
            request_id="def456",
            method="POST",
            url="http://api.example.com/data",  # noqa
            headers={"Content-Type": "application/json"},
            body=body,
        )
        msg = deserialize_message(raw)
        self.assertEqual(msg["method"], "POST")
        self.assertEqual(msg["body"], body)

    def test_response_roundtrip(self):
        body = b"<html><body>Hello</body></html>"
        raw = serialize_response(
            request_id="abc123",
            status=200,
            headers={"Content-Type": "text/html"},
            body=body,
        )
        msg = deserialize_message(raw)
        self.assertEqual(msg["type"], "response")
        self.assertEqual(msg["status"], 200)
        self.assertEqual(msg["body"], body)

    def test_binary_body(self):
        body = os.urandom(1024)
        raw = serialize_response(
            request_id="bin",
            status=200,
            headers={"Content-Type": "application/octet-stream"},
            body=body,
        )
        msg = deserialize_message(raw)
        self.assertEqual(msg["body"], body)


class TestEndToEndPipeline(unittest.TestCase):
    """Simulate full request flow through crypto pipeline."""

    def _make_pipeline(self, cipher_names, compressor_names):  # noqa
        return CryptoPipeline.from_config(
            secret="integration-test-secret",
            cipher_names=cipher_names,
            compressor_names=compressor_names,
        )

    def test_full_request_response_cycle(self):
        """Simulate: serialize request → encrypt → decrypt → deserialize."""
        pipeline = self._make_pipeline(
            ["aes-256-gcm", "chacha20-poly1305"],  # noqa
            ["zstd"],
        )

        # Client side: serialize and encrypt request
        raw_req = serialize_request(
            request_id="req-001",
            method="GET",
            url="http://example.com/api/data",  # noqa
            headers={"Authorization": "Bearer secret-token"},
            body=b"",
        )
        encrypted_req = pipeline.process(raw_req)

        # Verify it's encrypted (not readable)
        self.assertNotIn(b"secret-token", encrypted_req)
        self.assertNotIn(b"example.com", encrypted_req)

        # Server side: decrypt and deserialize request
        decrypted_req = pipeline.unprocess(encrypted_req)
        req_msg = deserialize_message(decrypted_req)
        self.assertEqual(req_msg["method"], "GET")
        self.assertEqual(req_msg["headers"]["Authorization"], "Bearer secret-token")

        # Server side: serialize and encrypt response
        raw_resp = serialize_response(
            request_id="req-001",
            status=200,
            headers={"Content-Type": "application/json"},
            body=b'{"result": "success", "data": [1,2,3]}',
        )
        encrypted_resp = pipeline.process(raw_resp)

        # Client side: decrypt and deserialize response
        decrypted_resp = pipeline.unprocess(encrypted_resp)
        resp_msg = deserialize_message(decrypted_resp)
        self.assertEqual(resp_msg["status"], 200)
        self.assertIn(b"success", resp_msg["body"])

    def test_large_response(self):
        """Test with a large response body (simulating file download)."""
        pipeline = self._make_pipeline(
            ["aes-256-gcm", "chacha20-poly1305", "camellia-256-gcm"],  # noqa
            ["zstd"],
        )

        # Simulate a 1MB file download
        body = os.urandom(1024 * 1024)
        raw = serialize_response(
            request_id="big",
            status=200,
            headers={"Content-Type": "application/octet-stream"},
            body=body,
        )

        encrypted = pipeline.process(raw)
        decrypted = pipeline.unprocess(encrypted)
        msg = deserialize_message(decrypted)
        self.assertEqual(msg["body"], body)

    def test_mismatched_pipelines_fail(self):
        """Two peers with different configs can't communicate."""
        p1 = self._make_pipeline(["aes-256-gcm"], ["zstd"])
        p2 = self._make_pipeline(["chacha20-poly1305"], ["zstd"])  # noqa

        raw = serialize_request("x", "GET", "http://x.com", {}, b"")  # noqa
        encrypted = p1.process(raw)

        with self.assertRaises(Exception):
            p2.unprocess(encrypted)


if __name__ == "__main__":
    unittest.main()
