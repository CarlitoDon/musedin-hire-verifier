#!/usr/bin/env python3
"""
Unit test suite for MusedIn Hire Record Verifier
"""

import unittest
import base64
import json
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519

from check_hire_record import b64url_decode, verify_ed25519, check_hire

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

class TestHireRecordVerifier(unittest.TestCase):
    def setUp(self):
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_bytes = self.pub_key.public_bytes_raw()
        self.pub_b64 = b64url_encode(self.pub_bytes)

    def test_b64url_decode_padding(self):
        sample = b"hello world musedin test padding"
        encoded = b64url_encode(sample)
        # remove padding if any
        self.assertNotIn("=", encoded)
        decoded = b64url_decode(encoded)
        self.assertEqual(decoded, sample)

    def test_verify_ed25519_valid(self):
        message = b"musedin-test-attestation-payload-123"
        sig = self.priv_key.sign(message)
        sig_b64 = b64url_encode(sig)

        result = verify_ed25519(self.pub_b64, message, sig_b64)
        self.assertTrue(result)

    def test_verify_ed25519_invalid_signature(self):
        message = b"musedin-test-attestation-payload-123"
        tampered_message = b"musedin-test-attestation-payload-456"
        sig = self.priv_key.sign(message)
        sig_b64 = b64url_encode(sig)

        result = verify_ed25519(self.pub_b64, tampered_message, sig_b64)
        self.assertFalse(result)

    def test_verify_ed25519_wrong_key(self):
        other_priv = ed25519.Ed25519PrivateKey.generate()
        other_pub_b64 = b64url_encode(other_priv.public_key().public_bytes_raw())
        message = b"musedin-payload"
        sig = self.priv_key.sign(message)
        sig_b64 = b64url_encode(sig)

        result = verify_ed25519(other_pub_b64, message, sig_b64)
        self.assertFalse(result)

    @patch("check_hire_record.fetch_json")
    def test_check_hire_mock_valid(self, mock_fetch):
        # Prepare mock issuer data
        issuer_data = {
            "issuer": "musedin.com",
            "public_key": self.pub_b64
        }
        
        # Prepare mock payload signed by issuer
        internal_payload = {
            "hire_id": 9999,
            "role": "instant-task",
            "key_history": {},
            "evidence": []
        }
        payload_str = json.dumps(internal_payload)
        sig_b64 = b64url_encode(self.priv_key.sign(payload_str.encode("utf-8")))

        record_data = {
            "ok": True,
            "attestation": {
                "payload": payload_str,
                "signature": sig_b64
            },
            "rechecks": []
        }

        mock_fetch.side_effect = [issuer_data, record_data]

        # Execute check_hire and verify it runs without error
        try:
            check_hire("9999")
        except SystemExit as e:
            self.fail(f"check_hire exited unexpectedly with {e}")

if __name__ == "__main__":
    unittest.main()
