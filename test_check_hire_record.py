#!/usr/bin/env python3
"""
Unit test suite for MusedIn Hire Record Verifier
"""

import unittest
import base64
import json
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519

from check_hire_record import (
    b64url_decode,
    verify_ed25519,
    check_hire,
    check_record,
    is_future_close,
    parse_target,
    SUSPICIOUS_FUTURE_CLOSE,
)

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



CLOSE_READ_AT = 1792300663022          # a signed read_at (2026-10-18)
BUG_CLOSED_AT = 1793453981305          # +13.35 days: the observed job-f78 offset


def make_close_record(priv_key, *, status="filled", closed_at=BUG_CLOSED_AT,
                      read_at=CLOSE_READ_AT, kind="close", ident="job-f78",
                      record_kind="close"):
    """Build a signed close-record answer shaped like GET /api/record/close/<slug>."""
    record = {
        "kind": record_kind,
        "id": ident,
        "role": ident,
        "title": "Run check_hire_record.py across 5 MusedIn hire records",
        "poster": "agent_h5a9773q0o",
        "status": status,
        "closed_at": closed_at,
    }
    internal_payload = {
        "v": 1,
        "issuer": "musedin.com",
        "kind": kind,
        "id": ident,
        "read_at": read_at,
        "record": record,
        "evidence": [],
        "evidence_count": 0,
        "evidence_note": "closed when its days ran out: no one signed a close",
        "key_history": {},
    }
    payload_str = json.dumps(internal_payload, sort_keys=True, separators=(",", ":"))
    sig_b64 = b64url_encode(priv_key.sign(payload_str.encode("utf-8")))
    return {
        "ok": True,
        "record": record,
        "evidence": [],
        "evidence_note": internal_payload["evidence_note"],
        "key_history": {},
        "attestation": {"payload": payload_str, "signature": sig_b64},
    }


class TestFutureCloseDetection(unittest.TestCase):
    """is_future_close: the pure policy for the future-timestamp bug."""

    def test_bug_shape_is_flagged(self):
        record = {"kind": "close", "status": "filled", "closed_at": BUG_CLOSED_AT}
        suspicious, reason = is_future_close(record, CLOSE_READ_AT)
        self.assertTrue(suspicious)
        self.assertIn("filled", reason)

    def test_healthy_closed_record_not_flagged(self):
        record = {"kind": "close", "status": "closed", "closed_at": CLOSE_READ_AT - 1}
        suspicious, _ = is_future_close(record, CLOSE_READ_AT)
        self.assertFalse(suspicious)

    def test_future_closed_timestamp_alone_is_not_flagged(self):
        # Status is healthy, so a future closed_at is not this defect.
        record = {"kind": "close", "status": "closed", "closed_at": BUG_CLOSED_AT}
        suspicious, _ = is_future_close(record, CLOSE_READ_AT)
        self.assertFalse(suspicious)

    def test_past_timestamp_not_flagged(self):
        record = {"kind": "close", "status": "filled", "closed_at": CLOSE_READ_AT - 1000}
        suspicious, _ = is_future_close(record, CLOSE_READ_AT)
        self.assertFalse(suspicious)

    def test_clock_tolerance_at_boundary(self):
        record = {"kind": "close", "status": "filled", "closed_at": CLOSE_READ_AT + 60_000}
        self.assertFalse(is_future_close(record, CLOSE_READ_AT)[0])
        record["closed_at"] = CLOSE_READ_AT + 60_001
        self.assertTrue(is_future_close(record, CLOSE_READ_AT)[0])

    def test_non_close_kind_not_flagged(self):
        record = {"kind": "hire", "status": "hired", "closed_at": BUG_CLOSED_AT}
        suspicious, _ = is_future_close(record, CLOSE_READ_AT)
        self.assertFalse(suspicious)

    def test_falls_back_to_now_when_read_at_missing(self):
        record = {"kind": "close", "status": "filled", "closed_at": BUG_CLOSED_AT}
        self.assertTrue(is_future_close(record, None, now_ms=CLOSE_READ_AT)[0])
        self.assertFalse(is_future_close(record, None, now_ms=None)[0])

    def test_malformed_timestamps_not_flagged(self):
        for closed_at in (None, "1793453981305", True):
            record = {"kind": "close", "status": "filled", "closed_at": closed_at}
            self.assertFalse(is_future_close(record, CLOSE_READ_AT)[0])


class TestParseTarget(unittest.TestCase):
    """CLI parsing: bare job slugs imply a close record."""

    def test_default_is_hire_1401(self):
        self.assertEqual(parse_target([]), ("hire", "1401"))

    def test_explicit_kind(self):
        self.assertEqual(parse_target(["close:job-f78"]), ("close", "job-f78"))
        self.assertEqual(parse_target(["hire:1401"]), ("hire", "1401"))

    def test_bare_slug_implies_close(self):
        self.assertEqual(parse_target(["job-f78"]), ("close", "job-f78"))

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            parse_target(["bogus:1"])

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            parse_target(["close:"])


class TestCloseRecordCheck(unittest.TestCase):
    """check_record end-to-end against signed fixtures (no network)."""

    def setUp(self):
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_b64 = b64url_encode(self.priv_key.public_key().public_bytes_raw())
        self.issuer_data = {"issuer": "musedin.com", "public_key": self.pub_b64}

    def _run(self, record_obj):
        with patch("check_hire_record.fetch_json") as mock_fetch:
            mock_fetch.side_effect = [self.issuer_data, record_obj]
            return check_record("close", "job-f78")

    def test_future_close_record_is_flagged(self):
        exit_code = self._run(make_close_record(self.priv_key))
        self.assertEqual(exit_code, 1)

    def test_healthy_close_record_passes(self):
        record_obj = make_close_record(self.priv_key, status="closed")
        self.assertEqual(self._run(record_obj), 0)

    def test_tampered_close_record_fails_envelope(self):
        record_obj = make_close_record(self.priv_key)
        record_obj["attestation"]["payload"] = record_obj["attestation"]["payload"].replace(
            '"filled"', '"closed"')
        self.assertEqual(self._run(record_obj), 1)

    def test_id_substitution_fails_binding(self):
        # Valid signature, but this envelope names another record.
        record_obj = make_close_record(self.priv_key, ident="job-f999")
        self.assertEqual(self._run(record_obj), 1)

    def test_kind_substitution_fails_binding(self):
        record_obj = make_close_record(self.priv_key, kind="hire", record_kind="hire")
        self.assertEqual(self._run(record_obj), 1)

    def test_missing_attestation_fails(self):
        with patch("check_hire_record.fetch_json") as mock_fetch:
            mock_fetch.side_effect = [
                self.issuer_data,
                {"ok": True, "attestation": None, "attestation_note": "no issuer key"},
            ]
            self.assertEqual(check_record("close", "job-f78"), 1)

    def test_suspicious_constant_is_stable(self):
        # The verdict label is part of the harness contract.
        self.assertEqual(SUSPICIOUS_FUTURE_CLOSE, "SUSPICIOUS_FUTURE_CLOSE")


if __name__ == "__main__":
    unittest.main()
