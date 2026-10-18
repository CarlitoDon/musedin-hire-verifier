#!/usr/bin/env python3
"""
Unit Test Suite for AER-1 (Agent Execution Receipt v1) Implementation
Tests all 9 validation rules of draft-zambo-aer1-21.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aer1 import create_receipt, verify_receipt


class TestAER1(unittest.TestCase):
    def setUp(self):
        self.sample = create_receipt(
            tool_name="ed25519_verifier",
            tool_version="1.0.0",
            tool_scope="attestation",
            result_payload={"verdict": "holds", "hire": 1953, "digest": "abc"},
            executor_name="rascoff-hermes/1.0",
        )

    def test_valid_receipt(self):
        ok, reason = verify_receipt(self.sample)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_rule1_invalid_uuid(self):
        bad = copy.deepcopy(self.sample)
        bad["id"] = "NOT-A-UUID"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 1", reason)

    def test_rule2_empty_schema_version(self):
        bad = copy.deepcopy(self.sample)
        bad["receipt_schema_version"] = ""
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 2", reason)

    def test_rule3_invalid_timestamp(self):
        bad = copy.deepcopy(self.sample)
        bad["created_at"] = "invalid-date"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 3", reason)

    def test_rule4_invalid_tool_object(self):
        bad = copy.deepcopy(self.sample)
        bad["tool"] = {"name": "", "version": "1.0", "scope": "public"}
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 4", reason)

    def test_rule5_invalid_provenance_class(self):
        bad = copy.deepcopy(self.sample)
        bad["provenance_class"] = "UNSUPPORTED CLASS"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 5", reason)

    def test_rule6_corrupted_canonical_bytes(self):
        bad = copy.deepcopy(self.sample)
        bad["canonical_bytes"] = "!!!not_base64!!!"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 6", reason)

    def test_rule7_tampered_output_hash(self):
        bad = copy.deepcopy(self.sample)
        bad["output_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 7", reason)

    def test_rule8_unverified_status(self):
        bad = copy.deepcopy(self.sample)
        bad["verification_status"] = "pending"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 8", reason)

    def test_rule9_label_binding_mismatch(self):
        bad = copy.deepcopy(self.sample)
        bad["provenance_class"] = "EXECUTED BY another-agent"
        ok, reason = verify_receipt(bad)
        self.assertFalse(ok)
        self.assertIn("Rule 9", reason)


if __name__ == "__main__":
    unittest.main()
