#!/usr/bin/env python3
"""
AER-1 (Agent Execution Receipt v1) Implementation & Verifier
Conformant with IETF Internet-Draft draft-zambo-aer1-21 (October 2026).
Author: Rascoff (@CarlitoDon)
"""

import base64
import hashlib
import json
import re
import uuid
from datetime import datetime

AER1_SCHEMA_VERSION = "0.3"
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RFC3339_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def canonical_json(obj) -> str:
    """Encode an object to canonical JSON (sorted keys, compact delimiters, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def create_receipt(tool_name: str, tool_version: str, tool_scope: str,
                   result_payload: dict, executor_name: str = "rascoff-hermes/1.0") -> dict:
    """Create a valid AER-1 receipt committing to an execution result."""
    now_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt_id = str(uuid.uuid4()).lower()
    provenance_class = f"EXECUTED BY {executor_name}"

    # Payload with bound metadata (Rule 9)
    committed_payload = {
        "receipt_id": receipt_id,
        "receipt_schema_version": AER1_SCHEMA_VERSION,
        "created_at": now_utc,
        "tool": {
            "name": tool_name,
            "version": tool_version,
            "scope": tool_scope
        },
        "issuer_claims": {
            "provenance_class": provenance_class,
            "executor": executor_name
        },
        "result": result_payload
    }

    raw_bytes = canonical_json(committed_payload).encode("utf-8")
    canonical_b64 = base64.b64encode(raw_bytes).decode("ascii")
    output_hash = f"sha256:{hashlib.sha256(raw_bytes).hexdigest().lower()}"

    receipt = {
        "id": receipt_id,
        "receipt_schema_version": AER1_SCHEMA_VERSION,
        "created_at": now_utc,
        "tool": {
            "name": tool_name,
            "version": tool_version,
            "scope": tool_scope
        },
        "provenance_class": provenance_class,
        "canonical_bytes": canonical_b64,
        "output_hash": output_hash,
        "verification_status": "verified"
    }

    return receipt


def verify_receipt(receipt: dict) -> tuple[bool, str]:
    """
    Verify an AER-1 receipt against the 9 rules of draft-zambo-aer1-21.
    Returns (True, "OK") or (False, error_reason).
    """
    if not isinstance(receipt, dict):
        return False, "Receipt must be a JSON object"

    # Rule 1: id is lowercase UUID
    receipt_id = receipt.get("id")
    if not isinstance(receipt_id, str) or not UUID_REGEX.match(receipt_id):
        return False, f"Rule 1 failed: invalid or non-lowercase UUID id '{receipt_id}'"

    # Rule 2: receipt_schema_version is non-empty string
    schema_ver = receipt.get("receipt_schema_version")
    if not isinstance(schema_ver, str) or not schema_ver.strip():
        return False, "Rule 2 failed: receipt_schema_version must be a non-empty string"

    # Rule 3: created_at is valid RFC 3339 timestamp
    created_at = receipt.get("created_at")
    if not isinstance(created_at, str) or not RFC3339_REGEX.match(created_at):
        return False, f"Rule 3 failed: created_at '{created_at}' is not a valid RFC 3339 timestamp"

    # Rule 4: tool is object with non-empty string name, version, scope
    tool = receipt.get("tool")
    if not isinstance(tool, dict):
        return False, "Rule 4 failed: tool must be an object"
    for field in ["name", "version", "scope"]:
        val = tool.get(field)
        if not isinstance(val, str) or not val.strip():
            return False, f"Rule 4 failed: tool.{field} must be a non-empty string"

    # Rule 5: provenance_class validation
    prov_class = receipt.get("provenance_class")
    if not isinstance(prov_class, str):
        return False, "Rule 5 failed: provenance_class must be a string"
    valid_prefix = prov_class.startswith("EXECUTED BY ") and len(prov_class) > 12
    valid_exact = prov_class in ["OBSERVED VIA GATEWAY", "LOGGED BY AGENT"]
    if not (valid_prefix or valid_exact):
        return False, f"Rule 5 failed: invalid provenance_class '{prov_class}'"

    # Rule 6: canonical_bytes is strict base64 decoding to strict UTF-8
    canonical_b64 = receipt.get("canonical_bytes")
    if not isinstance(canonical_b64, str):
        return False, "Rule 6 failed: canonical_bytes must be a string"
    try:
        raw_bytes = base64.b64decode(canonical_b64, validate=True)
        utf8_text = raw_bytes.decode("utf-8")
    except Exception as e:
        return False, f"Rule 6 failed: canonical_bytes failed base64/UTF-8 decoding: {e}"

    # Rule 7: output_hash equals sha256:<lowercase_hex>
    output_hash = receipt.get("output_hash")
    if not isinstance(output_hash, str) or not output_hash.startswith("sha256:"):
        return False, "Rule 7 failed: output_hash must start with 'sha256:'"
    expected_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest().lower()
    if output_hash.lower() != expected_hash:
        return False, f"Rule 7 failed: output_hash mismatch (got {output_hash}, expected {expected_hash})"

    # Rule 8: verification_status is exactly 'verified'
    if receipt.get("verification_status") != "verified":
        return False, f"Rule 8 failed: verification_status must be 'verified', got '{receipt.get('verification_status')}'"

    # Rule 9: Metadata labels bound to committed payload
    try:
        payload = json.loads(utf8_text)
    except Exception as e:
        return False, f"Rule 9 failed: payload is not valid JSON: {e}"

    if not isinstance(payload, dict):
        return False, "Rule 9 failed: committed payload must be a JSON object"

    committed_claims = payload.get("issuer_claims", {})
    if committed_claims.get("provenance_class") != prov_class:
        return False, "Rule 9 failed: provenance_class label does not match committed payload"

    if payload.get("receipt_schema_version") != schema_ver:
        return False, "Rule 9 failed: receipt_schema_version does not match committed payload"

    return True, "OK"


if __name__ == "__main__":
    # Self-test
    sample = create_receipt("ed25519_verifier", "1.0.0", "attestation", {"verdict": "holds", "hire": 1953})
    ok, reason = verify_receipt(sample)
    print(f"Sample receipt verification: {ok} ({reason})")
    print(json.dumps(sample, indent=2))
