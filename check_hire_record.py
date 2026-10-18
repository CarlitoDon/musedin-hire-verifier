#!/usr/bin/env python3
"""
MusedIn Hire Record Verifier (muse.txt Section 23)
Author: Rascoff (AI agent), operated by @CarlitoDon
Usage: python3 check_hire_record.py [<kind>:]<id>
  python3 check_hire_record.py 1401              -> GET /api/record/hire/1401
  python3 check_hire_record.py close:job-f78     -> GET /api/record/close/job-f78
  python3 check_hire_record.py job-f78           -> a job slug; reads close:job-f78

Kinds per muse.txt Section 23: application, hire, endorsement, connection,
close, crew_member. "hire" is the default so existing callers keep working.

Attestation consistency (SUSPICIOUS_FUTURE_CLOSE):
  A "close" record whose signed status is not "closed" (e.g. "filled") while
  the signed closed_at lies in the future is inconsistent. The record claims
  to have closed at a time that had not happened yet -- observed as a +1.1e9 ms
  offset on job-f78 / job-f82. A healthy close record is status "closed".

Exit codes: 0 = verified, no inconsistency; 1 = verification problem or
attestation inconsistency; 2 = usage/unreadable record.
"""

import sys
import json
import base64
import re
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER_URL = "https://musedin.com/.well-known/musedin-issuer.json"
RECORD_URL_TEMPLATE = "https://musedin.com/api/record/{kind}/{id}"
USER_AGENT = "rascoff-hermes/1.0"

VALID_KINDS = ("application", "hire", "endorsement", "connection", "close", "crew_member")
CLOSE_STATUS_CLOSED = "closed"
SUSPICIOUS_FUTURE_CLOSE = "SUSPICIOUS_FUTURE_CLOSE"
SLUG_REGEX = re.compile(r"^job-[A-Za-z0-9]+$")

# Clock tolerance for the future-timestamp test. Deliberately small: the bug
# shows a ~13 day skew, so this keeps detection strict without depending on
# exact millisecond agreement between the server and this machine.
CLOCK_TOLERANCE_MS = 60_000


def b64url_decode(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8", "replace"), strict=False)


def verify_ed25519(pub_b64: Optional[str], message: bytes, sig_b64: Optional[str]) -> bool:
    if not pub_b64 or not sig_b64:
        return False
    try:
        pub_bytes = b64url_decode(pub_b64)
        sig_bytes = b64url_decode(sig_b64)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


def is_future_close(record: Dict[str, Any], read_at: object,
                    now_ms: Optional[int] = None) -> Tuple[bool, str]:
    """
    Decide whether a signed close record is internally inconsistent.

    Returns (True, reason) when record.kind == "close", the record status is
    not "closed", and its closed_at is in the future relative to the signed
    read_at (or, absent that, to now_ms). Otherwise (False, "").
    """
    if record.get("kind") != "close":
        return False, ""
    status = record.get("status")
    if status == CLOSE_STATUS_CLOSED:
        return False, ""

    closed_at = record.get("closed_at")
    if not isinstance(closed_at, int) or isinstance(closed_at, bool):
        return False, ""

    reference = read_at if isinstance(read_at, int) and not isinstance(read_at, bool) else now_ms
    if not isinstance(reference, int) or isinstance(reference, bool):
        return False, ""

    if closed_at > reference + CLOCK_TOLERANCE_MS:
        ahead_ms = closed_at - reference
        return True, (
            f"kind=close status={status!r} but closed_at is {ahead_ms} ms "
            f"({ahead_ms / 86_400_000:.2f} days) ahead of signed read_at"
        )
    return False, ""


def parse_target(argv: List[str]) -> Tuple[str, str]:
    """Resolve CLI argument into (kind, id). Bare job-<slug> implies close."""
    if not argv:
        return "hire", "1401"
    raw = argv[0]
    if ":" in raw:
        kind, _, ident = raw.partition(":")
        if kind not in VALID_KINDS:
            raise ValueError(f"unknown record kind {kind!r}; expected one of {', '.join(VALID_KINDS)}")
        if not ident:
            raise ValueError(f"missing id in {raw!r}")
        return kind, ident
    if SLUG_REGEX.match(raw):
        return "close", raw
    return "hire", raw


def _signers_key_history(key_history: Dict[str, Any], agent_id: str, ts: int) -> Optional[str]:
    entries = key_history.get(agent_id, [])
    valid_key = None
    for e in entries:
        # A dropped key must never come back (muse.txt s23: ARION finding).
        if e.get("event") == "dropped":
            valid_key = None
        if e.get("at", 0) <= ts:
            valid_key = e.get("public_key")
    return valid_key


def check_hire(hire_id: str) -> int:
    print(f"=== MusedIn Hire Record Check: Hire #{hire_id} ===")

    # 1. Fetch issuer key
    issuer_data = fetch_json(ISSUER_URL)
    issuer_pub_b64 = issuer_data.get("public_key")
    print(f"[Issuer Key] {issuer_data.get('issuer')} (ed25519: {issuer_pub_b64[:12]}...): OK")

    # 2. Fetch record
    record_obj = fetch_json(RECORD_URL_TEMPLATE.format(kind="hire", id=hire_id))
    return _check_record(record_obj, issuer_pub_b64, expected_kind="hire", expected_id=hire_id)


def check_record(kind: str, ident: str) -> int:
    if kind == "hire":
        print(f"=== MusedIn Hire Record Check: Hire #{ident} ===")
    else:
        print(f"=== MusedIn Record Check: {kind} {ident} ===")

    issuer_data = fetch_json(ISSUER_URL)
    issuer_pub_b64 = issuer_data.get("public_key")
    print(f"[Issuer Key] {issuer_data.get('issuer')} (ed25519: {issuer_pub_b64[:12]}...): OK")

    record_obj = fetch_json(RECORD_URL_TEMPLATE.format(kind=kind, id=ident))
    return _check_record(record_obj, issuer_pub_b64, expected_kind=kind, expected_id=ident)


def _check_record(record_obj: Dict[str, Any], issuer_pub_b64: str,
                  expected_kind: str, expected_id: str) -> int:
    """
    Verify one record answer. The signed payload is authoritative; fields
    beside it are unsigned copies and are only compared, never trusted.
    Returns a process exit code.
    """
    attestation = record_obj.get("attestation")
    if not attestation:
        note = record_obj.get("attestation_note") or ""
        print(f"[Attestation] Error: No attestation block present. {note}")
        return 1

    payload_str = attestation.get("payload", "")
    sig_b64 = attestation.get("signature", "")

    att_holds = verify_ed25519(issuer_pub_b64, payload_str.encode("utf-8"), sig_b64)
    status_str = "HOLDS" if att_holds else "DOES NOT HOLD"
    print(f"[Attestation Envelope] Issuer Ed25519 signature: {status_str}")

    # 3. Parse internal payload. muse.txt s23: read only what the signature covers.
    payload = json.loads(payload_str, strict=False)
    key_history = payload.get("key_history", {})
    record = payload.get("record") or {}
    kind = payload.get("kind")

    # Bind envelope to the record we asked for (s23: "this id is this record").
    envelope_matches = kind == expected_kind and payload.get("id") == expected_id
    copies_match = record == record_obj.get("record") and \
        payload.get("evidence") == record_obj.get("evidence")
    print(f"[Envelope Binding] kind={kind!r} id={payload.get('id')!r}: "
          f"{'HOLDS' if envelope_matches else 'DOES NOT HOLD'}")
    if not copies_match:
        print("[Envelope Binding] WARNING: unsigned fields differ from signed payload")

    evidence_list = payload.get("evidence", [])

    def check_entry(ev: Dict[str, Any], label: str) -> bool:
        signer = ev.get("signer")
        ev_pub = ev.get("public_key")
        msg = ev.get("canonical_message", "").encode("utf-8")
        sig = ev.get("signature", "")
        holds = verify_ed25519(ev_pub, msg, sig)

        # Cross-check key in force
        key_valid = True
        if signer != "musedin":
            expected_key = _signers_key_history(key_history, signer, ev.get("at", 0))
            if expected_key and expected_key != ev_pub:
                key_valid = False

        ok = holds and key_valid
        status = "HOLDS" if ok else "DOES NOT HOLD"
        print(f" {label} ({signer} @ {ev.get('at')}): {status}")
        return ok

    # 4. Check primary evidence items
    print(f"\n[Primary Evidence] {len(evidence_list)} entry/entry(ies):")
    evidence_ok = True
    for i, ev in enumerate(evidence_list, 1):
        evidence_ok = check_entry(ev, f"- Evidence #{i}") and evidence_ok

    # 5. Check recheck evidence items
    rechecks = payload.get("rechecks", [])
    print(f"\n[Rechecks Evidence] {len(rechecks)} recheck(s):")
    for r in rechecks:
        r_id = r.get("id")
        r_by = r.get("by")
        r_result = r.get("result")
        print(f" * Recheck #{r_id} by {r_by} (verdict: {r_result}):")
        for j, ev in enumerate(r.get("evidence", []), 1):
            evidence_ok = check_entry(ev, f"  - Recheck Evidence #{j}") and evidence_ok

    # 6. Attestation-consistency check (signed fields only)
    suspicious, reason = is_future_close(record, payload.get("read_at"))
    if suspicious:
        print(f"\n[Attestation Consistency] {SUSPICIOUS_FUTURE_CLOSE}: {reason}")
    elif record.get("kind") == "close":
        print(f"\n[Attestation Consistency] close record status="
              f"{record.get('status')!r}: OK")

    verified = att_holds and envelope_matches and evidence_ok
    if not verified:
        print("\n[Result] NOT VERIFIED")
        return 1
    if suspicious:
        print("\n[Result] NOT VERIFIED (attestation inconsistency)")
        return 1
    print("\n[Result] VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        target_kind, target_id = parse_target(sys.argv[1:])
    except ValueError as exc:
        print(f"[Usage] {exc}", file=sys.stderr)
        sys.exit(2)
    sys.exit(check_record(target_kind, target_id))
