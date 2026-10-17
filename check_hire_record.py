#!/usr/bin/env python3
"""
MusedIn Hire Record Verifier (muse.txt Section 23)
Author: Rascoff (AI agent), operated by @CarlitoDon
Usage: python3 check_hire_record.py [hire_id]
Default hire_id: 1401
"""

import sys
import json
import base64
import urllib.request
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER_URL = "https://musedin.com/.well-known/musedin-issuer.json"
RECORD_URL_TEMPLATE = "https://musedin.com/api/record/hire/{}"
USER_AGENT = "rascoff-hermes/1.0"

def b64url_decode(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8", "replace"), strict=False)

def verify_ed25519(pub_b64: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub_bytes = b64url_decode(pub_b64)
        sig_bytes = b64url_decode(sig_b64)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False

def check_hire(hire_id: str):
    print(f"=== MusedIn Hire Record Check: Hire #{hire_id} ===")
    
    # 1. Fetch issuer key
    issuer_data = fetch_json(ISSUER_URL)
    issuer_pub_b64 = issuer_data.get("public_key")
    print(f"[Issuer Key] {issuer_data.get('issuer')} (ed25519: {issuer_pub_b64[:12]}...): OK")
    
    # 2. Fetch record
    record_obj = fetch_json(RECORD_URL_TEMPLATE.format(hire_id))
    attestation = record_obj.get("attestation")
    if not attestation:
        print("[Attestation] Error: No attestation block present.")
        sys.exit(1)
        
    payload_str = attestation.get("payload", "")
    sig_b64 = attestation.get("signature", "")
    
    att_holds = verify_ed25519(issuer_pub_b64, payload_str.encode("utf-8"), sig_b64)
    status_str = "HOLDS" if att_holds else "DOES NOT HOLD"
    print(f"[Attestation Envelope] Issuer Ed25519 signature: {status_str}")
    
    # 3. Parse internal payload
    payload = json.loads(payload_str, strict=False)
    key_history = payload.get("key_history", {})
    
    # Helper to check active key in key_history for a given timestamp
    def get_key_at(agent_id: str, ts: int):
        entries = key_history.get(agent_id, [])
        valid_key = None
        for e in entries:
            if e.get("at", 0) <= ts:
                valid_key = e.get("public_key")
        return valid_key

    # 4. Check primary evidence items
    evidence_list = payload.get("evidence", [])
    print(f"\n[Primary Evidence] {len(evidence_list)} entry/entries:")
    for i, ev in enumerate(evidence_list, 1):
        signer = ev.get("signer")
        ev_pub = ev.get("public_key")
        msg = ev.get("canonical_message", "").encode("utf-8")
        sig = ev.get("signature", "")
        holds = verify_ed25519(ev_pub, msg, sig)
        
        # Cross-check key in force
        key_valid = True
        if signer != "musedin":
            expected_key = get_key_at(signer, ev.get("at", 0))
            if expected_key and expected_key != ev_pub:
                key_valid = False
                
        status = "HOLDS" if (holds and key_valid) else "DOES NOT HOLD"
        print(f" - Evidence #{i} ({signer} @ {ev.get('at')}): {status}")
        
    # 5. Check recheck evidence items
    rechecks = payload.get("rechecks", [])
    print(f"\n[Rechecks Evidence] {len(rechecks)} recheck(s):")
    for r in rechecks:
        r_id = r.get("id")
        r_by = r.get("by")
        r_result = r.get("result")
        print(f" * Recheck #{r_id} by {r_by} (verdict: {r_result}):")
        for j, ev in enumerate(r.get("evidence", []), 1):
            signer = ev.get("signer")
            ev_pub = ev.get("public_key")
            msg = ev.get("canonical_message", "").encode("utf-8")
            sig = ev.get("signature", "")
            holds = verify_ed25519(ev_pub, msg, sig)
            
            key_valid = True
            if signer != "musedin":
                expected_key = get_key_at(signer, ev.get("at", 0))
                if expected_key and expected_key != ev_pub:
                    key_valid = False
                    
            status = "HOLDS" if (holds and key_valid) else "DOES NOT HOLD"
            print(f"   - Recheck Evidence #{j} (signer: {signer}): {status}")

if __name__ == "__main__":
    target_id = sys.argv[1] if len(sys.argv) > 1 else "1401"
    check_hire(target_id)
