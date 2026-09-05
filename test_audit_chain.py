"""
TruthLens Cryptographic Audit Chain Test Suite
SIH26188: AI-Based Fake Identity & Document Screening System (Ministry of Home Affairs)
Category: Blockchain & Cybersecurity

Validates:
1. Clean Genesis Anchor State
2. Sequential Block Appending with SHA-256 Hash-Chaining
3. Verification of Untampered Chain (/api/audit/verify -> valid: True)
4. Tampering Detection: Modifying a database record directly in SQLite
   fails verification with exact record ID (/api/audit/verify -> valid: False)
5. Chain Restoration: Reverting tampered data restores valid status
"""
import sys
import json
import sqlite3
from fastapi.testclient import TestClient
from app.main import app
from app.config import DB_PATH
from app.database.db_manager import (
    get_connection,
    add_audit_chain_record,
    verify_audit_chain,
    get_audit_chain_records,
    GENESIS_HASH
)

client = TestClient(app)


def test_audit_chain_integrity():
    print("=" * 70)
    print("TRUTHLENS CRYPTOGRAPHIC AUDIT CHAIN VERIFICATION SUITE")
    print("=" * 70)

    # 1. Clean test setup in audit_chain
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_chain")
    conn.commit()
    conn.close()

    print("\n[TEST 1] Testing Genesis / Empty Chain State...")
    verify_res = verify_audit_chain()
    assert verify_res["valid"] is True, f"Empty chain should be valid: {verify_res}"
    assert verify_res["total_records"] == 0
    print(f"  >>> PASS: Empty chain verified as valid genesis state: {verify_res['message']}")

    # 2. Add sequential records
    print("\n[TEST 2] Appending Sequential Cryptographic Blocks...")
    sample_data_1 = {
        "screening_id": "TL-TEST-001",
        "doc_type": "PASSPORT",
        "verdict": "VERIFIED / LOW RISK",
        "risk_score": 5,
        "person_name": "JOHN DOE"
    }
    sample_data_2 = {
        "screening_id": "TL-TEST-002",
        "doc_type": "AADHAAR",
        "verdict": "VERIFIED / LOW RISK",
        "risk_score": 0,
        "person_name": "PRIYA SHARMA"
    }
    sample_data_3 = {
        "screening_id": "TL-TEST-003",
        "doc_type": "VISA",
        "verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
        "risk_score": 100,
        "person_name": "MARIA GONZALEZ"
    }

    b1 = add_audit_chain_record("TL-TEST-001", sample_data_1, "2026-09-05 14:00:01")
    assert b1["previous_hash"] == GENESIS_HASH, "First block previous_hash must be GENESIS_HASH"
    print(f"  Block #1 Appended: Hash={b1['short_hash']}... | Prev={b1['short_prev_hash']}...")

    b2 = add_audit_chain_record("TL-TEST-002", sample_data_2, "2026-09-05 14:00:02")
    assert b2["previous_hash"] == b1["record_hash"], "Block #2 previous_hash must match Block #1 record_hash"
    print(f"  Block #2 Appended: Hash={b2['short_hash']}... | Prev={b2['short_prev_hash']}...")

    b3 = add_audit_chain_record("TL-TEST-003", sample_data_3, "2026-09-05 14:00:03")
    assert b3["previous_hash"] == b2["record_hash"], "Block #3 previous_hash must match Block #2 record_hash"
    print(f"  Block #3 Appended: Hash={b3['short_hash']}... | Prev={b3['short_prev_hash']}...")
    print("  >>> PASS: Sequential hash-chaining linkage verified!")

    # 3. Test verification API endpoint
    print("\n[TEST 3] Testing /api/audit/verify Endpoint on Clean Ledger...")
    res = client.get("/api/audit/verify")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    body = res.json()
    assert body["valid"] is True, f"Expected valid: True, got {body}"
    assert body["total_records"] == 3
    assert body["broken_at"] is None
    print(f"  >>> PASS: API /api/audit/verify reported clean ledger: {body['message']}")

    # 4. Test audit chain retrieval API endpoint
    print("\n[TEST 4] Testing /api/audit/chain Visual Endpoint...")
    res_chain = client.get("/api/audit/chain")
    assert res_chain.status_code == 200
    chain_body = res_chain.json()
    assert len(chain_body["chain"]) == 3
    assert chain_body["chain"][0]["short_prev_hash"] == "00000000"
    print(f"  >>> PASS: Retrieved {len(chain_body['chain'])} blocks formatted for UI.")

    # 5. DEMONSTRATION OF TAMPERING DETECTION:
    # Modify data_snapshot in SQLite directly (simulating rogue insider changing verdict)
    print("\n[TEST 5] Demonstrating Tamper Detection (Direct SQLite Alteration)...")
    tampered_id = b2["id"]

    # Read original snapshot
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT data_snapshot FROM audit_chain WHERE id = ?", (tampered_id,))
    original_snapshot = cursor.fetchone()["data_snapshot"]

    # Tamper with snapshot: change risk_score from 0 to 99
    tampered_dict = json.loads(original_snapshot)
    tampered_dict["risk_score"] = 99
    tampered_dict["verdict"] = "TAMPERED_BY_INSIDER"
    tampered_snapshot = json.dumps(tampered_dict, sort_keys=True)

    cursor.execute("UPDATE audit_chain SET data_snapshot = ? WHERE id = ?", (tampered_snapshot, tampered_id))
    conn.commit()
    conn.close()
    print(f"  [SIMULATION] Directly altered data_snapshot of Block #{tampered_id} in SQLite truthlens.db")

    # Call /api/audit/verify and confirm it detects tampering
    tamper_res = client.get("/api/audit/verify")
    assert tamper_res.status_code == 200
    tamper_body = tamper_res.json()
    print(f"  Verification Result: valid={tamper_body['valid']}, broken_at={tamper_body.get('broken_at')}")
    print(f"  Alert Message: {tamper_body.get('reason')}")

    assert tamper_body["valid"] is False, "Verification MUST fail on tampered record!"
    assert tamper_body["broken_at"] == tampered_id, f"broken_at must be {tampered_id}, got {tamper_body.get('broken_at')}"
    print(f"  >>> PASS: Tampering successfully detected at Block #{tampered_id} with exact cryptographic evidence!")

    # 6. Revert tampering
    print("\n[TEST 6] Restoring Original Data and Re-verifying...")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE audit_chain SET data_snapshot = ? WHERE id = ?", (original_snapshot, tampered_id))
    conn.commit()
    conn.close()

    restore_res = client.get("/api/audit/verify")
    restore_body = restore_res.json()
    assert restore_body["valid"] is True, f"Chain should be restored to valid: {restore_body}"
    print(f"  >>> PASS: Ledger integrity successfully restored (valid: True)")

    print("\n" + "=" * 70)
    print("ALL 6 CRYPTOGRAPHIC AUDIT CHAIN TESTS PASSED!")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = test_audit_chain_integrity()
    sys.exit(0 if success else 1)
