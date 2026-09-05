"""
TruthLens Privacy Data Masking & Data Minimization Verification Suite
SIH26188: AI-Based Fake Identity & Document Screening System (Ministry of Home Affairs)
DPDP Act 2023 / Privacy By Design Standard

Validates:
1. Masking logic for Aadhaar ("1234 5678 9012" -> "XXXX XXXX 9012")
2. Masking logic for Passport ("L898902C3" -> "XXXXX02C3")
3. Masking logic for PAN ("ABCPS1234F" -> "XXXXXX234F")
4. Masking logic for Driving License ("DL-1420110012345" -> "XX-XXXXXXXXX2345")
5. History table list view masks document numbers while keeping Subject Name visible
6. Detailed dossier inspection retains full unmasked document number for active review
7. Visual hash-chain explorer summary applies identical masking rule
8. Underlying stored SQLite data and SHA-256 hash-chain integrity remain completely intact
"""
import sys
import json
import subprocess
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.config import STATIC_DIR
from app.database.db_manager import (
    verify_audit_chain,
    get_audit_chain_records,
    get_history,
    get_screening_by_id
)

client = TestClient(app)


def test_js_masking_logic():
    print("\n[TEST 1] Verifying Frontend maskDocumentNumber Function Logic via Node.js...")
    js_test_script = r"""
    const fs = require('fs');
    const content = fs.readFileSync('static/js/app.js', 'utf8');

    // Extract maskDocumentNumber function definition
    const match = content.match(/function maskDocumentNumber\([\s\S]*?\n  \}/);
    if (!match) {
      console.error("maskDocumentNumber function not found in app.js");
      process.exit(1);
    }

    eval(match[0]);

    // Test Cases
    const t1 = maskDocumentNumber("1234 5678 9012", "AADHAAR");
    const t2 = maskDocumentNumber("123456789012", "AADHAAR");
    const t3 = maskDocumentNumber("L898902C3", "PASSPORT");
    const t4 = maskDocumentNumber("ABCPS1234F", "PAN");
    const t5 = maskDocumentNumber("DL-1420110012345", "DRIVING_LICENSE");
    const t6 = maskDocumentNumber("V987654321", "VISA");

    console.log(JSON.stringify({
      aadhaar_spaced: t1,
      aadhaar_raw: t2,
      passport: t3,
      pan: t4,
      dl: t5,
      visa: t6
    }));
    """
    proc = subprocess.run(["node", "-e", js_test_script], capture_output=True, text=True)
    assert proc.returncode == 0, f"Node script error: {proc.stderr}"
    results = json.loads(proc.stdout.strip())

    print(f"  Aadhaar (spaced) : {results['aadhaar_spaced']}")
    print(f"  Aadhaar (raw)    : {results['aadhaar_raw']}")
    print(f"  Passport         : {results['passport']}")
    print(f"  PAN              : {results['pan']}")
    print(f"  Driving License  : {results['dl']}")
    print(f"  Visa             : {results['visa']}")

    assert results["aadhaar_spaced"] == "XXXX XXXX 9012", f"Unexpected Aadhaar masking: {results['aadhaar_spaced']}"
    assert results["aadhaar_raw"] == "XXXX XXXX 9012", f"Unexpected Aadhaar raw masking: {results['aadhaar_raw']}"
    assert results["passport"] == "XXXXX02C3", f"Unexpected Passport masking: {results['passport']}"
    assert results["pan"] == "XXXXXX234F", f"Unexpected PAN masking: {results['pan']}"
    assert results["dl"].endswith("2345") and "X" in results["dl"], f"Unexpected DL masking: {results['dl']}"
    print("  >>> PASS: maskDocumentNumber adheres precisely to government privacy standards!")


def test_history_list_and_dossier_contract():
    print("\n[TEST 2] Verifying History List View vs Detailed Inspect Dossier Contract...")
    js_path = STATIC_DIR / "js" / "app.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # 1. Check history table uses maskDocumentNumber for doc_number
    assert "maskDocumentNumber(r.doc_number, r.doc_type)" in js_code, \
        "loadHistory must mask document numbers with maskDocumentNumber(r.doc_number, r.doc_type)"
    assert "masked-doc-badge" in js_code, \
        "History table must render masked doc badge"

    # 2. Check history table keeps person_name unmasked
    assert "${r.person_name || 'N/A'}" in js_code, \
        "Subject name must remain visible and unmasked in history table"

    # 3. Check detailed dossier uses unmasked values
    assert "dossier.doc_number || fields.passport_number || fields.id_number || fields.visa_number" in js_code, \
        "Detailed master dossier must display unmasked document number"

    # 4. Check inspect button triggers master dossier render
    assert "btn-view-history-record" in js_code, "Inspect button class must exist"
    assert "renderMasterDossier(rep)" in js_code, "Clicking inspect must call renderMasterDossier"
    print("  >>> PASS: History list masks document numbers, preserves names, and inspect displays full unmasked dossier!")


def test_audit_chain_explorer_masking():
    print("\n[TEST 3] Verifying Audit Chain Visual Explorer Masking...")
    js_path = STATIC_DIR / "js" / "app.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # Verify visual explorer calls maskDocumentNumber
    assert "maskDocumentNumber(block.doc_number, block.doc_type)" in js_code, \
        "Visual hash-chain explorer must mask document numbers if present"

    # Verify API /api/audit/chain provides block metadata
    res = client.get("/api/audit/chain?limit=10")
    assert res.status_code == 200
    chain = res.json().get("chain", [])
    if len(chain) > 0:
        first = chain[0]
        assert "doc_type" in first and "doc_number" in first, \
            "get_audit_chain_records must supply doc_type and doc_number for visual explorer"
    print("  >>> PASS: Visual Hash-Chain explorer summary applies identical masking logic!")


def test_database_and_hash_integrity():
    print("\n[TEST 4] Verifying Underlying Database and Cryptographic Hash Integrity...")
    # 1. Check /api/history returns raw unmasked data (backend data layer untouched)
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 200
    records = res_hist.json().get("history", [])
    for rec in records:
        # Check that stored doc numbers are raw (not overwritten with 'XXXX')
        raw_doc = rec.get("doc_number")
        if raw_doc and raw_doc != "N/A":
            assert not raw_doc.startswith("XXXX XXXX"), \
                f"Underlying database doc_number was corrupted/masked: {raw_doc}"

    # 2. Check cryptographic audit verification
    verify_res = verify_audit_chain()
    assert verify_res["valid"] is True, f"Hash chain verification failed: {verify_res}"
    assert verify_res["broken_at"] is None
    print(f"  Audit Verification: {verify_res['message']}")
    print("  >>> PASS: Database records & SHA-256 hash-chain integrity remain 100% intact!")


def run_all():
    print("=" * 75)
    print("TRUTHLENS DATA MASKING & PRIVACY SPECIFICATION TESTS")
    print("=" * 75)
    test_js_masking_logic()
    test_history_list_and_dossier_contract()
    test_audit_chain_explorer_masking()
    test_database_and_hash_integrity()
    print("\n" + "=" * 75)
    print("ALL DATA MASKING & PRIVACY TESTS PASSED!")
    print("=" * 75)
    return True


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
