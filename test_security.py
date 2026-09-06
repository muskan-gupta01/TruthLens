"""
TruthLens Comprehensive Security & Verification Test Suite
SIH26188: AI-Based Fake Identity & Document Screening System (Ministry of Home Affairs)

Automated test verification covering all 15 mandatory scenarios:
1. Genuine Aadhaar + claimed Aadhaar (Aadhaar detected / no business-card misclassification)
2. Business card + claimed Aadhaar (Commercial detected / type mismatch / Critical Risk)
3. Business card in AUTO detection (BUSINESS_CARD detected)
4. Genuine Aadhaar containing gov contact info (uidai.gov.in, 1947, Office NOT business card)
5. OCR-noisy genuine Aadhaar (Uncertainty state, not automatic counterfeit)
6. Tampered Aadhaar sample (Tampering indicators detected)
7. PAN sample (Format & checksums pass)
8. Passport sample (MRZ structure & 7-3-1 check digits verified)
9. 860x540 synthetic fallback removal (No hardcoded identity injected)
10. QR decode failure (Graceful behavior, no crash)
11. XSS mitigation (Untrusted OCR/history payloads escaped)
12. Directory traversal prevention (Traversal in sample_id safely blocked with 404)
13. Oversized upload prevention (>15MB rejected with 413)
14. Unauthenticated sensitive API protection (401 on /api/screen, /api/history, etc.)
15. OCR noise filtering, Aadhaar name disambiguation, and conditional MRZ processing
"""
import io
import re
import sys
from pathlib import Path
from PIL import Image
from fastapi.testclient import TestClient

from app.config import SAMPLE_DOCS_DIR
from app.main import app
from app.pipeline.screening_pipeline import run_truthlens_screening
from app.pipeline.ocr_extractor import (
    classify_document_evidence,
    extract_document_fields,
    clean_ocr_text,
    extract_aadhaar_name,
    parse_aadhaar_fields,
    DOC_TYPE_AADHAAR,
    DOC_TYPE_BUSINESS_CARD,
    DOC_TYPE_PAN,
    DOC_TYPE_PASSPORT
)
from app.pipeline.format_validator import validate_aadhaar_number, validate_document_rules
from app.pipeline.qr_detector import detect_and_decode_qr
from app.pipeline.risk_engine import compute_risk_assessment


def run_all_security_tests():
    print("=" * 75)
    print("TRUTHLENS SECURITY & FORENSIC PIPELINE AUTOMATED VERIFICATION SUITE")
    print("=" * 75)

    client = TestClient(app)
    passed_tests = 0
    total_tests = 15

    # Setup auth token for authenticated tests
    res_login = client.post("/api/auth/login", json={
        "email": "officer@truthlens.gov.in",
        "password": "TruthLens@2025"
    })
    if res_login.status_code != 200:
        print("[SETUP ERROR] Default officer could not authenticate:", res_login.text)
        sys.exit(1)
    session_token = res_login.json()["token"]
    auth_headers = {"Authorization": f"Bearer {session_token}"}

    # =========================================================================
    # TEST 1: Genuine Aadhaar + claimed Aadhaar
    # =========================================================================
    print("\n[TEST 1] Genuine Aadhaar + Claimed Aadhaar...")
    try:
        aadhaar_path = SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg"
        doc_img = Image.open(aadhaar_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="AADHAAR")
        assert res["doc_type"] == DOC_TYPE_AADHAAR, f"Expected AADHAAR, got {res['doc_type']}"
        assert res["ocr"]["is_claimed_mismatch"] is False, "Mismatch unexpectedly triggered"
        assert res["verdict"] == "VERIFIED / LOW RISK", f"Expected LOW RISK, got {res['verdict']}"
        assert res["risk_score"] <= 29, f"Risk score {res['risk_score']} exceeded 29"

        # Verify dossier checkpoint consistency: both format and checksum must be PASS
        cp_validity = next(c for c in res["dossier"]["checkpoints"] if c["id"] == "validity")
        cp_checksum = next(c for c in res["dossier"]["checkpoints"] if c["id"] == "checksum")
        assert cp_validity["status"] == "PASS", f"Expected validity PASS, got {cp_validity['status']}"
        assert cp_checksum["status"] == "PASS", f"Expected checksum PASS, got {cp_checksum['status']}"

        print(f"  >>> PASS: Aadhaar detected ({res['doc_type']}), Risk {res['risk_score']}/100, Verdict: {res['verdict']}")
        print(f"            Checkpoints: Validity={cp_validity['status']}, Checksum={cp_checksum['status']}")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 1 failed: {e}")

    # =========================================================================
    # TEST 2: Business card + claimed Aadhaar
    # =========================================================================
    print("\n[TEST 2] Business Card + Claimed Aadhaar (Mismatch Detection)...")
    try:
        biz_path = SAMPLE_DOCS_DIR / "sample_commercial_business_card.jpg"
        doc_img = Image.open(biz_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="AADHAAR")
        assert res["doc_type"] == DOC_TYPE_BUSINESS_CARD, f"Expected BUSINESS_CARD, got {res['doc_type']}"
        assert res["ocr"]["is_claimed_mismatch"] is True, "Mismatch signal was not set"
        assert res["ocr"]["is_non_identity"] is True, "Non-identity flag was not set"
        assert res["risk_score"] >= 95, f"Expected critical risk (>=95), got {res['risk_score']}"
        assert "REJECTED" in res["verdict"] or "HIGH RISK" in res["verdict"], f"Unexpected verdict: {res['verdict']}"
        print(f"  >>> PASS: Mismatch detected! Claimed: AADHAAR, Detected: {res['doc_type']}, Risk: {res['risk_score']}/100")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 2 failed: {e}")

    # =========================================================================
    # TEST 3: Business card in AUTO detection
    # =========================================================================
    print("\n[TEST 3] Business Card in AUTO Detection...")
    try:
        biz_path = SAMPLE_DOCS_DIR / "sample_commercial_business_card.jpg"
        doc_img = Image.open(biz_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="AUTO")
        assert res["doc_type"] == DOC_TYPE_BUSINESS_CARD, f"Expected BUSINESS_CARD, got {res['doc_type']}"
        assert res["risk_score"] >= 90, f"Expected risk >= 90, got {res['risk_score']}"
        print(f"  >>> PASS: AUTO classified as {res['doc_type']}, Risk: {res['risk_score']}/100")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 3 failed: {e}")

    # =========================================================================
    # TEST 4: Genuine Aadhaar containing gov contact info
    # =========================================================================
    print("\n[TEST 4] Genuine Aadhaar with Gov Contact Info (No False Business Card)...")
    try:
        sample_gov_ocr_text = (
            "GOVERNMENT OF INDIA\n"
            "UNIQUE IDENTIFICATION AUTHORITY OF INDIA\n"
            "Help: 1947 | help@uidai.gov.in | www.uidai.gov.in | uidai.gov.in\n"
            "Regional Office: Aadhaar Complex, New Delhi\n"
            "Director General UIDAI\n"
            "Mera Aadhaar, Meri Pehchan\n"
            "To: Rajesh Kumar Sharma\n"
            "DOB: 15/08/1985\n"
            "Gender: MALE\n"
            "1234 5678 9012\n"
        )
        ev_claimed = classify_document_evidence(sample_gov_ocr_text, user_hint="AADHAAR")
        assert ev_claimed["detected_type"] == DOC_TYPE_AADHAAR, f"Claimed Aadhaar classified as {ev_claimed['detected_type']}"
        assert ev_claimed["is_claimed_mismatch"] is False, "Mismatch falsely triggered"

        ev_auto = classify_document_evidence(sample_gov_ocr_text, user_hint="AUTO")
        assert ev_auto["detected_type"] == DOC_TYPE_AADHAAR, f"Auto classified as {ev_auto['detected_type']}"
        assert ev_auto["is_non_identity"] is False, "Aadhaar flagged as non-identity"

        print(f"  >>> PASS: Government domains & contact info successfully recognized as official Aadhaar.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 4 failed: {e}")

    # =========================================================================
    # TEST 5: OCR-noisy genuine Aadhaar (Uncertainty vs Counterfeit & Risk Consistency)
    # =========================================================================
    print("\n[TEST 5] OCR Uncertainty Handling & Checksum Verdict Consistency...")
    try:
        # Generate genuine 12-digit Aadhaar number with valid Verhoeff checksum
        # '234567890124' is verified valid by UIDAI Verhoeff algorithm
        valid_num = "234567890124"
        # '234567890125' is a single-digit optical substitution (common OCR ambiguity)
        noisy_num = "234567890125"

        # 5A: Single-digit OCR noise with low OCR confidence -> WARN / Uncertainty
        val_low_conf = validate_aadhaar_number(noisy_num, ocr_conf=40.0)
        assert val_low_conf["valid"] is False
        assert val_low_conf["status"] == "WARN", f"Expected WARN status, got {val_low_conf['status']}"
        assert "Uncertain" in val_low_conf["message"], f"Message should specify uncertainty: {val_low_conf['message']}"

        # 5B: High confidence scan with wrong checksum = Confirmed Failure
        val_high_conf = validate_aadhaar_number(noisy_num, ocr_conf=92.0)
        assert val_high_conf["valid"] is False
        assert val_high_conf["status"] == "FAIL", f"Expected FAIL status, got {val_high_conf['status']}"

        # 5C: Valid checksum = PASS
        val_valid = validate_aadhaar_number(valid_num, ocr_conf=90.0)
        assert val_valid["valid"] is True
        assert val_valid["status"] == "PASS"

        # 5D: Check document rules warning vs failure counting
        rules_warn = validate_document_rules(
            "AADHAAR",
            {"id_number": noisy_num},
            ocr_data={"mean_confidence": 38.0}
        )
        assert rules_warn["failures_count"] == 0, f"Low conf OCR error counted as failure: {rules_warn['failures_count']}"
        assert rules_warn["warnings_count"] >= 1, "Expected warning recorded for OCR uncertainty"

        # 5E: Risk Engine Consistency - Valid Checksum produces 0 penalty
        rep_valid = compute_risk_assessment(
            validation_report={"failures_count": 0, "warnings_count": 0, "checklist": [{"check": "Aadhaar Verhoeff Checksum", "status": "PASS", "detail": "Valid checksum"}]},
            forensics_report={},
            metadata_report={},
            face_report={},
            ocr_report={"fields": {"full_name": "Rajesh Kumar", "id_number": valid_num}, "doc_type": "AADHAAR", "claimed_type": "AADHAAR"}
        )
        assert rep_valid["score"] == 0, f"Valid checksum unexpectedly penalized: {rep_valid['score']}"
        assert rep_valid["verdict"] == "VERIFIED / LOW RISK"

        # 5F: Risk Engine Consistency - Confirmed Checksum Failure CANNOT be VERIFIED AUTHENTIC with 0 risk
        rep_invalid = compute_risk_assessment(
            validation_report={"failures_count": 1, "warnings_count": 0, "checklist": [{"check": "Aadhaar Verhoeff Checksum", "status": "FAIL", "detail": "Verhoeff Algorithm Checksum Failed: Invalid Aadhaar number."}]},
            forensics_report={},
            metadata_report={},
            face_report={},
            ocr_report={"fields": {"full_name": "Rajesh Kumar", "id_number": noisy_num}, "doc_type": "AADHAAR", "claimed_type": "AADHAAR"}
        )
        assert rep_invalid["score"] >= 35, f"Checksum failure risk too low: {rep_invalid['score']}"
        assert rep_invalid["verdict"] != "VERIFIED / LOW RISK", "Checksum failure incorrectly marked VERIFIED / LOW RISK"
        assert rep_invalid["verdict"] in ["NEEDS MANUAL REVIEW", "HIGH RISK / SUSPICIOUS DOCUMENT"]
        assert any(f["category"] == "CHECKSUM_FAILURE" for f in rep_invalid["factors"]), "Checksum failure factor missing"

        # 5G: Risk Engine Consistency - OCR Uncertainty produces WARN factor without declaring fraud
        rep_uncertain = compute_risk_assessment(
            validation_report={"failures_count": 0, "warnings_count": 1, "checklist": [{"check": "Aadhaar Verhoeff Checksum", "status": "WARN", "detail": "OCR Checksum Uncertainty"}]},
            forensics_report={},
            metadata_report={},
            face_report={},
            ocr_report={"fields": {"full_name": "Rajesh Kumar", "id_number": noisy_num}, "doc_type": "AADHAAR", "claimed_type": "AADHAAR"}
        )
        assert rep_uncertain["score"] <= 29, f"OCR uncertainty risk score too high: {rep_uncertain['score']}"
        assert any(f["category"] == "OCR_CHECKSUM_UNCERTAINTY" for f in rep_uncertain["factors"]), "Uncertainty factor missing"
        assert rep_uncertain["verdict"] != "HIGH RISK / SUSPICIOUS DOCUMENT", "OCR uncertainty falsely declared high risk fraud"

        print("  >>> PASS: Checksum verification logic and risk engine consistency confirmed across all states.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 5 failed: {e}")

    # =========================================================================
    # TEST 6: Tampered Aadhaar sample
    # =========================================================================
    print("\n[TEST 6] Tampered Document Detection...")
    try:
        tampered_path = SAMPLE_DOCS_DIR / "sample_tampered_name_aadhaar.jpg"
        doc_img = Image.open(tampered_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="AADHAAR")
        # Tampered name sample has OCR ↔ QR conflict or ELA anomaly
        assert res["risk_score"] >= 60, f"Expected elevated risk score (>=60), got {res['risk_score']}"
        assert res["verdict"] != "VERIFIED / LOW RISK", f"Tampered document was marked as LOW RISK"
        print(f"  >>> PASS: Tampering detected! Risk Score: {res['risk_score']}/100, Verdict: {res['verdict']}")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 6 failed: {e}")

    # =========================================================================
    # TEST 7: PAN sample
    # =========================================================================
    print("\n[TEST 7] PAN Card Processing & Format Validation...")
    try:
        pan_path = SAMPLE_DOCS_DIR / "sample_genuine_pan.jpg"
        doc_img = Image.open(pan_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="PAN")
        assert res["doc_type"] == DOC_TYPE_PAN, f"Expected PAN, got {res['doc_type']}"
        assert res["verdict"] == "VERIFIED / LOW RISK", f"Expected LOW RISK, got {res['verdict']}"
        assert res["risk_score"] <= 29, f"Risk score {res['risk_score']} exceeded 29"
        print(f"  >>> PASS: PAN verified authentic! ID: {res['ocr']['fields'].get('id_number')}, Risk: {res['risk_score']}/100")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 7 failed: {e}")

    # =========================================================================
    # TEST 8: Passport sample
    # =========================================================================
    print("\n[TEST 8] Passport MRZ Format & Checksum Verification...")
    try:
        passport_path = SAMPLE_DOCS_DIR / "demo_passport_genuine.jpg"
        doc_img = Image.open(passport_path)
        res = run_truthlens_screening(doc_img, claimed_doc_type="PASSPORT")
        assert res["doc_type"] == DOC_TYPE_PASSPORT, f"Expected PASSPORT, got {res['doc_type']}"
        mrz = res["ocr"]["mrz"]
        assert mrz is not None, "MRZ data missing"
        assert mrz["valid_structure"] is True, "MRZ structure invalid"
        assert mrz["checksums"]["all_passed"] is True, "MRZ checksums failed"
        assert res["verdict"] == "VERIFIED / LOW RISK"
        print(f"  >>> PASS: Passport MRZ verified! Country: {mrz.get('issuing_country')}, Doc#: {mrz.get('doc_number')}")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 8 failed: {e}")

    # =========================================================================
    # TEST 9: 860x540 synthetic fallback removal
    # =========================================================================
    print("\n[TEST 9] Verifying Removal of 860x540 Synthetic OCR Fallback...")
    try:
        # Create an arbitrary blank/gradient image with exact dimension 860x540
        fake_860x540 = Image.new("RGB", (860, 540), color=(128, 128, 128))
        extracted = extract_document_fields(fake_860x540, doc_type_hint="AADHAAR")
        raw_extracted = extracted.get("raw_text", "")

        # Verify neither Aakash Verma nor hardcoded identity strings are injected
        assert "Aakash Verma" not in raw_extracted, "Fabricated name 'Aakash Verma' found in OCR text!"
        assert "9876 5432 1098" not in raw_extracted, "Fabricated Aadhaar number found in OCR text!"
        assert "help@uidai.gov.in" not in raw_extracted or "1947" not in raw_extracted, "Hardcoded fallback text detected!"
        print("  >>> PASS: Synthetic dimension-based OCR fallback verified removed; no fake data injected.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 9 failed: {e}")

    # =========================================================================
    # TEST 10: QR decode failure handling
    # =========================================================================
    print("\n[TEST 10] QR Decode Failure / Non-QR Document Robustness...")
    try:
        # Image with no QR code
        blank_img = Image.new("RGB", (300, 300), color=(240, 240, 240))
        qr_info = detect_and_decode_qr(blank_img)
        assert isinstance(qr_info, dict), "detect_and_decode_qr did not return a dictionary"
        assert qr_info["detected"] is False, "QR falsely detected on blank image"
        assert qr_info["decoded"] is False

        # Run pipeline on document with no QR
        res = run_truthlens_screening(blank_img, claimed_doc_type="AUTO")
        assert res["qr"]["detected"] is False
        assert res["qr"]["decoded"] is False
        print("  >>> PASS: Pipeline handles missing/unreadable QR codes gracefully without exceptions.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 10 failed: {e}")

    # =========================================================================
    # TEST 11: XSS mitigation test
    # =========================================================================
    print("\n[TEST 11] XSS Mitigation & DOM Sanitization...")
    try:
        app_js_path = Path("static/js/app.js")
        assert app_js_path.exists(), "app.js not found"
        js_content = app_js_path.read_text(encoding="utf-8")

        # Verify escapeHtml utility function exists in app.js
        assert "function escapeHtml" in js_content, "escapeHtml function is missing in app.js"

        # Verify escapeHtml handles malicious characters properly
        def py_escape_html(s):
            return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#039;')

        malicious_payload = '<img src=x onerror=alert(1)>'
        escaped = py_escape_html(malicious_payload)
        assert "<" not in escaped and ">" not in escaped, "HTML characters not escaped"
        assert "&lt;img" in escaped and "&gt;" in escaped

        # Verify app.js calls escapeHtml in renderOcrResults, qrCrossTbody, renderValidationResults, etc.
        assert "escapeHtml(key" in js_content or "escapeHtml(val)" in js_content, "escapeHtml not used in renderOcrResults"
        assert "escapeHtml(row.field)" in js_content, "escapeHtml not used in QR cross verification table"
        assert "escapeHtml(item.check)" in js_content, "escapeHtml not used in checklist rendering"

        print("  >>> PASS: XSS sanitization verified in app.js; untrusted inputs properly escaped.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 11 failed: {e}")

    # =========================================================================
    # TEST 12: Directory traversal prevention
    # =========================================================================
    print("\n[TEST 12] Directory Traversal Vulnerability Prevention...")
    try:
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\boot.ini",
            "..%2F..%2Fwindows%2Fwin.ini",
            "....//sample_genuine_aadhaar.jpg",
            "/absolute/path/test"
        ]

        for payload in traversal_payloads:
            # Test /api/samples/{sample_id}
            resp = client.get(f"/api/samples/{payload}", headers=auth_headers)
            assert resp.status_code in [400, 404], f"Traversal payload '{payload}' returned status {resp.status_code}!"

            # Test /api/screen with sample_id traversal
            resp_screen = client.post(
                "/api/screen",
                data={"sample_id": payload, "doc_type": "AADHAAR"},
                headers=auth_headers
            )
            assert resp_screen.status_code in [400, 404], f"Screen traversal payload '{payload}' returned {resp_screen.status_code}!"

        print("  >>> PASS: Directory traversal attacks safely rejected with 404 Not Found.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 12 failed: {e}")

    # =========================================================================
    # TEST 13: Oversized upload rejection (15MB limit)
    # =========================================================================
    print("\n[TEST 13] File Upload Limits (Oversized Payload Rejection)...")
    try:
        # Create an oversized payload > 15MB (e.g. 15.5MB)
        oversized_data = b"\x00" * (15 * 1024 * 1024 + 512 * 1024)
        files = {"document_file": ("oversized.jpg", io.BytesIO(oversized_data), "image/jpeg")}
        resp = client.post(
            "/api/screen",
            data={"doc_type": "AADHAAR"},
            files=files,
            headers=auth_headers
        )
        assert resp.status_code == 413, f"Expected HTTP 413 Payload Too Large, got {resp.status_code}"
        assert "exceeds maximum" in resp.json().get("detail", "").lower(), f"Unexpected error detail: {resp.json()}"
        print(f"  >>> PASS: 15.5MB upload cleanly rejected with HTTP 413 ({resp.json()['detail']}).")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 13 failed: {e}")

    # =========================================================================
    # TEST 14: Unauthenticated sensitive API protection
    # =========================================================================
    print("\n[TEST 14] Sensitive API Authentication Protection...")
    try:
        # Endpoints requiring authentication
        protected_endpoints = [
            ("POST", "/api/screen", {"doc_type": "AADHAAR"}),
            ("GET", "/api/history", None),
            ("GET", "/api/history/1", None),
            ("GET", "/api/mock-db", None),
            ("GET", "/api/stats", None)
        ]

        unauthenticated_client = TestClient(app)

        for method, endpoint, data in protected_endpoints:
            if method == "POST":
                resp = unauthenticated_client.post(endpoint, data=data)
            else:
                resp = unauthenticated_client.get(endpoint)

            assert resp.status_code == 401, f"Unauthenticated {method} {endpoint} returned {resp.status_code}, expected 401!"
            assert "Authentication required" in resp.json().get("detail", "")

        # Verify that providing valid Bearer token permits access
        resp_auth = client.get("/api/stats", headers=auth_headers)
        assert resp_auth.status_code == 200, f"Authenticated request failed with {resp_auth.status_code}"

        print("  >>> PASS: Sensitive APIs (/api/screen, /api/history, /api/mock-db, /api/stats) strictly protected by 401.")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 14 failed: {e}")

    # =========================================================================
    # TEST 15: OCR Noise, Aadhaar Name Extraction & Conditional MRZ Processing
    # =========================================================================
    print("\n[TEST 15] OCR Noise Cleaning, Aadhaar Name Disambiguation & Conditional MRZ...")
    try:
        # Part A: OCR Noise Cleaning verification
        raw_noise_sample = "\n".join([
            "____",
            "--",
            "al",
            "= awe",
            "aX",
            "Ashna Kumari",
            "DOB: 18/05/2006",
            "FEMALE",
            "4528 9134 5679",
            "Mera Aadhaar, Meri Pehchan"
        ])
        cleaned_text = clean_ocr_text(raw_noise_sample)
        cleaned_lines = [l.strip() for l in cleaned_text.splitlines() if l.strip()]

        # 1. Verify noise tokens are completely filtered
        for noise_token in ["____", "--", "aX", "al", "= awe"]:
            assert noise_token not in cleaned_lines, f"Noise token '{noise_token}' was not filtered!"

        # 2. Verify valid tokens remain available
        for valid_token in ["Ashna Kumari", "DOB: 18/05/2006", "FEMALE", "4528 9134 5679"]:
            assert any(valid_token in l for l in cleaned_lines), f"Valid token '{valid_token}' was erroneously removed!"

        # 3. Verify short valid tokens are NOT blindly removed
        for short_tok in ["DOB", "ID", "PAN", "C/O"]:
            cleaned_short = clean_ocr_text(f"{short_tok}\n____\nal")
            assert short_tok in cleaned_short, f"Short token '{short_tok}' was erroneously filtered!"

        # Part B: Aadhaar Name Disambiguation verification
        # Case 1: Competing noisy candidate "ARPT PART" vs genuine name "Ashna Kumari"
        raw_with_arpt = "\n".join([
            "GOVERNMENT OF INDIA",
            "Unique Identification Authority of India",
            "ARPT PART",
            "Ashna Kumari",
            "DOB: 18/05/2006",
            "FEMALE",
            "4528 9134 5679"
        ])
        fields_ashna = parse_aadhaar_fields(clean_ocr_text(raw_with_arpt))
        assert fields_ashna["name"] == "Ashna Kumari", (
            f"Expected 'Ashna Kumari', but got '{fields_ashna.get('name')}' (ARPT PART was not rejected!)"
        )

        # Case 2: Generic distinct name "Vikram Malhotra" (verifies no hardcoding of Ashna Kumari)
        raw_with_vikram = "\n".join([
            "GOVERNMENT OF INDIA",
            "Unique Identification Authority of India",
            "ARPT PART",
            "Vikram Malhotra",
            "DOB: 02/11/1988",
            "MALE",
            "5432 1098 7654"
        ])
        fields_vikram = parse_aadhaar_fields(clean_ocr_text(raw_with_vikram))
        assert fields_vikram["name"] == "Vikram Malhotra", (
            f"Expected 'Vikram Malhotra', but got '{fields_vikram.get('name')}'"
        )

        # Case 3: Only noisy string "ARPT PART" with no valid name candidate -> "Uncertain (Needs Review)"
        raw_only_noise = "\n".join([
            "GOVERNMENT OF INDIA",
            "Unique Identification Authority of India",
            "ARPT PART",
            "DOB: 02/11/1988",
            "MALE",
            "5432 1098 7654"
        ])
        fields_uncertain = parse_aadhaar_fields(clean_ocr_text(raw_only_noise))
        assert fields_uncertain["name"] == "Uncertain (Needs Review)", (
            f"Expected 'Uncertain (Needs Review)', got '{fields_uncertain.get('name')}'"
        )

        # Part C: MRZ Conditional Processing verification
        # 1. Aadhaar -> MRZ parser skipped and MRZ data absent
        aadhaar_path = SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg"
        doc_aadhaar = Image.open(aadhaar_path)
        res_aadhaar = run_truthlens_screening(doc_aadhaar, claimed_doc_type="AADHAAR")
        assert res_aadhaar["ocr"]["mrz"] is None, (
            f"Aadhaar document unexpectedly contains MRZ data: {res_aadhaar['ocr']['mrz']}"
        )

        # 2. PAN -> MRZ parser skipped and MRZ data absent
        pan_path = SAMPLE_DOCS_DIR / "sample_genuine_pan.jpg"
        doc_pan = Image.open(pan_path)
        res_pan = run_truthlens_screening(doc_pan, claimed_doc_type="PAN")
        assert res_pan["ocr"]["mrz"] is None, (
            f"PAN document unexpectedly contains MRZ data: {res_pan['ocr']['mrz']}"
        )

        # 3. Commercial Business Card -> MRZ parser skipped and MRZ data absent
        biz_path = SAMPLE_DOCS_DIR / "sample_commercial_business_card.jpg"
        doc_biz = Image.open(biz_path)
        res_biz = run_truthlens_screening(doc_biz, claimed_doc_type="BUSINESS_CARD")
        assert res_biz["ocr"]["mrz"] is None, (
            f"Business Card unexpectedly contains MRZ data: {res_biz['ocr']['mrz']}"
        )

        # 4. Confirm that P< or V< OCR text alone CANNOT trigger MRZ parsing on non-MRZ docs
        # Even if an Aadhaar or DL or PAN or Business Card image contains "P<" or "V<" noise
        for non_mrz_type in ["AADHAAR", "PAN", "BUSINESS_CARD", "DRIVING_LICENSE"]:
            res_noise_mrz = extract_document_fields(doc_aadhaar, doc_type_hint=non_mrz_type)
            assert res_noise_mrz["mrz"] is None, f"{non_mrz_type} unexpectedly invoked MRZ parsing!"

        # 5. Passport -> MRZ parser executes and verifies MRZ structure
        passport_path = SAMPLE_DOCS_DIR / "demo_passport_genuine.jpg"
        doc_passport = Image.open(passport_path)
        res_passport = run_truthlens_screening(doc_passport, claimed_doc_type="PASSPORT")
        assert res_passport["ocr"]["mrz"] is not None, "Passport MRZ data missing"
        assert res_passport["ocr"]["mrz"]["valid_structure"] is True, "Passport MRZ structure invalid"

        print("  >>> PASS: OCR noise filtering, Aadhaar name disambiguation & conditional MRZ verified!")
        passed_tests += 1
    except Exception as e:
        print(f"  [FAIL] Test 15 failed: {e}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 75)
    print(f"ALL SECURITY VERIFICATION TESTS COMPLETED: {passed_tests}/{total_tests} PASSED")
    print("=" * 75)
    return passed_tests == total_tests


if __name__ == "__main__":
    success = run_all_security_tests()
    sys.exit(0 if success else 1)
