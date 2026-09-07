"""
TruthLens Aadhaar Fixes Verification Suite
Validates:
1. Bidirectional UIDAI Secure QR V2 masking (12-digit printed vs 4-digit QR)
2. Statutory Masked Aadhaar format validation (XXXX XXXX 1234, **** **** 1234)
3. Name extraction header exclusion ("Unique Identification" never captured as name)
4. Anti-tamper negative test retention (Scenario 6 altered name still flagged as HIGH RISK)
5. End-to-end mock screening of real modern Aadhaar profile (LOW RISK / VERIFIED)
"""
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from unittest.mock import patch
from PIL import Image
from app.pipeline.cross_verifier import compare_id_numbers, compare_names, cross_verify_documents
from app.pipeline.format_validator import validate_aadhaar_number, validate_verhoeff
from app.pipeline.ocr_extractor import parse_aadhaar_fields
from app.pipeline.screening_pipeline import run_truthlens_screening
from app.config import SAMPLE_DOCS_DIR


def run_aadhaar_tests():
    print("=" * 75)
    print("TRUTHLENS AADHAAR REAL-DOCUMENT FIXES VERIFICATION SUITE")
    print("=" * 75)

    passed = 0
    total = 9

    # =========================================================================
    # TEST 1: BIDIRECTIONAL UIDAI SECURE QR V2 NUMBER MATCHING
    # =========================================================================
    print("\n[TEST 1] Testing Bidirectional UIDAI Secure QR V2 Number Matching...")
    # Modern card: 12-digit printed vs 4-digit QR
    sim1, st1, exp1 = compare_id_numbers("5489 2104 7834", "XXXX XXXX 7834")
    assert st1 == "MATCH", f"Expected MATCH for 12-digit vs 4-digit QR, got {st1}: {exp1}"
    assert sim1 == 100.0

    # Masked card: 4-digit printed vs 12-digit QR
    sim2, st2, exp2 = compare_id_numbers("XXXX XXXX 7834", "548921047834")
    assert st2 == "MATCH", f"Expected MATCH for 4-digit masked vs 12-digit QR, got {st2}: {exp2}"
    assert sim2 == 100.0

    # Tampered card: Altered digits must STILL be rejected!
    sim3, st3, exp3 = compare_id_numbers("5489 2104 7834", "XXXX XXXX 9999")
    assert st3 == "MISMATCH", f"Expected MISMATCH for forged ID, got {st3}: {exp3}"
    assert "CRITICAL" in exp3

    print("  >>> PASS: Bidirectional UIDAI Secure QR V2 matching verified (fraud still rejected)!")
    passed += 1

    # =========================================================================
    # TEST 2: STATUTORY MASKED AADHAAR FORMAT VALIDATION
    # =========================================================================
    print("\n[TEST 2] Testing Statutory Masked Aadhaar Format Validation...")
    # Masked formats under UIDAI / DPDP Act 2023
    r_x = validate_aadhaar_number("XXXX XXXX 7834")
    assert r_x["valid"] is True and r_x["status"] == "PASS", f"Masked XXXX failed: {r_x}"

    r_dot = validate_aadhaar_number("•••• •••• 7834")
    assert r_dot["valid"] is True and r_dot["status"] == "PASS", f"Masked dots failed: {r_dot}"

    r_star = validate_aadhaar_number("**** **** 7834")
    assert r_star["valid"] is True and r_star["status"] == "PASS", f"Masked stars failed: {r_star}"

    # Genuine 12-digit with Verhoeff
    r_gen = validate_aadhaar_number("452891345679")
    assert r_gen["valid"] is True and r_gen["status"] == "PASS", f"Valid 12-digit failed: {r_gen}"

    # Counterfeit 12-digit with bad check digit must STILL fail!
    r_bad = validate_aadhaar_number("452891345670")
    assert r_bad["valid"] is False and r_bad["status"] == "FAIL", f"Counterfeit 12-digit passed: {r_bad}"

    print("  >>> PASS: Statutory Masked Aadhaar formats accepted, counterfeits correctly rejected!")
    passed += 1

    # =========================================================================
    # TEST 3: HEADER LINE EXCLUSION IN NAME EXTRACTION
    # =========================================================================
    print("\n[TEST 3] Testing Name Extraction Header Exclusion...")
    sample_text = """
    GOVERNMENT OF INDIA
    Unique Identification Authority of India
    Aakash Verma
    DOB: 12/05/1992
    MALE
    5489 2104 7834
    Mera Aadhaar, Meri Pehchan
    """
    fields = parse_aadhaar_fields(sample_text)
    assert fields["name"] == "Aakash Verma", f"Expected 'Aakash Verma', got '{fields['name']}'"
    assert "Unique" not in str(fields["name"])

    # Test text where Unique Identification is on its own isolated line
    sample_text_split = """
    Unique Identification
    Authority of India
    Priya Kumari
    DOB: 18/09/1994
    FEMALE
    XXXX XXXX 1234
    """
    fields_split = parse_aadhaar_fields(sample_text_split)
    assert fields_split["name"] == "Priya Kumari", f"Expected 'Priya Kumari', got '{fields_split['name']}'"

    # Subtest 3.1: Reject OCR noise garbage (Sew STR NK Or Ww few om eer) when no valid name exists
    sample_noise_only = """
    GOVERNMENT OF INDIA
    Unique Identification Authority of India
    Sew STR NK Or Ww few om eer
    DOB: 12/05/1992
    MALE
    5489 2104 7834
    """
    fields_noise = parse_aadhaar_fields(sample_noise_only)
    assert fields_noise["name"] is None, f"Expected None for OCR garbage, got '{fields_noise['name']}'"

    # Subtest 3.2: Highest priority to text immediately following 'Name:' even with noise present
    sample_with_label_and_noise = """
    GOVERNMENT OF INDIA
    Unique Identification Authority of India
    Sew STR NK Or Ww few om eer
    Name: Aakash Verma
    DOB: 12/05/1992
    MALE
    5489 2104 7834
    """
    fields_lbl = parse_aadhaar_fields(sample_with_label_and_noise)
    assert fields_lbl["name"] == "Aakash Verma", f"Expected 'Aakash Verma', got '{fields_lbl['name']}'"

    # Subtest 3.3: Hindi label 'नाम:' priority
    sample_hindi_label = """
    GOVERNMENT OF INDIA
    Unique Identification Authority of India
    Sew STR NK Or Ww few om eer
    नाम: रोहित शर्मा
    Rohit Sharma
    DOB: 15/08/1995
    MALE
    5489 2104 7834
    """
    fields_hindi = parse_aadhaar_fields(sample_hindi_label)
    assert fields_hindi["name"] == "Rohit Sharma", f"Expected 'Rohit Sharma', got '{fields_hindi['name']}'"

    # Subtest 3.4: Bilingual label 'नाम / Name:' priority
    sample_bilingual = """
    GOVERNMENT OF INDIA
    Unique Identification Authority of India
    Sew STR NK Or Ww few om eer
    नाम / Name: Suresh Kumar
    DOB: 20/11/1988
    MALE
    5489 2104 7834
    """
    fields_bi = parse_aadhaar_fields(sample_bilingual)
    assert fields_bi["name"] == "Suresh Kumar", f"Expected 'Suresh Kumar', got '{fields_bi['name']}'"

    # Subtest 3.5: Reject address, website, and symbol noise
    sample_address_noise = """
    Address: S/O Ramesh Kumar, House 42, MG Road, Indiranagar, Bangalore 560038
    www.uidai.gov.in
    1947
    help@uidai.gov.in
    ~*^$ Sew STR NK Or Ww few om eer
    """
    fields_addr = parse_aadhaar_fields(sample_address_noise)
    assert fields_addr["name"] is None, f"Expected None for address/website text, got '{fields_addr['name']}'"

    print("  >>> PASS: 'Unique Identification' excluded, OCR noise strictly rejected, label priority verified!")
    passed += 1

    # =========================================================================
    # TEST 4: END-TO-END SCREENING OF REALISTIC MODERN AADHAAR CARD PROFILE
    # =========================================================================
    print("\n[TEST 4] Testing End-to-End Real Modern Aadhaar Profile...")
    # Load authentic sample Aadhaar
    genuine_path = SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg"
    assert genuine_path.exists(), "sample_genuine_aadhaar.jpg missing"
    doc_img = Image.open(genuine_path)

    res = run_truthlens_screening(doc_img)
    verdict = res["verdict"]
    score = res["risk_score"]
    level = res["risk_level"]

    print(f"  Result: Verdict = '{verdict}' | Risk Score = {score}/100 ({level})")
    assert verdict == "VERIFIED / LOW RISK", f"Genuine Aadhaar failed: {verdict} (Score: {score})"
    assert score <= 29, f"Risk score exceeded low-risk threshold: {score}"

    print("  >>> PASS: Genuine Aadhaar Card correctly verified as LOW RISK / VERIFIED!")
    passed += 1

    # =========================================================================
    # TEST 5: FRAUD CASE RETENTION (SCENARIO 6 TAMPERED AADHAAR STILL HIGH RISK)
    # =========================================================================
    print("\n[TEST 5] Testing Anti-Tamper Fraud Case Retention (Tampered Aadhaar)...")
    tampered_path = SAMPLE_DOCS_DIR / "sample_tampered_name_aadhaar.jpg"
    assert tampered_path.exists(), "sample_tampered_name_aadhaar.jpg missing"
    t_img = Image.open(tampered_path)

    res_t = run_truthlens_screening(t_img)
    t_verdict = res_t["verdict"]
    t_score = res_t["risk_score"]
    t_level = res_t["risk_level"]

    print(f"  Tampered Result: Verdict = '{t_verdict}' | Risk Score = {t_score}/100 ({t_level})")
    assert t_verdict == "HIGH RISK / SUSPICIOUS DOCUMENT", f"Tampered Aadhaar was NOT flagged! Got {t_verdict}"
    assert t_score >= 60, f"Tampered Aadhaar score too low: {t_score}"

    print("  >>> PASS: Tampered Aadhaar with altered name remains strictly flagged as HIGH RISK!")
    passed += 1

    # =========================================================================
    # TEST 6: TARGETED TEST 1 - VALID VERHOEFF CHECKSUM -> AUTHENTIC / LOW-RISK
    # =========================================================================
    print("\n[TEST 6] TARGETED TEST 1: Valid Verhoeff Checksum -> Authentic / Low-Risk Path Retained...")
    # Genuine card with valid Verhoeff checksum
    res_gen = run_truthlens_screening(doc_img)
    chk_gen = next(c for c in res_gen["dossier"]["checkpoints"] if c["id"] == "checksum")
    assert chk_gen["status"] == "PASS", f"Expected PASS for valid Verhoeff, got {chk_gen['status']}"
    assert res_gen["verdict"] == "VERIFIED / LOW RISK", f"Expected VERIFIED / LOW RISK, got {res_gen['verdict']}"
    assert res_gen["dossier"]["simple_badge"] == "VERIFIED AUTHENTIC", f"Expected VERIFIED AUTHENTIC, got {res_gen['dossier']['simple_badge']}"
    assert res_gen["dossier"]["validity_status"] == "ACTIVE / VALID", f"Expected ACTIVE / VALID, got {res_gen['dossier']['validity_status']}"
    assert res_gen["risk_score"] <= 29, f"Risk score exceeded low risk threshold: {res_gen['risk_score']}"

    print("  >>> PASS: Valid Verhoeff checksum produces VERIFIED AUTHENTIC & ACTIVE / VALID with LOW RISK!")
    passed += 1

    # =========================================================================
    # TEST 7: TARGETED TEST 2 - CONFIRMED INVALID VERHOEFF CHECKSUM -> CANNOT BE VERIFIED AUTHENTIC
    # =========================================================================
    print("\n[TEST 7] TARGETED TEST 2: Confirmed Invalid Verhoeff Checksum -> Cannot Be VERIFIED AUTHENTIC...")
    # Isolate checksum failure by disabling QR decoding override and injecting confirmed invalid check digit
    with patch("app.pipeline.screening_pipeline.detect_and_decode_qr", return_value={"detected": False, "decoded": False}):
        res_bad = run_truthlens_screening(doc_img, doc_number_override="5489 2104 7830")
    chk_bad = next(c for c in res_bad["dossier"]["checkpoints"] if c["id"] == "checksum")
    assert chk_bad["status"] == "FAIL", f"Expected Mathematical Checksum: FAIL, got {chk_bad['status']}"

    # Critical requirement: Confirmed invalid checksum MUST NOT produce "VERIFIED AUTHENTIC"
    badge = res_bad["dossier"]["simple_badge"]
    verdict = res_bad["verdict"]
    print(f"  Result: Badge = '{badge}' | Verdict = '{verdict}' | Risk Score = {res_bad['risk_score']}/100")
    assert badge != "VERIFIED AUTHENTIC", f"VIOLATION: Confirmed invalid checksum produced '{badge}'!"
    assert verdict != "VERIFIED / LOW RISK", f"VIOLATION: Confirmed invalid checksum produced '{verdict}'!"
    assert verdict in ["NEEDS MANUAL REVIEW", "HIGH RISK / SUSPICIOUS DOCUMENT"], f"Unexpected verdict: {verdict}"
    assert badge in ["REVIEW REQUIRED", "REJECTED / SUSPICIOUS"], f"Unexpected badge: {badge}"

    print("  >>> PASS: Confirmed invalid Verhoeff checksum CANNOT produce VERIFIED AUTHENTIC (routed to Review/High Risk)!")
    passed += 1

    # =========================================================================
    # TEST 8: TARGETED TEST 3 - CONFIRMED INVALID CHECKSUM -> CANNOT SHOW ACTIVE / VALID
    # =========================================================================
    print("\n[TEST 8] TARGETED TEST 3: Confirmed Invalid Checksum -> Cannot Show ACTIVE / VALID...")
    val_status = res_bad["dossier"]["validity_status"]
    val_class = res_bad["dossier"]["validity_badge_class"]
    print(f"  Result: Validity Status = '{val_status}' | Badge Class = '{val_class}'")
    assert val_status != "ACTIVE / VALID", f"VIOLATION: Invalid checksum displayed as '{val_status}'!"
    assert val_status in ["INVALID CHECKSUM", "INVALID"], f"Expected non-valid status, got '{val_status}'"
    assert val_class == "badge-red", f"Expected badge-red, got '{val_class}'"

    print("  >>> PASS: Confirmed invalid checksum CANNOT show ACTIVE / VALID (correctly displays INVALID CHECKSUM)!")
    passed += 1

    # =========================================================================
    # TEST 9: TARGETED TEST 4 - OCR-UNCERTAIN CHECKSUM -> REVIEW REQUIRED RATHER THAN AUTHENTIC
    # =========================================================================
    print("\n[TEST 9] TARGETED TEST 4: OCR-Uncertain Checksum -> REVIEW REQUIRED Rather Than Authentic...")
    # 1. Format validator level
    val_unc = validate_aadhaar_number("5489 2104 7830", ocr_confidence=60.0)
    assert val_unc["status"] == "WARN", f"Expected WARN for uncertain OCR checksum, got {val_unc['status']}"
    assert "Uncertainty" in val_unc["message"], f"Expected uncertainty explanation, got {val_unc['message']}"

    # 2. End-to-end pipeline screening level with uncertain OCR capture
    with patch("app.pipeline.screening_pipeline.detect_and_decode_qr", return_value={"detected": False, "decoded": False}), \
         patch("app.pipeline.screening_pipeline.extract_document_fields") as mock_ocr:
        mock_ocr.return_value = {
            "doc_type": "AADHAAR",
            "fields": {"id_number": "5489 2104 7830", "name": "Aakash Verma"},
            "mean_confidence": 60.0,
            "ocr_confidence": 60.0,
            "confidence": 60.0,
            "raw_text": "5489 2104 7830\nAakash Verma",
            "mrz": None
        }
        res_unc = run_truthlens_screening(doc_img)

    chk_unc = next(c for c in res_unc["dossier"]["checkpoints"] if c["id"] == "checksum")
    assert chk_unc["status"] == "WARN", f"Expected checksum status WARN, got {chk_unc['status']}"

    badge_unc = res_unc["dossier"]["simple_badge"]
    verdict_unc = res_unc["verdict"]
    val_unc_status = res_unc["dossier"]["validity_status"]
    print(f"  Result: Badge = '{badge_unc}' | Verdict = '{verdict_unc}' | Validity = '{val_unc_status}'")

    assert badge_unc == "REVIEW REQUIRED", f"Expected REVIEW REQUIRED for uncertain checksum, got '{badge_unc}'"
    assert verdict_unc == "NEEDS MANUAL REVIEW", f"Expected NEEDS MANUAL REVIEW, got '{verdict_unc}'"
    assert badge_unc != "VERIFIED AUTHENTIC", "Uncertain checksum must NOT be declared authentic!"
    assert val_unc_status != "ACTIVE / VALID", "Uncertain checksum must NOT show ACTIVE / VALID!"

    print("  >>> PASS: OCR-uncertain checksum correctly routed to REVIEW REQUIRED rather than authentic!")
    passed += 1

    print("\n" + "=" * 75)
    print(f"ALL {passed}/{total} AADHAAR VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 75)
    return passed == total


if __name__ == "__main__":
    success = run_aadhaar_tests()
    sys.exit(0 if success else 1)
