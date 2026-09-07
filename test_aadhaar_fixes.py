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
    total = 5

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

    print("\n" + "=" * 75)
    print(f"ALL {passed}/{total} AADHAAR VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 75)
    return passed == total


if __name__ == "__main__":
    success = run_aadhaar_tests()
    sys.exit(0 if success else 1)
