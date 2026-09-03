"""
TruthLens Pipeline Automated Test Suite
SIH26188: AI-Based Fake Identity & Document Screening System (Ministry of Home Affairs)

Verifies:
1. Genuine Travel Passport + Biometric Face Match (LOW RISK / VERIFIED)
2. Expired Visa with Overstay Flag (HIGH RISK / REJECTED)
3. Tampered Passport + Spliced Portrait + Live Impersonation (CRITICAL RISK / REJECTED)
4. Genuine Aadhaar Card with Verhoeff Checksum & Secure QR (LOW RISK / VERIFIED)
5. Genuine PAN Card with Income Tax Department Format (LOW RISK / VERIFIED)
"""
import sys
from pathlib import Path
from PIL import Image

from app.config import SAMPLE_DOCS_DIR
from app.pipeline.screening_pipeline import run_truthlens_screening


def run_tests():
    print("=" * 70)
    print("TRUTHLENS BORDER SCREENING PIPELINE VERIFICATION SUITE")
    print("=" * 70)

    test_cases = [
        {
            "name": "Scenario 1: Genuine Passport + Live Face Match",
            "file": SAMPLE_DOCS_DIR / "demo_passport_genuine.jpg",
            "live_file": SAMPLE_DOCS_DIR / "demo_person_live_match.jpg",
            "expected_verdict": "VERIFIED / LOW RISK",
            "max_risk": 29
        },
        {
            "name": "Scenario 2: Expired Visa (Watchlist Overstay Flag)",
            "file": SAMPLE_DOCS_DIR / "demo_visa_expired.jpg",
            "live_file": None,
            "expected_verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
            "min_risk": 60
        },
        {
            "name": "Scenario 3: Tampered Passport + Face Impersonation",
            "file": SAMPLE_DOCS_DIR / "demo_passport_tampered.jpg",
            "live_file": SAMPLE_DOCS_DIR / "demo_person_live_mismatch.jpg",
            "expected_verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
            "min_risk": 60
        },
        {
            "name": "Scenario 4: Genuine Aadhaar Card (Verhoeff Checksum)",
            "file": SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg",
            "live_file": None,
            "expected_verdict": "VERIFIED / LOW RISK",
            "max_risk": 29
        },
        {
            "name": "Scenario 5: Genuine PAN Card (ITD Entity Code)",
            "file": SAMPLE_DOCS_DIR / "sample_genuine_pan.jpg",
            "live_file": None,
            "expected_verdict": "VERIFIED / LOW RISK",
            "max_risk": 29
        }
    ]

    passed_count = 0

    for tc in test_cases:
        print(f"\n[TESTING] {tc['name']}...")
        if not tc["file"].exists():
            print(f"  [FAIL] File not found: {tc['file']}")
            continue

        doc_img = Image.open(tc["file"])
        live_img = Image.open(tc["live_file"]) if tc["live_file"] and tc["live_file"].exists() else None

        result = run_truthlens_screening(doc_img, live_image_input=live_img)

        verdict = result["verdict"]
        score = result["risk_score"]
        level = result["risk_level"]
        elapsed = result["elapsed_ms"]

        print(f"  Verdict: {verdict} | Risk Score: {score}/100 ({level}) in {elapsed}ms")
        print(f"  Summary: {result['summary']}")
        print(f"  Officer Rec: {result['officer_recommendation']}")
        print(f"  Face Verification: {result['face_verification'].get('verdict')} (Match: {result['face_verification'].get('match_percentage')}%)")
        print(f"  ELA Tamper Index: {result['forensics_ela']['tamper_score']}% ({result['forensics_ela']['status_label']})")

        # Verify expectations
        is_passed = True
        if verdict != tc["expected_verdict"]:
            is_passed = False
            print(f"  [FAIL] Verdict mismatch! Expected '{tc['expected_verdict']}', got '{verdict}'")

        if "max_risk" in tc and score > tc["max_risk"]:
            is_passed = False
            print(f"  [FAIL] Risk score {score} exceeded max allowed {tc['max_risk']}")

        if "min_risk" in tc and score < tc["min_risk"]:
            is_passed = False
            print(f"  [FAIL] Risk score {score} below minimum expected {tc['min_risk']}")

        if is_passed:
            passed_count += 1
            print(f"  >>> PASS: Scenario '{tc['name']}' verified successfully! <<<")

    print("\n" + "=" * 70)
    print(f"VERIFICATION COMPLETED: {passed_count}/{len(test_cases)} SCENARIOS PASSED")
    print("=" * 70)
    return passed_count == len(test_cases)


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
