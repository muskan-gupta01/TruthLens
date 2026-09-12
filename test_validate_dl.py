"""
TruthLens Indian Driving License (DL) Validation Test Suite
SIH26188: AI-Based Fake Identity & Document Screening System
Ministry of Home Affairs - Blockchain & Cybersecurity

Unit tests for validate_dl():
1. Valid DL with hyphen format (SS-RRYYYYNNNNNNN)
2. Valid DL with space format (SSRR YYYYNNNNNNN)
3. Normalization of inconsistent spacing/hyphens
4. Invalid State Code (e.g. XX)
5. Malformed regex structure
6. Future issue year sanity check
7. Pre-1980 issue year sanity check
8. Underage holder at issue date (< 18 yrs)
9. Valid age holder at issue date (>= 18 yrs)
10. Missing / unreadable DOB handled gracefully (not failed)
11. Expired DL flag
12. Active / unexpired DL
13. Empty or unreadable DL string
"""
import sys
from datetime import date
from app.pipeline.format_validator import validate_dl, validate_dl_number, validate_driving_license
from app.pipeline.dl_state_codes import VALID_STATE_CODES


def test_valid_dl_hyphen_format():
    """Valid standard format with hyphen: DL-0420180012345."""
    res = validate_dl("DL-0420180012345", dob="12/05/1990", expiry_date="14/06/2038")
    assert res["valid"] is True
    assert res["is_valid"] is True
    assert res["status"] == "PASS"
    assert res["state_code"] == "DL"
    assert res["state_name"] == "Delhi"
    assert res["rto_code"] == "04"
    assert res["issue_year"] == 2018
    assert res["serial_number"] == "0012345"
    assert res["expired"] is False
    assert len(res["failure_reasons"]) == 0


def test_valid_dl_space_format():
    """Valid standard format with space: MH02 20190054321."""
    res = validate_dl("MH02 20190054321", dob="20/10/1995", expiry_date="19/10/2039")
    assert res["valid"] is True
    assert res["is_valid"] is True
    assert res["status"] == "PASS"
    assert res["state_code"] == "MH"
    assert res["state_name"] == "Maharashtra"
    assert res["rto_code"] == "02"
    assert res["issue_year"] == 2019
    assert res["serial_number"] == "0054321"
    assert res["expired"] is False


def test_valid_dl_normalization():
    """Inputs with irregular spacing/hyphens are normalized into standard format."""
    # Both hyphen and space
    res1 = validate_dl("DL-04 20180012345")
    assert res1["valid"] is True
    assert res1["state_code"] == "DL"

    # No separator: 15 alphanumeric characters
    res2 = validate_dl("KA0120170098765")
    assert res2["valid"] is True
    assert res2["state_code"] == "KA"
    assert res2["state_name"] == "Karnataka"

    # Lowercase input
    res3 = validate_dl("up14 20200012345")
    assert res3["valid"] is True
    assert res3["state_code"] == "UP"
    assert res3["state_name"] == "Uttar Pradesh"


def test_invalid_state_code():
    """State code XX is not in VALID_STATE_CODES."""
    res = validate_dl("XX-0420180012345")
    assert res["valid"] is False
    assert res["is_valid"] is False
    assert res["status"] == "FAIL"
    assert any("Invalid state code" in reason for reason in res["failure_reasons"])


def test_malformed_regex():
    """Malformed syntax must be rejected."""
    # Too short
    r_short = validate_dl("DL-04201800123")
    assert r_short["valid"] is False
    assert r_short["status"] == "FAIL"

    # Too long
    r_long = validate_dl("DL-042018001234567")
    assert r_long["valid"] is False

    # Non-digit year
    r_bad_yr = validate_dl("DL-04ABCD0012345")
    assert r_bad_yr["valid"] is False

    # 1-letter state
    r_1_letter = validate_dl("D-0420180012345")
    assert r_1_letter["valid"] is False

    # Random string
    r_rand = validate_dl("NOT_A_DRIVING_LICENSE")
    assert r_rand["valid"] is False


def test_future_year():
    """Issue year cannot be in the future."""
    res = validate_dl("DL-0420350012345", current_year=2026)
    assert res["valid"] is False
    assert res["status"] == "FAIL"
    assert any("future" in r.lower() for r in res["failure_reasons"])


def test_pre_1980_year():
    """Issue year cannot predate 1980."""
    res = validate_dl("DL-0419750012345")
    assert res["valid"] is False
    assert res["status"] == "FAIL"
    assert any("1980" in r for r in res["failure_reasons"])


def test_age_underage():
    """Holder under 18 at issue date must fail."""
    # DOB: 2005, Issue Year: 2018 -> Age: 13
    res = validate_dl("DL-0420180012345", dob="15/06/2005")
    assert res["valid"] is False
    assert res["status"] == "FAIL"
    assert any("Underage" in r for r in res["failure_reasons"])


def test_age_valid():
    """Holder >= 18 at issue date must pass."""
    # DOB: 1995, Issue Year: 2018 -> Age: 23
    res = validate_dl("DL-0420180012345", dob="15/06/1995")
    assert res["valid"] is True
    assert res["status"] == "PASS"
    assert res["extracted_fields"].get("age_at_issue") == 23


def test_missing_dob_graceful():
    """Missing or unparseable DOB should be skipped gracefully without failing."""
    res = validate_dl("DL-0420180012345", dob=None)
    assert res["valid"] is True
    assert res["status"] == "PASS"
    age_check = next((c for c in res["checks_performed"] if "Age" in c["check"]), None)
    assert age_check is not None
    assert age_check["status"] == "WARN"


def test_expired_dl():
    """Expired DL must flag expired=True."""
    # Past expiry date
    res = validate_dl("DL-0420100012345", dob="12/05/1985", expiry_date="14/06/2020")
    assert res["expired"] is True
    assert res["status"] == "WARN"
    assert res["label"] == "⚠ Expired"


def test_active_dl():
    """Active unexpired DL must have expired=False."""
    res = validate_dl("DL-0420180012345", dob="12/05/1990", expiry_date="14/06/2038")
    assert res["expired"] is False
    assert res["status"] == "PASS"


def test_empty_or_none_dl():
    """Empty or None DL number returns unreadable/glare warning."""
    r_none = validate_dl(None)
    assert r_none["status"] == "WARN"
    assert r_none["valid"] is True

    r_empty = validate_dl("")
    assert r_empty["status"] == "WARN"
    assert r_empty["valid"] is True


def test_aliases():
    """validate_dl_number and validate_driving_license aliases work identically."""
    r1 = validate_dl("DL-0420180012345")
    r2 = validate_dl_number("DL-0420180012345")
    r3 = validate_driving_license("DL-0420180012345")
    assert r1 == r2 == r3


def run_tests():
    print("=" * 70)
    print("TRUTHLENS DRIVING LICENSE (DL) VALIDATOR TEST SUITE")
    print("=" * 70)
    tests = [
        ("Valid DL Hyphen Format", test_valid_dl_hyphen_format),
        ("Valid DL Space Format", test_valid_dl_space_format),
        ("DL Input Normalization", test_valid_dl_normalization),
        ("Invalid State Code (XX)", test_invalid_state_code),
        ("Malformed Regex Structure", test_malformed_regex),
        ("Future Year Sanity Check", test_future_year),
        ("Pre-1980 Year Sanity Check", test_pre_1980_year),
        ("Underage Holder Violation", test_age_underage),
        ("Valid Holder Age (>= 18)", test_age_valid),
        ("Graceful Missing DOB Handling", test_missing_dob_graceful),
        ("Expired DL Flag", test_expired_dl),
        ("Active Unexpired DL", test_active_dl),
        ("Empty / None DL Input", test_empty_or_none_dl),
        ("Function Aliases", test_aliases),
    ]

    passed = 0
    for name, test_fn in tests:
        try:
            test_fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")

    print("=" * 70)
    print(f"RESULTS: {passed}/{len(tests)} TESTS PASSED")
    print("=" * 70)
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
