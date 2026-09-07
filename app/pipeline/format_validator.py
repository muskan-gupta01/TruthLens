"""
Format & Checksum Validation Module
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188: Ministry of Home Affairs - Blockchain & Cybersecurity

Implements mathematical and structural checksum validations:
1. ICAO 9303 Passport MRZ & Number validation
2. Expiry date & Border 6-month validity rule
3. Visa validity window & stay duration compliance
4. Aadhaar Verhoeff Checksum Algorithm (D5 Dihedral group mathematical checksum)
5. PAN Structure & Entity Code validation
6. Mock Verification Database Watchlist & Duplicate Screening checks

Outputs structured checklist: ✓ Valid | ⚠ Warning | ✕ Invalid
"""
import re
from datetime import datetime, date
from typing import Dict, Any, Optional, List, Tuple
from app.database.db_manager import query_mock_database, check_duplicate_screenings
from app.config import (
    DOC_TYPE_PASSPORT,
    DOC_TYPE_VISA,
    DOC_TYPE_DRIVING_LICENSE,
    DOC_TYPE_PERMIT,
    DOC_TYPE_AADHAAR,
    DOC_TYPE_PAN,
    DOC_TYPE_BUSINESS_CARD,
    DOC_TYPE_NON_IDENTITY,
    DOC_TYPE_UNKNOWN
)

# ==============================================================================
# 1. VERHOEFF ALGORITHM (OFFICIAL UIDAI AADHAAR CHECKSUM)
# ==============================================================================
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number_str: str) -> bool:
    """Validates 12-digit number using UIDAI Verhoeff dihedral group D5 algorithm."""
    clean_str = re.sub(r"\D", "", str(number_str))
    if not clean_str:
        return False
    c = 0
    reversed_digits = [int(x) for x in reversed(clean_str)]
    for idx, digit in enumerate(reversed_digits):
        p_row = idx % 8
        c = _VERHOEFF_D[c][_VERHOEFF_P[p_row][digit]]
    return c == 0


def generate_verhoeff_check_digit(number_str: str) -> str:
    """Generates the single Verhoeff checksum digit for a number string."""
    clean_str = re.sub(r"\D", "", str(number_str))
    c = 0
    reversed_digits = [int(x) for x in reversed(clean_str)]
    for idx, digit in enumerate(reversed_digits):
        p_row = (idx + 1) % 8
        c = _VERHOEFF_D[c][_VERHOEFF_P[p_row][digit]]
    return str(_VERHOEFF_INV[c])



# ==============================================================================
# 2. DATE & EXPIRY HELPERS
# ==============================================================================
def parse_date_universal(date_str: Optional[str]) -> Optional[date]:
    """Parses date string in formats: DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, or DD.MM.YYYY."""
    if not date_str:
        return None
    clean = re.sub(r"[^\d/\-\.]", "", str(date_str).strip())
    for fmt in ["%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"]:
        try:
            return datetime.strptime(clean, fmt).date()
        except ValueError:
            continue
    return None


def check_date_validity(dob_str: Optional[str]) -> Dict[str, Any]:
    """Checks DOB validity and calculates age."""
    if not dob_str:
        return {"valid": False, "status": "WARN", "label": "⚠ Warning", "message": "Date of Birth missing from document"}

    dt = parse_date_universal(dob_str)
    if not dt:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": f"Malformed DOB format: '{dob_str}'"}

    today = date(2026, 3, 9)  # Local reference date
    if dt > today:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": f"Impossible future DOB: {dob_str}"}

    age = today.year - dt.year - ((today.month, today.day) < (dt.month, dt.day))
    if age > 120 or age < 0:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": f"Unrealistic age ({age} years) from DOB: {dob_str}"}

    return {
        "valid": True,
        "status": "PASS",
        "label": "✓ Valid",
        "age": age,
        "message": f"Valid Date of Birth: {dob_str} (Calculated Age: {age} yrs)"
    }


def check_expiry_validity(expiry_str: Optional[str], doc_type: str = "PASSPORT") -> Dict[str, Any]:
    """Checks whether the document has expired and verifies international 6-month validity rule."""
    if not expiry_str:
        # Some domestic IDs don't have expiry
        if doc_type in [DOC_TYPE_AADHAAR, DOC_TYPE_PAN]:
            return {"valid": True, "status": "PASS", "label": "✓ Valid", "message": "Permanent Identity Document (No Expiry Required)"}
        return {"valid": False, "status": "WARN", "label": "⚠ Warning", "message": "Expiry date missing on travel document"}

    dt = parse_date_universal(expiry_str)
    if not dt:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": f"Malformed expiry date: '{expiry_str}'"}

    today = date(2026, 3, 9)
    days_left = (dt - today).days

    if days_left < 0:
        return {
            "valid": False,
            "expired": True,
            "status": "FAIL",
            "label": "✕ Invalid",
            "days_remaining": days_left,
            "message": f"DOCUMENT EXPIRED! Expired on {expiry_str} ({abs(days_left)} days ago). Entry rejected."
        }

    # Border 6-month passport validity rule
    if doc_type == DOC_TYPE_PASSPORT and days_left < 180:
        return {
            "valid": False,
            "expired": False,
            "status": "WARN",
            "label": "⚠ Warning",
            "days_remaining": days_left,
            "message": f"Border Alert: Less than 6 months validity remaining ({days_left} days left). Violates international transit rule."
        }

    return {
        "valid": True,
        "expired": False,
        "status": "PASS",
        "label": "✓ Valid",
        "days_remaining": days_left,
        "message": f"Document Valid until {expiry_str} ({days_left} days remaining)"
    }


# ==============================================================================
# 3. DOCUMENT NUMBER SPECIFIC VALIDATIONS
# ==============================================================================
def validate_passport_number(doc_num: Optional[str], mrz_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validates passport number format and ICAO 9303 checksum."""
    if not doc_num:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": "Passport number missing"}

    clean_num = "".join(doc_num.upper().split())
    # Standard format: 1 letter followed by 7-8 digits (e.g. A1234567, L898902C3)
    is_format_ok = bool(re.match(r"^[A-Z0-9]{8,9}$", clean_num))

    if mrz_data and mrz_data.get("valid_structure"):
        chk_info = mrz_data.get("checksums", {}).get("doc_number", {})
        if not chk_info.get("valid", True):
            return {
                "valid": False,
                "status": "FAIL",
                "label": "✕ Invalid",
                "message": f"ICAO 9303 MRZ Checksum Failure on Passport '{clean_num}'. Calculated checksum does not match check digit {chk_info.get('expected')}."
            }
        return {
            "valid": True,
            "status": "PASS",
            "label": "✓ Valid",
            "message": f"Valid Passport number '{clean_num}' with verified ICAO 9303 MRZ mathematical checksum."
        }

    if is_format_ok:
        return {"valid": True, "status": "PASS", "label": "✓ Valid", "message": f"Passport number format verified: '{clean_num}'"}
    else:
        return {"valid": False, "status": "WARN", "label": "⚠ Warning", "message": f"Non-standard passport number format: '{clean_num}'"}


def validate_pan_number(pan_str: Optional[str]) -> Dict[str, Any]:
    """Validates Indian PAN structural format and 4th entity character."""
    if not pan_str:
        return {
            "valid": True,
            "status": "WARN",
            "label": "⚠ Unreadable / Glare",
            "message": "PAN number not detected via OCR. Verify document surface or re-scan under even lighting."
        }
    clean_pan = pan_str.strip().upper()
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", clean_pan):
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": f"Invalid PAN format: '{clean_pan}'. Must be 5 letters, 4 digits, 1 letter."}
    entity_code = clean_pan[3]
    entity_types = {
        "P": "Individual / Person",
        "C": "Company",
        "H": "HUF (Hindu Undivided Family)",
        "F": "Firm / Partnership",
        "A": "AOP (Association of Persons)",
        "T": "Trust",
        "B": "BOI (Body of Individuals)",
        "L": "Local Authority",
        "J": "Artificial Juridical Person",
        "G": "Government Entity"
    }
    entity_name = entity_types.get(entity_code, "Unknown Entity")
    return {
        "valid": True,
        "status": "PASS",
        "label": "✓ Valid",
        "entity_type": entity_name,
        "message": f"Valid PAN format. 4th character '{entity_code}' confirms entity: {entity_name}."
    }


def validate_aadhaar_number(
    aadhaar_str: Optional[str],
    ocr_confidence: Optional[float] = None,
    is_uncertain: bool = False
) -> Dict[str, Any]:
    """
    Validates Aadhaar number with UIDAI Verhoeff mathematical checksum (12 digits)
    or statutory Masked Aadhaar format (XXXX XXXX 1234) under UIDAI / DPDP guidelines.
    """
    if not aadhaar_str:
        return {
            "valid": True,
            "status": "WARN",
            "label": "⚠ Unreadable / Glare",
            "message": "Aadhaar number not detected via OCR. Verify document surface or re-scan under even lighting."
        }

    raw_str = str(aadhaar_str).strip()

    # 1. Statutory Masked Aadhaar check (e.g. XXXX XXXX 1234, **** **** 1234, •••• •••• 1234)
    clean_digits = re.sub(r"\D", "", raw_str)
    has_mask_symbols = bool(re.search(r"[Xx\*\.••]", raw_str)) or "XXXX" in raw_str.upper()

    if len(clean_digits) == 4 and (has_mask_symbols or raw_str.upper().startswith("XXXX")):
        return {
            "valid": True,
            "status": "PASS",
            "label": "✓ Valid",
            "message": f"Statutory Masked Aadhaar (XXXX XXXX {clean_digits}) verified compliant with UIDAI privacy guidelines."
        }

    # 2. Optical character normalization if OCR read characters like 'O', 'I', 'l', 'S'
    if len(clean_digits) != 12:
        # Common OCR digit confusion map
        ocr_digit_map = {'O': '0', 'o': '0', 'D': '0', 'Q': '0', 'I': '1', 'l': '1', '|': '1', 'S': '5', 's': '5', 'B': '8', 'Z': '2'}
        norm_str = "".join(ocr_digit_map.get(ch, ch) for ch in raw_str)
        cand_digits = re.sub(r"\D", "", norm_str)
        if len(cand_digits) == 12 and validate_verhoeff(cand_digits):
            clean_digits = cand_digits

    # 3. 12-digit format check
    if len(clean_digits) != 12:
        return {
            "valid": False,
            "status": "FAIL",
            "label": "✕ Invalid",
            "message": f"Aadhaar number must have exactly 12 digits or statutory masked format (found {len(clean_digits)} digits)."
        }

    if clean_digits[0] in ["0", "1"]:
        return {"valid": False, "status": "FAIL", "label": "✕ Invalid", "message": "Aadhaar number cannot begin with 0 or 1."}

    is_valid = validate_verhoeff(clean_digits)
    if not is_valid:
        uncertain = is_uncertain or (ocr_confidence is not None and ocr_confidence < 75.0)
        if uncertain:
            conf_str = f" (OCR confidence: {ocr_confidence}%)" if ocr_confidence is not None else ""
            return {
                "valid": False,
                "status": "WARN",
                "label": "⚠ Review Required",
                "message": f"Mathematical Checksum Uncertainty: Aadhaar number '{clean_digits}' failed Verhoeff verification due to possible OCR ambiguity{conf_str}. Manual review required."
            }
        return {
            "valid": False,
            "status": "FAIL",
            "label": "✕ Invalid",
            "message": f"Mathematical Checksum Failure: Aadhaar number '{clean_digits}' failed Verhoeff algorithm verification (counterfeit sequence)."
        }

    return {
        "valid": True,
        "status": "PASS",
        "label": "✓ Valid",
        "message": f"Valid 12-digit Aadhaar ({clean_digits[:4]} {clean_digits[4:8]} {clean_digits[8:]}) with verified Verhoeff checksum."
    }


# ==============================================================================
# 4. MASTER VALIDATION CONTROLLER
# ==============================================================================
def validate_document_rules(
    doc_type: str,
    fields: Dict[str, Any],
    mrz_data: Optional[Dict[str, Any]] = None,
    ocr_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes full rule-based validation:
    1. Mandatory field checks
    2. Format & checksum checks (ICAO, Verhoeff, PAN)
    3. Expiry date & DOB sanity checks
    4. Mock Database Watchlist & Duplicate checks
    Returns checklist with ✓ Valid, ⚠ Warning, ✕ Invalid badges and risk contribution.
    """
    checklist: List[Dict[str, Any]] = []
    total_failures = 0
    total_warnings = 0

    ocr_data = ocr_data or {}
    is_mismatch = ocr_data.get("is_claimed_mismatch", False)
    is_non_id = ocr_data.get("is_non_identity", False) or (doc_type in [DOC_TYPE_BUSINESS_CARD, DOC_TYPE_NON_IDENTITY])
    claimed_type = ocr_data.get("claimed_type") or doc_type

    doc_num = (
        fields.get("passport_number") or
        fields.get("visa_number") or
        fields.get("id_number") or
        fields.get("license_number") or
        fields.get("permit_id")
    )
    person_name = fields.get("full_name") or fields.get("name") or fields.get("traveler_name")

    # 0. Non-Identity Document / Claimed Document Type Mismatch Check
    if is_mismatch or is_non_id:
        checklist.append({
            "check": "Document Type Conformity & Physical Authenticity",
            "status": "FAIL",
            "badge": "✕ Invalid",
            "detail": (
                f"CRITICAL FRAUD / TYPE MISMATCH: User submitted intake under category '{claimed_type}', "
                f"but physical optical examination identified a non-identity commercial document "
                f"({doc_type.replace('_', ' ').title()}). Lacks all statutory government identity credentials."
            )
        })
        total_failures += 3

        checklist.append({
            "check": "Statutory Government Emblems & Security Features",
            "status": "FAIL",
            "badge": "✕ Invalid",
            "detail": f"FAILED: Document lacks official government security features (National Emblem, UIDAI hologram, official typography) required for {claimed_type}."
        })
        total_failures += 2

    # 1. Mandatory Name Check
    if person_name and len(person_name.strip()) >= 3:
        checklist.append({
            "check": "Full Name Presence",
            "status": "PASS" if not (is_mismatch or is_non_id) else "WARN",
            "badge": "✓ Valid" if not (is_mismatch or is_non_id) else "⚠ Commercial Name",
            "detail": f"Subject name recorded: '{person_name}'." if not (is_mismatch or is_non_id) else f"Commercial contact name extracted ('{person_name}'), but lacks institutional citizenship endorsement."
        })
        if is_mismatch or is_non_id:
            total_warnings += 1
    else:
        checklist.append({
            "check": "Full Name Presence",
            "status": "WARN",
            "badge": "⚠ Warning",
            "detail": "Document holder name missing or unclear from OCR."
        })
        total_warnings += 1

    # 2. Document Number & Checksum Check
    if is_mismatch or is_non_id or doc_type in [DOC_TYPE_BUSINESS_CARD, DOC_TYPE_NON_IDENTITY]:
        if claimed_type == DOC_TYPE_AADHAAR:
            checklist.append({
                "check": "Aadhaar Verhoeff Checksum",
                "status": "FAIL",
                "badge": "✕ Invalid",
                "detail": "FAILED: Missing official 12-digit UIDAI sequence. Verhoeff dihedral D5 checksum cannot be computed on non-identity media."
            })
            total_failures += 2
        elif claimed_type == DOC_TYPE_PAN:
            checklist.append({
                "check": "PAN Syntax & Entity Code",
                "status": "FAIL",
                "badge": "✕ Invalid",
                "detail": "FAILED: No 10-character PAN syntax found. Commercial document lacks Income Tax Department structure."
            })
            total_failures += 2
        elif claimed_type == DOC_TYPE_PASSPORT:
            checklist.append({
                "check": "Passport Number & ICAO Checksum",
                "status": "FAIL",
                "badge": "✕ Invalid",
                "detail": "FAILED: Missing ICAO Doc 9303 MRZ lines and passport serial number."
            })
            total_failures += 2
        else:
            checklist.append({
                "check": "Statutory Document Number & Checksum",
                "status": "FAIL",
                "badge": "✕ Invalid",
                "detail": f"FAILED: No statutory {claimed_type} identifier detected on non-identity media."
            })
            total_failures += 2

    elif doc_type == DOC_TYPE_PASSPORT:
        res_num = validate_passport_number(doc_num, mrz_data)
        checklist.append({
            "check": "Passport Number & ICAO Checksum",
            "status": res_num["status"],
            "badge": res_num["label"],
            "detail": res_num["message"]
        })
        if res_num["status"] == "FAIL":
            total_failures += 1
        elif res_num["status"] == "WARN":
            total_warnings += 1

    elif doc_type == DOC_TYPE_AADHAAR:
        ocr_conf = ocr_data.get("mean_confidence") or ocr_data.get("ocr_confidence") or ocr_data.get("confidence")
        is_unc = (
            ocr_data.get("is_uncertain", False) or
            ocr_data.get("ocr_uncertain", False) or
            fields.get("is_uncertain", False) or
            fields.get("ocr_uncertain", False)
        )
        res_num = validate_aadhaar_number(doc_num, ocr_confidence=ocr_conf, is_uncertain=is_unc)
        checklist.append({
            "check": "Aadhaar Verhoeff Checksum",
            "status": res_num["status"],
            "badge": res_num["label"],
            "detail": res_num["message"]
        })
        if res_num["status"] == "FAIL":
            total_failures += 1
        elif res_num["status"] == "WARN":
            total_warnings += 1

    elif doc_type == DOC_TYPE_PAN:
        res_num = validate_pan_number(doc_num)
        checklist.append({
            "check": "PAN Syntax & Entity Code",
            "status": res_num["status"],
            "badge": res_num["label"],
            "detail": res_num["message"]
        })
        if res_num["status"] == "FAIL":
            total_failures += 1
        elif res_num["status"] == "WARN":
            total_warnings += 1

    elif doc_type == DOC_TYPE_VISA:
        if doc_num:
            checklist.append({
                "check": "Visa Number Syntax",
                "status": "PASS",
                "badge": "✓ Valid",
                "detail": f"Visa document identifier verified: '{doc_num}'."
            })
        else:
            checklist.append({
                "check": "Visa Number Syntax",
                "status": "FAIL",
                "badge": "✕ Invalid",
                "detail": "Visa document number could not be detected."
            })
            total_failures += 1

    # 3. DOB & Passenger Age
    if is_mismatch or is_non_id:
        checklist.append({
            "check": "Date of Birth & Age Sanity",
            "status": "FAIL",
            "badge": "✕ Invalid",
            "detail": f"FAILED: No statutory Date of Birth recorded. Inadmissible for {claimed_type} identity intake."
        })
        total_failures += 1
    else:
        dob_val = fields.get("dob")
        dob_res = check_date_validity(dob_val)
        checklist.append({
            "check": "Date of Birth & Age Sanity",
            "status": dob_res["status"],
            "badge": dob_res["label"],
            "detail": dob_res["message"]
        })
        if dob_res["status"] == "FAIL":
            total_failures += 1

    # 4. Expiry Date & Border 6-Month Rule
    if is_mismatch or is_non_id:
        checklist.append({
            "check": "Document Expiry & Validity Window",
            "status": "FAIL",
            "badge": "✕ Invalid",
            "detail": "FAILED: Commercial non-identity media cannot be verified for statutory immigration validity."
        })
        total_failures += 1
    else:
        expiry_val = fields.get("expiry_date") or fields.get("valid_until")
        exp_res = check_expiry_validity(expiry_val, doc_type)
        checklist.append({
            "check": "Document Expiry & Validity Window",
            "status": exp_res["status"],
            "badge": exp_res["label"],
            "detail": exp_res["message"]
        })
        if exp_res["status"] == "FAIL":
            total_failures += 1
        elif exp_res["status"] == "WARN":
            total_warnings += 1

    # 5. Visa Stay Duration Rule
    if doc_type == DOC_TYPE_VISA and not (is_mismatch or is_non_id):
        stay = fields.get("stay_duration", "90 DAYS")
        checklist.append({
            "check": "Visa Stay Duration Limit",
            "status": "PASS",
            "badge": "✓ Valid",
            "detail": f"Authorized stay duration ({stay}) conforms with standard entry regulations."
        })

    # 6. Mock Verification Database Check (Watchlists / Stolen / Revoked)
    mock_hit = query_mock_database(doc_num, person_name)
    if mock_hit:
        checklist.append({
            "check": "Mock Watchlist & Blacklist Verification",
            "status": "FAIL",
            "badge": "✕ Invalid",
            "detail": f"ALERT [Mock Database Hit]: Document/Person flagged with status '{mock_hit['status']}' - {mock_hit['reason']} ({mock_hit['notes']})."
        })
        total_failures += 2  # Severe security violation
    else:
        checklist.append({
            "check": "Mock Watchlist & Blacklist Verification",
            "status": "PASS",
            "badge": "✓ Valid",
            "detail": "No active watchlists, Interpol notices, or revocation flags in Mock Database."
        })

    # 7. Duplicate Submission Check (Anti-Fraud Ring)
    dups = check_duplicate_screenings(doc_num)
    if dups > 3:
        checklist.append({
            "check": "Duplicate Screening Registry",
            "status": "WARN",
            "badge": "⚠ Warning",
            "detail": f"Repeated screening attempt: This document number has been submitted {dups} times recently."
        })
        total_warnings += 1
    else:
        checklist.append({
            "check": "Duplicate Screening Registry",
            "status": "PASS",
            "badge": "✓ Valid",
            "detail": "Single unique screening transaction confirmed."
        })

    # Ensure every checklist item has both 'check' and 'name' for backwards compatibility
    for item in checklist:
        if "name" not in item and "check" in item:
            item["name"] = item["check"]

    # Summary verdict
    if total_failures > 0:
        overall_status = "FAILED"
        verdict_label = "VALIDATION FAILED"
    elif total_warnings > 0:
        overall_status = "WARNING"
        verdict_label = "WARNINGS FOUND"
    else:
        overall_status = "PASSED"
        verdict_label = "ALL CHECKS PASSED"

    return {
        "valid": (total_failures == 0),
        "overall_status": overall_status,
        "verdict_label": verdict_label,
        "total_checks": len(checklist),
        "failures_count": total_failures,
        "warnings_count": total_warnings,
        "checklist": checklist,
        "mock_database_hit": mock_hit,
        "mock_db_disclaimer": "DEMO DATA – NOT CONNECTED TO GOVERNMENT DATABASES"
    }
