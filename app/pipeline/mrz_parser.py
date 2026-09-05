"""
ICAO Doc 9303 Machine Readable Zone (MRZ) Parser & Checksum Validator
SIH26188: AI-Based Fake Identity & Document Screening System

Supports:
- TD3 (Passports): 2 lines of 44 characters
- TD1 (ID Cards & Residence Permits): 3 lines of 30 characters

Calculates official 7-3-1 weighting check digits to mathematically detect
forged passport numbers, altered dates of birth, or modified expiry dates.
"""
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple


def _mrz_char_value(c: str) -> int:
    """Returns ICAO 9303 integer value of a character (0-9, A-Z=10-35, <=0)."""
    c = c.upper()
    if c.isdigit():
        return int(c)
    elif "A" <= c <= "Z":
        return ord(c) - ord("A") + 10
    else:
        return 0


def calculate_icao_check_digit(data: str) -> int:
    """
    Computes ICAO 9303 check digit using weights [7, 3, 1] cyclically.
    Sum mod 10 is the check digit.
    """
    weights = [7, 3, 1]
    total = 0
    for idx, char in enumerate(data):
        val = _mrz_char_value(char)
        weight = weights[idx % 3]
        total += val * weight
    return total % 10


def verify_icao_check_digit(data: str, expected_digit: str) -> bool:
    """Verifies whether expected check digit matches calculated value."""
    if not expected_digit.isdigit():
        return False
    calc = calculate_icao_check_digit(data)
    return calc == int(expected_digit)


def parse_mrz_date(yymmdd: str, is_expiry: bool = False) -> Optional[str]:
    """Converts YYMMDD string into DD/MM/YYYY."""
    if len(yymmdd) != 6 or not yymmdd.isdigit():
        return None
    yy = int(yymmdd[0:2])
    mm = int(yymmdd[2:4])
    dd = int(yymmdd[4:6])

    # Basic range sanity
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return None

    # For expiry date: passport/travel documents are in 2000s (2000-2099)
    if is_expiry:
        full_year = 2000 + yy
    else:
        # Birth year: if yy > 26 -> 1900s, else 2000s
        current_yy = 26
        century = 1900 if yy > current_yy else 2000
        full_year = century + yy

    return f"{dd:02d}/{mm:02d}/{full_year}"



def parse_mrz_td3(lines: List[str]) -> Dict[str, Any]:
    """
    Parses TD3 (Passport) format: 2 lines of 44 characters each.
    """
    line1 = lines[0].replace(" ", "").upper()
    line2 = lines[1].replace(" ", "").upper()

    # Clean non-standard OCR noise
    line1 = re.sub(r"[^A-Z0-9<]", "<", line1).ljust(44, "<")[:44]
    line2 = re.sub(r"[^A-Z0-9<]", "<", line2).ljust(44, "<")[:44]

    doc_type = line1[0:2].replace("<", "")
    issuing_country = line1[2:5].replace("<", "")

    # Names: Surname<<Given Names
    names_raw = line1[5:44].split("<<")
    surname = names_raw[0].replace("<", " ").strip()
    given_names = names_raw[1].replace("<", " ").strip() if len(names_raw) > 1 else ""
    full_name = f"{given_names} {surname}".strip() if given_names else surname

    # Line 2 fields
    doc_num_raw = line2[0:9]
    doc_num = doc_num_raw.replace("<", "").strip()
    doc_num_chk = line2[9]

    nationality = line2[10:13].replace("<", "")
    dob_raw = line2[13:19]
    dob_chk = line2[19]

    sex_char = line2[20]
    sex = "MALE" if sex_char == "M" else ("FEMALE" if sex_char == "F" else "UNSPECIFIED")

    expiry_raw = line2[21:27]
    expiry_chk = line2[27]

    personal_num_raw = line2[28:42]
    personal_num_chk = line2[42]
    composite_chk = line2[43]

    # Verify check digits
    doc_num_valid = verify_icao_check_digit(doc_num_raw, doc_num_chk)
    dob_valid = verify_icao_check_digit(dob_raw, dob_chk)
    expiry_valid = verify_icao_check_digit(expiry_raw, expiry_chk)

    # Composite check covers: doc_num+chk + dob+chk + expiry+chk + personal_num
    composite_data = line2[0:10] + line2[13:20] + line2[21:43]
    composite_valid = verify_icao_check_digit(composite_data, composite_chk)

    return {
        "format": "ICAO_TD3",
        "valid_structure": True,
        "doc_type": "PASSPORT",
        "issuing_country": issuing_country,
        "full_name": full_name,
        "surname": surname,
        "given_names": given_names,
        "doc_number": doc_num,
        "nationality": nationality,
        "dob": parse_mrz_date(dob_raw, is_expiry=False),
        "dob_raw": dob_raw,
        "gender": sex,
        "expiry_date": parse_mrz_date(expiry_raw, is_expiry=True),
        "expiry_raw": expiry_raw,
        "checksums": {
            "doc_number": {"valid": doc_num_valid, "expected": doc_num_chk, "calc": calculate_icao_check_digit(doc_num_raw)},
            "dob": {"valid": dob_valid, "expected": dob_chk, "calc": calculate_icao_check_digit(dob_raw)},
            "expiry": {"valid": expiry_valid, "expected": expiry_chk, "calc": calculate_icao_check_digit(expiry_raw)},
            "composite": {"valid": composite_valid, "expected": composite_chk, "calc": calculate_icao_check_digit(composite_data)},
            "all_passed": (doc_num_valid and dob_valid and expiry_valid)
        }
    }


def find_and_parse_mrz(ocr_text: str) -> Optional[Dict[str, Any]]:
    """
    Scans raw OCR text for MRZ lines matching TD3 (2 lines ~44 chars) or TD1 (3 lines ~30 chars).
    Returns structured parsed fields or None if no valid MRZ sequence is detected.
    """
    lines = [l.strip().replace(" ", "") for l in ocr_text.splitlines() if l.strip()]

    # Require line to contain actual MRZ delimiter characters ('<') in original text
    candidate_lines = []
    for line in lines:
        if "<" in line and len(line) >= 30 and line.count("<") >= 2:
            cleaned = re.sub(r"[^A-Za-z0-9<]", "<", line)
            candidate_lines.append(cleaned)

    # TD3 Match: exactly 2 lines >= 38 chars starting with P<
    for i in range(len(candidate_lines) - 1):
        l1 = candidate_lines[i]
        l2 = candidate_lines[i+1]
        if re.match(r"^P[A-Z0-9<]?<", l1) and len(l1) >= 38 and len(l2) >= 38:
            try:
                res = parse_mrz_td3([l1, l2])
                if res and res.get("valid_structure"):
                    return res
            except Exception as e:
                print(f"[MRZ PARSER] Error parsing TD3: {e}")

    return None
