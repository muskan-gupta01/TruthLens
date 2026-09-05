"""
Cross-Verification & Fuzzy Matching Module
TruthLens - AI-Based Fake Identity & Document Screening System

Compares OCR-extracted fields against QR-decoded cryptographic identity records
using token-aware fuzzy string matching and specialized heuristics.
Flags identity discrepancies, altered names, forged ID numbers, or altered dates.
"""
import re
import difflib
from typing import Dict, Any, List, Tuple
from app.config import (
    FUZZY_MATCH_THRESHOLD_PASS,
    FUZZY_MATCH_THRESHOLD_WARN
)

try:
    from thefuzz import fuzz
    HAS_THEFUZZ = True
except ImportError:
    HAS_THEFUZZ = False


def _clean_string(s: str) -> str:
    """Normalizes string for robust comparison (lowercase, trimmed whitespace, no punctuation)."""
    if not s:
        return ""
    cleaned = re.sub(r"[^\w\s]", " ", str(s).lower())
    return " ".join(cleaned.split())


def _clean_digits(s: str) -> str:
    """Extracts only digits from a string."""
    return re.sub(r"\D", "", str(s or ""))


def compute_string_similarity(str1: str, str2: str) -> float:
    """
    Computes percentage similarity (0.0 to 100.0) between two strings.
    Uses token_sort_ratio from thefuzz if available, or difflib SequenceMatcher.
    """
    c1 = _clean_string(str1)
    c2 = _clean_string(str2)

    if not c1 and not c2:
        return 100.0
    if not c1 or not c2:
        return 0.0

    if HAS_THEFUZZ:
        # token_sort_ratio accounts for word order differences (e.g. "Kumar Rajesh" vs "Rajesh Kumar")
        return float(fuzz.token_sort_ratio(c1, c2))
    else:
        matcher = difflib.SequenceMatcher(None, c1, c2)
        return round(matcher.ratio() * 100.0, 1)


def compare_id_numbers(ocr_id: str, qr_id: str) -> Tuple[float, str, str]:
    """
    Compares OCR-detected ID number with QR-embedded ID number.
    Returns: (similarity_score, status, explanation)
    """
    d_ocr = _clean_digits(ocr_id)
    d_qr = _clean_digits(qr_id)

    # If both are alphanumeric (e.g. PAN card)
    if not d_ocr and not d_qr:
        s_ocr = _clean_string(ocr_id).upper()
        s_qr = _clean_string(qr_id).upper()
        if not s_ocr or not s_qr:
            return 0.0, "MISSING", "ID number not detected in both sources."
        sim = compute_string_similarity(s_ocr, s_qr)
        if sim >= 95.0:
            return 100.0, "MATCH", f"ID numbers match perfectly ({s_ocr})."
        return sim, "MISMATCH", f"ID number mismatch: Document reads '{s_ocr}' vs QR record '{s_qr}'."

    if not d_ocr:
        return 0.0, "MISSING", "ID number could not be extracted from document text."
    if not d_qr:
        return 0.0, "MISSING", "ID number missing from QR code payload."

    if d_ocr == d_qr:
        return 100.0, "MATCH", f"ID number matches perfectly ({d_ocr})."
    
    # Statutory UIDAI Privacy Masking - Bidirectional 4-digit vs 12-digit checks:
    # Case A: Document printed full 12 digits, QR stores last 4 digits (UIDAI Secure QR V2 standard)
    if len(d_qr) == 4 and d_ocr.endswith(d_qr):
        return 100.0, "MATCH", f"Verified: Document ID matches UIDAI Secure QR record (last 4 digits: {d_qr})."

    # Case B: Document printed masked with last 4 digits, QR stores full 12 digits (legacy QR)
    if len(d_ocr) == 4 and d_qr.endswith(d_ocr):
        return 100.0, "MATCH", f"Verified: Masked document ID matches last 4 digits ({d_ocr}) of QR record."

    # Case C: Both are masked or partial and match last 4 digits
    if len(d_ocr) >= 4 and len(d_qr) >= 4 and d_ocr[-4:] == d_qr[-4:] and (len(d_ocr) == 4 or len(d_qr) == 4):
        return 100.0, "MATCH", f"Verified: Masked ID matches last 4 digits ({d_ocr[-4:]}) across document and QR."

    sim = compute_string_similarity(d_ocr, d_qr)
    return sim, "MISMATCH", f"CRITICAL: ID number mismatch! Document reads '{d_ocr}' but QR contains '{d_qr}'."


def compare_names(ocr_name: str, qr_name: str, raw_ocr_text: str = "") -> Tuple[float, str, str]:
    """
    Compares printed name on document with name stored in the QR code.
    Also searches raw_ocr_text to ensure OCR field-extraction misses don't cause false alarms.
    Returns: (similarity_score, status, explanation)
    """
    if not qr_name:
        return 0.0, "MISSING", "Name is not present in QR code data."

    # First check direct similarity
    sim = compute_string_similarity(ocr_name, qr_name) if ocr_name else 0.0

    if sim >= FUZZY_MATCH_THRESHOLD_PASS:
        return sim, "MATCH", f"Name verified: '{ocr_name}' matches QR '{qr_name}' ({sim:.0f}% similarity)."
    elif sim >= FUZZY_MATCH_THRESHOLD_WARN:
        return sim, "PARTIAL", f"Minor name variation: Document reads '{ocr_name}', QR reads '{qr_name}' ({sim:.0f}% similarity - possible OCR typo or abbreviation)."

    # If field similarity is low, verify whether the QR name or its core tokens exist in raw_ocr_text
    if raw_ocr_text:
        raw_upper = raw_ocr_text.upper()
        qr_clean = _clean_string(qr_name).upper()
        if qr_clean and qr_clean in raw_upper:
            return 100.0, "MATCH", f"Name verified: QR identity '{qr_name}' confirmed present on physical document surface."

        qr_tokens = [tok for tok in qr_clean.split() if len(tok) >= 3]
        if qr_tokens and all(tok in raw_upper for tok in qr_tokens):
            return 95.0, "MATCH", f"Name verified: All tokens of QR identity '{qr_name}' confirmed on physical document surface."

    if not ocr_name:
        return 0.0, "MISSING", "Name could not be confidently identified by OCR."

    return sim, "MISMATCH", f"CRITICAL: Name mismatch! Document printed name '{ocr_name}' conflicts with QR identity '{qr_name}' ({sim:.0f}% similarity)."


def compare_dates(ocr_dob: str, qr_dob: str) -> Tuple[float, str, str]:
    """
    Compares Date of Birth / Year of Birth between OCR and QR code.
    Handles DD/MM/YYYY vs YYYY formats gracefully.
    """
    if not ocr_dob:
        return 0.0, "MISSING", "DOB not detected on document face."
    if not qr_dob:
        return 0.0, "MISSING", "DOB not encoded in QR code."

    # Direct match check
    c_ocr = re.sub(r"[^\d]", "", ocr_dob)
    c_qr = re.sub(r"[^\d]", "", qr_dob)

    if c_ocr == c_qr:
        return 100.0, "MATCH", f"DOB matches: {ocr_dob}"

    # Check if one is Year-only (4 digits)
    y_ocr = re.search(r"\b(19\d{2}|20\d{2})\b", ocr_dob)
    y_qr = re.search(r"\b(19\d{2}|20\d{2})\b", qr_dob)

    if y_ocr and y_qr:
        if y_ocr.group(1) == y_qr.group(1):
            return 90.0, "MATCH", f"Birth year verified ({y_ocr.group(1)}). Full string: Doc '{ocr_dob}' vs QR '{qr_dob}'."
        else:
            return 0.0, "MISMATCH", f"CRITICAL: Birth year mismatch! Document indicates '{y_ocr.group(1)}' but QR specifies '{y_qr.group(1)}'."

    sim = compute_string_similarity(ocr_dob, qr_dob)
    if sim >= 80:
        return sim, "MATCH", f"DOB matches with minor format difference: '{ocr_dob}' vs '{qr_dob}'."
    return sim, "MISMATCH", f"DOB mismatch: Document shows '{ocr_dob}', QR contains '{qr_dob}'."


def compare_gender(ocr_gender: str, qr_gender: str) -> Tuple[float, str, str]:
    """
    Compares Gender field.
    """
    if not ocr_gender:
        return 0.0, "MISSING", "Gender not identified on document."
    if not qr_gender:
        return 0.0, "MISSING", "Gender not specified in QR code."

    g_ocr = ocr_gender.upper().strip()
    g_qr = qr_gender.upper().strip()

    # Normalize M -> MALE, F -> FEMALE
    norm = {"M": "MALE", "F": "FEMALE", "MALE": "MALE", "FEMALE": "FEMALE", "TRANSGENDER": "TRANSGENDER"}
    n_ocr = norm.get(g_ocr, g_ocr)
    n_qr = norm.get(g_qr, g_qr)

    if n_ocr == n_qr:
        return 100.0, "MATCH", f"Gender verified: {n_ocr}"
    return 0.0, "MISMATCH", f"Gender mismatch: Document indicates '{n_ocr}', QR indicates '{n_qr}'."


def cross_verify_documents(ocr_data: Dict[str, Any], qr_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cross-verifies all extracted fields from OCR and QR code.
    Returns:
    - verification_matrix: list of field comparisons with scores and statuses
    - overall_match_score: composite similarity score (0-100)
    - has_critical_mismatch: bool
    - reasons: list of human-readable findings
    """
    if not qr_data.get("decoded"):
        return {
            "qr_present": qr_data.get("detected", False),
            "qr_decoded": False,
            "overall_match_score": 0.0,
            "has_critical_mismatch": False,
            "verification_matrix": [],
            "reasons": ["QR code is either missing, unreadable, or not present on document."]
        }

    ocr_fields = ocr_data.get("fields", {})
    qr_fields = qr_data.get("fields", {})

    matrix: List[Dict[str, Any]] = []
    reasons: List[str] = []
    has_critical_mismatch = False
    scores: List[float] = []

    # 1. Compare ID Number (Aadhaar / PAN)
    id_score, id_status, id_exp = compare_id_numbers(
        ocr_fields.get("id_number", ""),
        qr_fields.get("id_number", "")
    )
    matrix.append({
        "field": "ID Number",
        "ocr_val": ocr_fields.get("id_number") or "Not detected",
        "qr_val": qr_fields.get("id_number") or "Not detected",
        "score": id_score,
        "status": id_status,
        "explanation": id_exp
    })
    reasons.append(id_exp)
    if id_status == "MISMATCH":
        has_critical_mismatch = True
    if id_status != "MISSING":
        scores.append(id_score)

    # 2. Compare Name
    raw_ocr = str(ocr_data.get("raw_text") or "")
    name_score, name_status, name_exp = compare_names(
        ocr_fields.get("name", ""),
        qr_fields.get("name", ""),
        raw_ocr_text=raw_ocr
    )
    # If QR name verified on document face via raw text, sync ocr field
    if name_status == "MATCH" and qr_fields.get("name") and not ocr_fields.get("name"):
        ocr_fields["name"] = qr_fields["name"]
    elif name_status == "MATCH" and qr_fields.get("name") and ocr_fields.get("name") != qr_fields.get("name") and "Unique" in str(ocr_fields.get("name")):
        ocr_fields["name"] = qr_fields["name"]

    matrix.append({
        "field": "Name",
        "ocr_val": ocr_fields.get("name") or "Not detected",
        "qr_val": qr_fields.get("name") or "Not detected",
        "score": name_score,
        "status": name_status,
        "explanation": name_exp
    })
    reasons.append(name_exp)
    if name_status == "MISMATCH":
        has_critical_mismatch = True
    if name_status != "MISSING":
        scores.append(name_score)

    # 3. Compare DOB
    dob_score, dob_status, dob_exp = compare_dates(
        ocr_fields.get("dob", ""),
        qr_fields.get("dob", "")
    )
    matrix.append({
        "field": "Date of Birth",
        "ocr_val": ocr_fields.get("dob") or "Not detected",
        "qr_val": qr_fields.get("dob") or "Not detected",
        "score": dob_score,
        "status": dob_status,
        "explanation": dob_exp
    })
    reasons.append(dob_exp)
    if dob_status == "MISMATCH":
        has_critical_mismatch = True
    if dob_status != "MISSING":
        scores.append(dob_score)

    # 4. Compare Gender (if available)
    if ocr_fields.get("gender") or qr_fields.get("gender"):
        gen_score, gen_status, gen_exp = compare_gender(
            ocr_fields.get("gender", ""),
            qr_fields.get("gender", "")
        )
        matrix.append({
            "field": "Gender",
            "ocr_val": ocr_fields.get("gender") or "Not detected",
            "qr_val": qr_fields.get("gender") or "Not detected",
            "score": gen_score,
            "status": gen_status,
            "explanation": gen_exp
        })
        if gen_status == "MISMATCH":
            has_critical_mismatch = True
            reasons.append(gen_exp)
        if gen_status != "MISSING":
            scores.append(gen_score)

    overall_score = round(float(sum(scores) / len(scores)), 1) if scores else 0.0

    return {
        "qr_present": True,
        "qr_decoded": True,
        "overall_match_score": overall_score,
        "has_critical_mismatch": has_critical_mismatch,
        "verification_matrix": matrix,
        "reasons": reasons
    }
