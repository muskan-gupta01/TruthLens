"""
OCR Extraction Module
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188 (Ministry of Home Affairs - Blockchain & Cybersecurity)

Performs Optical Character Recognition (OCR) using pytesseract with
advanced image preprocessing (CLAHE + Bilateral filtering + Adaptive Thresholding).
Extracts structured identity & travel fields for:
1. Passports (Visual Inspection Zone + ICAO Doc 9303 MRZ)
2. Visas (Visa No, Type, Country, Entry Type, Validity, Stay Duration)
3. National IDs (Aadhaar & PAN)
4. Driving Licenses
5. Permits / Travel Authorizations
"""
import re
import cv2
import numpy as np
from PIL import Image
import pytesseract
from pytesseract import Output
from typing import Dict, Any, Optional, Tuple, List

from app.config import (
    TESSERACT_PATH,
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
from app.pipeline.mrz_parser import find_and_parse_mrz

# Configure Tesseract binary path if available
if TESSERACT_PATH:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


def preprocess_image_for_ocr(cv_image: np.ndarray, binarize: bool = False) -> np.ndarray:
    """
    Applies image preprocessing to improve OCR accuracy:
    1. Grayscale conversion
    2. Adaptive scaling (upscales small/low-res documents to optimal 1200px width)
    3. Bilateral filtering (smoothes sensor noise while keeping text edges razor sharp)
    4. CLAHE (Contrast Limited Adaptive Histogram Equalization)
    5. Optional Otsu binarization for low-contrast text
    """
    if len(cv_image.shape) == 3:
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv_image.copy()

    h, w = gray.shape[:2]
    # Optimal OCR resolution: width between 1100px and 1600px
    if w > 1650:
        scale = 1500.0 / w
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    elif w < 1100:
        scale = 1200.0 / w
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

    # Bilateral filter reduces sensor noise while keeping text edges razor sharp
    denoised = cv2.bilateralFilter(gray, 9, 75, 75)

    # Adaptive histogram equalization (CLAHE) for high local contrast
    clahe = cv2.createCLAHE(clipLimit=2.2, tileGridSize=(8, 8))
    enhanced = clahe.apply(denoised)

    if binarize:
        _, enhanced = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    return enhanced


def extract_text_and_data(image_input) -> Tuple[str, float]:
    """
    Runs pytesseract with multi-pass recognition:
    - Pass 1: Contrast-enhanced grayscale with PSM 3
    - Pass 2: Sparse text recovery with PSM 11
    - Pass 3: Adaptive Otsu binarization
    - Pass 4: Multi-angle rotation testing (90°, 180°, 270°)
    Returns:
    - raw_text: complete extracted text string
    - mean_confidence: average OCR confidence percentage (0 - 100)
    """
    if TESSERACT_PATH:
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

    if isinstance(image_input, Image.Image):
        cv_img = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        cv_img = image_input
    else:
        raise ValueError("Unsupported image type for OCR extraction")

    custom_config = r"--oem 3 --psm 3"

    try:
        preprocessed = preprocess_image_for_ocr(cv_img, binarize=False)
        raw_text = pytesseract.image_to_string(preprocessed, config=custom_config)

        # If Pass 1 is sparse, test PSM 11 (Sparse text recovery)
        if len(raw_text.strip()) < 25:
            sparse_text = pytesseract.image_to_string(preprocessed, config=r"--oem 3 --psm 11")
            if len(sparse_text.strip()) > len(raw_text.strip()):
                raw_text = sparse_text

        # If still sparse, run Pass 3 with Otsu binarization
        if len(raw_text.strip()) < 15:
            preprocessed_b = preprocess_image_for_ocr(cv_img, binarize=True)
            text_pass3 = pytesseract.image_to_string(preprocessed_b, config=custom_config)
            if len(text_pass3.strip()) > len(raw_text.strip()):
                raw_text = text_pass3

        if not raw_text.strip():
            return "", 0.0

        # Calculate confidence metric
        try:
            data = pytesseract.image_to_data(preprocessed, output_type=Output.DICT, config=custom_config)
            confidences = [
                int(conf) for conf in data.get("conf", [])
                if conf != "-1" and str(conf).isdigit() and int(conf) > 0
            ]
            mean_conf = float(np.mean(confidences)) if confidences else 75.0
        except Exception:
            mean_conf = 75.0

        return raw_text, round(mean_conf, 1)

    except Exception as e:
        print(f"[OCR ERROR] Failed to run pytesseract: {e}")
        return "", 0.0


# Whitelisted short tokens that must NEVER be removed as noise
VALID_SHORT_TOKENS = {
    "DOB", "ID", "PAN", "DL", "C/O", "S/O", "D/O", "W/O",
    "NO", "TO", "OF", "IN", "AT", "BY", "PIN", "M", "F",
    "IND", "USA", "CAN", "GBR", "DEU", "FRA", "VID", "YOB"
}

# Known OCR confusion artifacts / isolated garbage words
KNOWN_OCR_NOISE_TOKENS = {
    "AWE", "WAA", "WRAEW", "FARARST", "HIHI", "HHH", "AXX", "AX", "AL", "ANA"
}


def clean_ocr_text(raw_text: str) -> str:
    """
    Cleans raw OCR output by filtering out obvious OCR noise artifacts:
    - lines containing only repeated symbols (e.g., '____', '--', '===', '...')
    - isolated meaningless fragments (e.g., 'al', 'aX', '= awe')
    - obvious OCR artifacts and sensor junk
    Preserves all valid tokens (DOB, ID, PAN, C/O, names, dates, numbers).
    Does NOT invent, alter, or hallucinate text.
    """
    if not raw_text:
        return ""

    cleaned_lines = []
    raw_lines = raw_text.splitlines()

    for line in raw_lines:
        trimmed = line.strip()
        if not trimmed:
            continue

        # 1. Pure symbol / non-alphanumeric lines: '____', '--', '====', '...', etc.
        if not re.search(r"[A-Za-z0-9]", trimmed):
            continue

        # 2. Extract core alphanumeric content by stripping surrounding punctuation/symbols
        core = re.sub(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "", trimmed).strip()
        if not core:
            continue

        core_upper = core.upper()

        # 3. Always preserve known valid short tokens (DOB, ID, PAN, C/O, M, F, etc.)
        if core_upper in VALID_SHORT_TOKENS or trimmed.upper() in VALID_SHORT_TOKENS:
            cleaned_lines.append(trimmed)
            continue

        # 4. Filter known isolated noise tokens (awe, al, aX, waa, wraew, etc.)
        if core_upper in KNOWN_OCR_NOISE_TOKENS:
            continue

        # 5. Filter lines starting with symbol noise like '= awe', '~ ax', '- al', etc.
        if re.match(r"^[^A-Za-z0-9\s]", trimmed) and len(core) <= 4:
            if core_upper not in VALID_SHORT_TOKENS and not re.search(r"\d", core):
                continue

        # 6. Filter isolated 1-character non-whitelisted fragments ('~', 'l', 'a', etc.)
        if len(core) <= 1 and not re.search(r"\d", core):
            continue

        # 7. Filter isolated 2-character non-whitelisted fragments (e.g. 'al', 'aX')
        if len(core) == 2 and not re.search(r"\d", core):
            if core_upper not in VALID_SHORT_TOKENS:
                continue

        # 8. Filter isolated lowercase 3-letter words that are not names or tokens (e.g. 'awe')
        if len(core.split()) == 1 and len(core) == 3 and core.islower() and not re.search(r"\d", core):
            if core_upper not in VALID_SHORT_TOKENS:
                continue

        # 9. Filter words with repeated identical characters (e.g. 'aaa', 'www', 'ooo')
        if re.search(r"(.)\1\1", core.lower()):
            continue

        # Valid line
        cleaned_lines.append(trimmed)

    return "\n".join(cleaned_lines)


def _get_demo_sample_fallback_text(cv_img: np.ndarray) -> Optional[Tuple[str, float]]:
    """
    Synthetic dimension-based fallback has been removed to prevent injection of
    predetermined genuine document text into malicious or forged inputs.
    Returns None so real OCR and subsequent forensic checks operate honestly.
    """
    return None


def classify_document_evidence(text: str, user_hint: Optional[str] = None, mrz_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Evaluates multi-modal optical evidence to independently classify document type and verify
    conformance against user-claimed document type (anti-impersonation / fraud check).

    Separates:
      1. claimed_type: What the user selected at intake
      2. detected_type: What the optical evidence independently confirms
      3. is_claimed_mismatch: Signal if claimed and detected conflict
    """
    text_upper = text.upper()
    clean_norm = " ".join(re.sub(r"[^A-Z0-9\s]", " ", text_upper).split())

    # Official government domains (Indian & International)
    GOV_DOMAINS = [
        "UIDAI.GOV.IN", "WWW.UIDAI.GOV.IN", "HELP@UIDAI.GOV.IN",
        "INCOMETAX.GOV.IN", "INCOMETAXINDIA.GOV.IN", "PASSPORTINDIA.GOV.IN",
        "PARIVAHAN.GOV.IN", "GOV.IN", "NIC.IN", "INDIA.GOV.IN"
    ]

    has_gov_domain = any(domain in text_upper for domain in GOV_DOMAINS)

    # Document-specific official institutional keyword dictionaries
    passport_keywords = [
        "PASSPORT", "PASSEPORT", "REPUBLIC OF", "UNITED STATES OF AMERICA",
        "P<", "NATIONALITY", "SURNAME", "GIVEN NAMES", "DATE OF EXPIRY", "PASSPORT NO"
    ]
    visa_keywords = [
        "VISA", "VALID FOR", "ENTRIES", "DURATION OF STAY", "TYPE OF VISA",
        "SCHENGEN", "STAY DURATION", "ENTRY TYPE", "VALID FROM", "VALID UNTIL", "V<"
    ]
    dl_keywords = [
        "DRIVING LICENCE", "DRIVING LICENSE", "MOTOR VEHICLES", "TRANSPORT",
        "DL NO", "AUTHORISATION TO DRIVE", "VEHICLE CLASS", "LMV", "MCWG", "PARIVAHAN"
    ]
    permit_keywords = [
        "TRAVEL PERMIT", "ENTRY AUTHORIZATION", "RESIDENCE PERMIT", "BORDER TRANSIT",
        "WORK PERMIT", "IMMIGRATION PERMIT"
    ]
    aadhaar_keywords = [
        "AADHAAR", "AADHAR", "UIDAI", "UNIQUE IDENTIFICATION", "AUTHORITY OF INDIA",
        "GOVERNMENT OF INDIA", "GOVT OF INDIA", "BHARAT SARKAR", "MERA AADHAAR", "MERI PEHCHAN",
        "ENROLMENT NO", "1947", "HELP@UIDAI", "EAADHAAR", "E-AADHAAR", "VID:"
    ]
    pan_keywords = [
        "INCOME TAX DEPARTMENT", "PERMANENT ACCOUNT NUMBER", "INCOMETAX", "PAN CARD",
        "GOVT. OF INDIA", "GOVERNMENT OF INDIA"
    ]

    # Strong commercial entity tokens - required to classify as a business card
    corporate_entity_tokens = [
        "PVT LTD", "PVT. LTD.", "PRIVATE LIMITED", "LLP", "INC.", "CORP.", "LIMITED",
        "ENTERPRISE", "ENTERPRISES", "INDUSTRIES", "VENTURES", "SOLUTIONS",
        "TECHNOLOGIES", "CONSULTING", "CONSULTANT", "SERVICES", "AGENCY", "STUDIO",
        "GSTIN", "CIN:"
    ]

    # Executive designations (only meaningful when accompanied by corporate entity context)
    executive_titles = [
        "CHIEF EXECUTIVE", "MANAGING DIRECTOR", "FOUNDER", "CO-FOUNDER",
        "PRESIDENT", "VICE PRESIDENT", "DIRECTOR", "CEO", "CTO", "COO", "CFO",
        "PROPRIETOR", "PARTNER", "GENERAL MANAGER"
    ]

    evidence: Dict[str, List[str]] = {
        DOC_TYPE_PASSPORT: [],
        DOC_TYPE_VISA: [],
        DOC_TYPE_DRIVING_LICENSE: [],
        DOC_TYPE_PERMIT: [],
        DOC_TYPE_AADHAAR: [],
        DOC_TYPE_PAN: [],
        DOC_TYPE_BUSINESS_CARD: []
    }

    # 1. Evaluate institutional government keywords
    for kw in passport_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_PASSPORT].append(kw)

    for kw in visa_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_VISA].append(kw)

    for kw in dl_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_DRIVING_LICENSE].append(kw)

    for kw in permit_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_PERMIT].append(kw)

    for kw in aadhaar_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_AADHAAR].append(kw)

    for kw in pan_keywords:
        if kw in text_upper or kw in clean_norm:
            evidence[DOC_TYPE_PAN].append(kw)

    # 2. Government domain boosts
    if has_gov_domain:
        matched_gov_domains = [d for d in GOV_DOMAINS if d in text_upper]
        if any("UIDAI" in d for d in matched_gov_domains):
            evidence[DOC_TYPE_AADHAAR].extend(matched_gov_domains)
        elif any("INCOMETAX" in d for d in matched_gov_domains):
            evidence[DOC_TYPE_PAN].extend(matched_gov_domains)
        else:
            evidence[DOC_TYPE_AADHAAR].extend(matched_gov_domains)

    # 3. Commercial evidence for business card classification
    matched_corp_tokens = [tok for tok in corporate_entity_tokens if tok in text_upper]
    matched_exec_titles = [title for title in executive_titles if re.search(rf"\b{re.escape(title)}\b", text_upper)]

    # Check for commercial non-government contact details
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b", text)
    commercial_emails = [e for e in emails if not any(gov in e.upper() for gov in ["GOV.IN", "NIC.IN", "UIDAI"])]

    urls = re.findall(r"\b(?:WWW\.[A-Z0-9\-\.]+\.[A-Z]{2,}|https?://[A-Z0-9\-\.]+)\b", text_upper)
    commercial_urls = [u for u in urls if not any(gov in u for gov in ["GOV.IN", "NIC.IN", "UIDAI"])]

    if matched_corp_tokens:
        evidence[DOC_TYPE_BUSINESS_CARD].extend(matched_corp_tokens)
    if commercial_emails:
        evidence[DOC_TYPE_BUSINESS_CARD].append(f"Commercial Email: {commercial_emails[0]}")
    if commercial_urls:
        evidence[DOC_TYPE_BUSINESS_CARD].append(f"Commercial Web: {commercial_urls[0]}")
    if matched_exec_titles and (matched_corp_tokens or commercial_emails or commercial_urls):
        evidence[DOC_TYPE_BUSINESS_CARD].extend(matched_exec_titles)

    # Calculate weighted scores
    scores = {
        DOC_TYPE_PASSPORT: len(evidence[DOC_TYPE_PASSPORT]) * 3,
        DOC_TYPE_VISA: len(evidence[DOC_TYPE_VISA]) * 3,
        DOC_TYPE_DRIVING_LICENSE: len(evidence[DOC_TYPE_DRIVING_LICENSE]) * 3,
        DOC_TYPE_PERMIT: len(evidence[DOC_TYPE_PERMIT]) * 3,
        DOC_TYPE_AADHAAR: len(evidence[DOC_TYPE_AADHAAR]) * 3,
        DOC_TYPE_PAN: len(evidence[DOC_TYPE_PAN]) * 3,
        DOC_TYPE_BUSINESS_CARD: (
            len(matched_corp_tokens) * 4 +
            (len(matched_exec_titles) * 3 if matched_corp_tokens else 0) +
            (4 if commercial_emails else 0) +
            (4 if commercial_urls else 0)
        )
    }

    # Institutional Format Regex Boosts
    if re.search(r"P<[A-Z0-9<]{30,}", text) or (mrz_data and mrz_data.get("valid_structure")):
        scores[DOC_TYPE_PASSPORT] += 15
        evidence[DOC_TYPE_PASSPORT].append("ICAO Doc 9303 MRZ Structure")

    if re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text_upper):
        scores[DOC_TYPE_PAN] += 12
        evidence[DOC_TYPE_PAN].append("PAN 10-Character Syntax")

    if re.search(r"\b[2-9]\d{3}[-\s]\d{4}[-\s]\d{4}\b", text):
        scores[DOC_TYPE_AADHAAR] += 12
        evidence[DOC_TYPE_AADHAAR].append("12-Digit Aadhaar Format")
    elif re.search(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b", text):
        scores[DOC_TYPE_AADHAAR] += 8
        evidence[DOC_TYPE_AADHAAR].append("12-Digit Numeric Grouping")

    if re.search(r"V<[A-Z0-9<]{30,}", text):
        scores[DOC_TYPE_VISA] += 15
        evidence[DOC_TYPE_VISA].append("ICAO Visa MRZ Structure")

    # Determine independent detected type
    gov_types = [DOC_TYPE_PASSPORT, DOC_TYPE_VISA, DOC_TYPE_DRIVING_LICENSE, DOC_TYPE_PERMIT, DOC_TYPE_AADHAAR, DOC_TYPE_PAN]
    best_gov_type = max(gov_types, key=scores.get)
    max_gov_score = scores[best_gov_type]
    biz_score = scores[DOC_TYPE_BUSINESS_CARD]

    # Heuristic detection
    detected_type = DOC_TYPE_UNKNOWN
    is_non_identity = False

    # Check for commercial business card: Requires strong commercial entity evidence
    has_strong_commercial_evidence = (
        len(matched_corp_tokens) >= 1 and
        (len(matched_exec_titles) >= 1 or commercial_emails or commercial_urls or len(matched_corp_tokens) >= 2)
    )

    if max_gov_score >= 6 and max_gov_score >= biz_score:
        detected_type = best_gov_type
        is_non_identity = False
    elif has_strong_commercial_evidence and max_gov_score < 6:
        detected_type = DOC_TYPE_BUSINESS_CARD
        is_non_identity = True
    elif max_gov_score >= 3 and max_gov_score > biz_score:
        detected_type = best_gov_type
        is_non_identity = False
    elif biz_score >= 8 and max_gov_score == 0:
        detected_type = DOC_TYPE_BUSINESS_CARD
        is_non_identity = True
    elif max_gov_score > 0:
        detected_type = best_gov_type
        is_non_identity = False
    else:
        detected_type = DOC_TYPE_UNKNOWN
        is_non_identity = True

    # Claimed Type vs Detected Type evaluation
    claimed_type = user_hint if user_hint and user_hint != "AUTO" else None
    is_claimed_mismatch = False
    mismatch_reason = None
    uncertainty = False

    # OCR Uncertainty Handling (sparse or degraded text)
    if len(text.strip()) < 15:
        if mrz_data and mrz_data.get("valid_structure"):
            detected_type = DOC_TYPE_PASSPORT
            is_non_identity = False
        else:
            uncertainty = True
            detected_type = claimed_type or DOC_TYPE_UNKNOWN
            is_non_identity = False if claimed_type in gov_types else True

    # Anti-impersonation conformance check
    if claimed_type and claimed_type in gov_types:
        claimed_score = scores[claimed_type]
        has_claimed_evidence = claimed_score >= 3 or len(evidence[claimed_type]) > 0

        # Special check for Aadhaar: if official keywords or valid 12-digit number exist, retain Aadhaar
        if claimed_type == DOC_TYPE_AADHAAR and (
            any(k in text_upper for k in ["AADHAAR", "AADHAR", "UIDAI", "GOVERNMENT OF INDIA", "MERA AADHAAR"]) or
            re.search(r"\b[2-9]\d{3}[-\s]\d{4}[-\s]\d{4}\b", text) or
            has_gov_domain
        ):
            has_claimed_evidence = True
            detected_type = DOC_TYPE_AADHAAR
            is_non_identity = False

        if not has_claimed_evidence:
            if detected_type == DOC_TYPE_BUSINESS_CARD or has_strong_commercial_evidence:
                is_claimed_mismatch = True
                detected_type = DOC_TYPE_BUSINESS_CARD
                is_non_identity = True
                mismatch_reason = (
                    f"Document Type Mismatch: Intake registered under '{claimed_type}', "
                    f"but optical analysis confirmed a commercial Business Card "
                    f"(detected: {', '.join(evidence[DOC_TYPE_BUSINESS_CARD][:3])}) "
                    f"lacking all statutory {claimed_type} credentials, emblems, and checksums."
                )
            elif max_gov_score >= 6 and best_gov_type != claimed_type:
                is_claimed_mismatch = True
                detected_type = best_gov_type
                is_non_identity = False
                mismatch_reason = (
                    f"Document Type Conflict: User selected '{claimed_type}', but document exhibits "
                    f"institutional characteristics of '{detected_type}'."
                )
            elif uncertainty:
                # Conservative: OCR uncertainty != confirmed fraud
                is_claimed_mismatch = False
                mismatch_reason = f"OCR text inconclusive; insufficient optical markers to verify {claimed_type}."
            else:
                is_claimed_mismatch = True
                detected_type = DOC_TYPE_NON_IDENTITY
                is_non_identity = True
                mismatch_reason = (
                    f"Invalid Identity Document: Presented media lacks statutory credentials for claimed '{claimed_type}'."
                )
        else:
            # Confirmed match with claimed type
            detected_type = claimed_type
            is_claimed_mismatch = False
            is_non_identity = False

    # Heuristic confidence calculation
    total_score = sum(scores.values())
    heuristic_conf = min(95.0, max(20.0, float(max_gov_score if not is_non_identity else biz_score) * 4.5)) if total_score > 0 else 0.0

    return {
        "detected_type": detected_type,
        "claimed_type": claimed_type,
        "is_claimed_mismatch": is_claimed_mismatch,
        "is_non_identity": is_non_identity,
        "mismatch_reason": mismatch_reason,
        "scores": scores,
        "evidence": evidence,
        "uncertainty": uncertainty,
        "confidence": round(heuristic_conf, 1)
    }


def identify_document_type(text: str, user_hint: Optional[str] = None) -> str:
    """
    Determines document type based on characteristic institutional keywords,
    official formats, checksums, or verified user hint.
    """
    evidence = classify_document_evidence(text, user_hint=user_hint)
    return evidence["detected_type"]


def parse_business_card_fields(text: str) -> Dict[str, Any]:
    """Extracts contact, company, designation and person details from commercial business cards."""
    fields: Dict[str, Any] = {
        "name": None,
        "full_name": None,
        "id_number": None,
        "designation": None,
        "company": None,
        "phone": None,
        "email": None,
        "website": None,
        "dob": None,
        "expiry_date": None,
        "nationality": None,
        "document_type": "BUSINESS_CARD",
        "notes": "Commercial Business / Visiting Card (Non-Identity Document)"
    }
    # Email
    em = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text)
    if em:
        fields["email"] = em.group(0)

    # Website
    ws = re.search(r"\b(?:https?://)?(?:www\.)?[A-Za-z0-9.-]+\.(?:com|in|org|net|io|co|biz|edu)\b", text, re.IGNORECASE)
    if ws:
        fields["website"] = ws.group(0)

    # Phone
    ph = re.search(r"(?:Ph|Phone|Mob|Mobile|Tel|Cell)?[\s:]*([+]?\d[\d\s\-]{8,14}\d)", text, re.IGNORECASE)
    if ph:
        fields["phone"] = ph.group(1).strip()

    # Designation
    desig_match = re.search(
        r"\b(CHIEF\s+EXECUTIVE|CEO|MANAGING\s+DIRECTOR|DIRECTOR|FOUNDER|CO-FOUNDER|PRESIDENT|VICE\s+PRESIDENT|VP|GENERAL\s+MANAGER|MANAGER|CONSULTANT|ADVOCATE|LAWYER|ENGINEER|DEVELOPER|ARCHITECT|PROPRIETOR|PROP\.?|PARTNER|EXECUTIVE|ASSOCIATE|MARKETING|SALES|DOCTOR|DR\.?|PROFESSOR|CHAIRMAN|SECRETARY)\b",
        text, re.IGNORECASE
    )
    if desig_match:
        fields["designation"] = desig_match.group(0).upper()

    # Company Name
    comp_match = re.search(
        r"([A-Za-z0-9\s&]{2,40}(?:PVT\.?\s*LTD\.?|PRIVATE\s+LIMITED|LIMITED|LLP|INC\.?|CORP\.?|CORPORATION|SOLUTIONS|TECHNOLOGIES|SERVICES|INDUSTRIES|ENTERPRISES|AGENCY|STUDIO))",
        text, re.IGNORECASE
    )
    if comp_match:
        fields["company"] = comp_match.group(0).strip()

    # Person Name
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        clean_l = re.sub(r"^[^A-Za-z]+", "", line).strip()
        if 3 <= len(clean_l) <= 30 and re.match(r"^[A-Za-z][A-Za-z\s\.]+$", clean_l):
            clean_up = clean_l.upper()
            if not any(k in clean_up for k in ["PVT", "LTD", "LIMITED", "INC", "CORP", "EMAIL", "WWW", "PHONE", "TEL", "MOB", "SOLUTIONS", "SERVICES", "CONSULTANT"]):
                if _is_valid_person_name(clean_l):
                    fields["name"] = clean_l
                    fields["full_name"] = clean_l
                    break

    return fields


def parse_passport_fields(text: str, mrz_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Extracts passport fields from Visual Inspection Zone & MRZ."""
    fields: Dict[str, Any] = {
        "full_name": None,
        "passport_number": None,
        "nationality": None,
        "dob": None,
        "gender": None,
        "issue_date": None,
        "expiry_date": None,
        "issuing_country": None
    }

    # Prefer MRZ data if available
    if mrz_data and mrz_data.get("valid_structure"):
        fields["full_name"] = mrz_data.get("full_name")
        fields["passport_number"] = mrz_data.get("doc_number")
        fields["nationality"] = mrz_data.get("nationality")
        fields["dob"] = mrz_data.get("dob")
        fields["gender"] = mrz_data.get("gender")
        fields["expiry_date"] = mrz_data.get("expiry_date")
        fields["issuing_country"] = mrz_data.get("issuing_country")

    # Fill in or fallback with visual text regex
    if not fields["passport_number"]:
        m = re.search(r"\b([A-Z][0-9]{7,8})\b", text)
        if m:
            fields["passport_number"] = m.group(1)

    if not fields["nationality"]:
        m = re.search(r"(?:Nationality|Nationalite)[\s:]*([A-Za-z]+)", text, re.IGNORECASE)
        if m:
            fields["nationality"] = m.group(1).upper()

    if not fields["full_name"]:
        m = re.search(r"(?:Name|Given Names?|Surname)[\s:]*([A-Z\s]{3,35})", text, re.IGNORECASE)
        if m:
            fields["full_name"] = " ".join(m.group(1).split())

    if not fields["dob"]:
        m = re.search(r"(?:Date of Birth|Birth|DOB)[\s:]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", text, re.IGNORECASE)
        if m:
            fields["dob"] = m.group(1)

    if not fields["expiry_date"]:
        m = re.search(r"(?:Date of Expiry|Expiry|Expires)[\s:]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", text, re.IGNORECASE)
        if m:
            fields["expiry_date"] = m.group(1)

    if not fields["issue_date"]:
        m = re.search(r"(?:Date of Issue|Issue)[\s:]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", text, re.IGNORECASE)
        if m:
            fields["issue_date"] = m.group(1)

    if not fields["gender"]:
        if re.search(r"\b(MALE|FEMALE)\b", text, re.IGNORECASE):
            fields["gender"] = "MALE" if re.search(r"\bMALE\b", text, re.IGNORECASE) else "FEMALE"

    return fields


def parse_visa_fields(text: str) -> Dict[str, Any]:
    """Extracts Visa fields: Visa No, Type, Country, Entries, Validity Dates, Stay Duration."""
    fields: Dict[str, Any] = {
        "visa_number": None,
        "visa_type": "TOURIST",
        "country": None,
        "entry_type": "MULTIPLE",
        "valid_from": None,
        "valid_until": None,
        "stay_duration": None,
        "full_name": None
    }

    # 1. Visa Number
    m = re.search(r"(?:Visa No|Number|Document No)[\s:]*([A-Z0-9]{7,12})", text, re.IGNORECASE)
    if m:
        fields["visa_number"] = m.group(1).upper()
    else:
        m2 = re.search(r"\b([Vv][0-9]{7,9})\b", text)
        if m2:
            fields["visa_number"] = m2.group(1).upper()

    # 2. Visa Type
    for vtype in ["TOURIST", "BUSINESS", "STUDENT", "EMPLOYMENT", "TRANSIT", "DIPLOMATIC"]:
        if vtype in text.upper():
            fields["visa_type"] = vtype
            break

    # 3. Entry Type
    if "SINGLE" in text.upper() or "01" in text:
        fields["entry_type"] = "SINGLE"
    elif "DOUBLE" in text.upper() or "02" in text:
        fields["entry_type"] = "DOUBLE"
    elif "MULTIPLE" in text.upper() or "MULT" in text.upper():
        fields["entry_type"] = "MULTIPLE"

    # 4. Dates
    dates = re.findall(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
    if len(dates) >= 2:
        fields["valid_from"] = dates[0]
        fields["valid_until"] = dates[1]
    elif len(dates) == 1:
        fields["valid_until"] = dates[0]

    # 5. Stay Duration
    m_stay = re.search(r"(\d{1,3}\s*(?:DAYS|MONTHS|WEEKS))", text, re.IGNORECASE)
    if m_stay:
        fields["stay_duration"] = m_stay.group(1).upper()
    else:
        fields["stay_duration"] = "90 DAYS"

    # 6. Country
    for c in ["INDIA", "USA", "UNITED KINGDOM", "FRANCE", "GERMANY", "SCHENGEN", "CANADA", "UAE", "SINGAPORE"]:
        if c in text.upper():
            fields["country"] = c
            break

    # 7. Name
    m_name = re.search(r"(?:Name|Bearer|Holder)[\s:]*([A-Z\s]{3,30})", text, re.IGNORECASE)
    if m_name:
        fields["full_name"] = " ".join(m_name.group(1).split())

    return fields


def parse_driving_license_fields(text: str) -> Dict[str, Any]:
    """Extracts Driving License fields."""
    fields: Dict[str, Any] = {
        "license_number": None,
        "full_name": None,
        "dob": None,
        "issue_date": None,
        "expiry_date": None,
        "vehicle_class": "LMV"
    }

    m_dl = re.search(r"\b([A-Z]{2}[0-9\-\s]{11,16})\b", text)
    if m_dl:
        fields["license_number"] = m_dl.group(1).strip()

    m_name = re.search(r"(?:Name)[\s:]*([A-Za-z\s]{3,30})", text, re.IGNORECASE)
    if m_name:
        fields["full_name"] = " ".join(m_name.group(1).split()).upper()

    dates = re.findall(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
    if len(dates) >= 2:
        fields["dob"] = dates[0]
        fields["expiry_date"] = dates[1]
    elif len(dates) == 1:
        fields["dob"] = dates[0]

    return fields


def parse_permit_fields(text: str) -> Dict[str, Any]:
    """Extracts Travel Permit / Authorization fields."""
    fields: Dict[str, Any] = {
        "permit_id": None,
        "traveler_name": None,
        "nationality": "IND",
        "permit_type": "BORDER_TRANSIT",
        "valid_until": None
    }
    m = re.search(r"\b([A-Z]{2,3}[0-9]{6,10})\b", text)
    if m:
        fields["permit_id"] = m.group(1)
    dates = re.findall(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
    if dates:
        fields["valid_until"] = dates[-1]
    return fields


AADHAAR_STOPWORDS = {
    # Institutional & Government keywords
    "GOVERNMENT", "GOVT", "INDIA", "BHARAT", "SARKAR", "UNIQUE",
    "IDENTIFICATION", "AUTHORITY", "UIDAI", "AADHAAR", "AADHAR",
    "MERA", "MERI", "PEHCHAN", "ENROLMENT", "ENROLLMENT", "HELP",
    "DOWNLOAD", "DATE", "ISSUE", "PRINT", "VALID", "ONLY", "THROUGH",
    "MOBILE", "NUMBER", "VID", "HELP@UIDAI", "WWW", "HTTP", "HTTPS",
    "COMMISSION", "MINISTRY", "DEPARTMENT", "DIRECTORATE", "RO", "REGIONAL",
    # Field labels
    "DOB", "DOS", "DO8", "YOB", "YEAR", "BIRTH", "GENDER", "SEX",
    "MALE", "FEMALE", "TRANSGENDER", "PURUSH", "MAHILA",
    "FATHER", "HUSBAND", "MOTHER", "WIFE", "SON", "DAUGHTER",
    "NAME", "NAAM", "ADDRESS", "PATA", "SIGNATURE", "OFFICE", "RESIDENT",
    # Address & location abbreviations and nouns
    "ARPT", "PART", "APARTMENT", "APT", "FLAT", "FLOOR", "HOUSE", "HNO",
    "H.NO", "BLOCK", "BLK", "SECTOR", "SEC", "PLOT", "ROAD", "RD",
    "STREET", "ST", "LANE", "MARG", "NAGAR", "COLONY", "ENCLAVE",
    "VIHAR", "POCKET", "PHASE", "DIST", "DISTRICT", "STATE", "PIN",
    "PINCODE", "PO", "P.O", "PS", "P.S", "TEHSIL", "TALUK", "VILLAGE",
    "CITY", "TOWN", "POST", "NEAR", "OPP", "BEHIND", "BESIDE", "FRONT",
    "WEST", "EAST", "NORTH", "SOUTH", "BUILDING", "BLDG", "TOWER",
    "COMPLEX", "PLAZA", "RESIDENCY", "SOCIETY", "ROOM", "WARD",
    # Known noise tokens
    "AWE", "WAA", "WRAEW", "FARARST", "HIHI", "HHH", "AXX", "AX", "AL", "ANA"
}

INDIAN_NAME_TOKENS = {
    "KUMAR", "KUMARI", "SINGH", "SHARMA", "VERMA", "GUPTA", "DEVI", "KAUR",
    "PATEL", "SHAH", "DAS", "ALI", "KHAN", "LAL", "PRASAD", "CHOWDHURY",
    "RAO", "REDDY", "NAIR", "IYER", "JOSHI", "SEN", "ROY", "MALHOTRA",
    "MEHTA", "BOSE", "JAIN", "BHATIA", "BHATTACHARYA", "CHOPRA", "MISHRA",
    "PANDEY", "YADAV", "TIWARI", "SAXENA", "KAPOOR", "AGRAWAL", "AGARWAL",
    "BANERJEE", "DUTTA", "CHATTERJEE", "MUKHERJEE", "GHOSH"
}


def _is_plausible_aadhaar_name(cand: str) -> bool:
    """Validates that candidate is a plausible human name and not camera noise or address token."""
    cand = cand.strip()
    if len(cand) < 3 or len(cand) > 35:
        return False

    # Only alphabetic characters, spaces, and periods for initials allowed
    if not re.match(r"^[A-Za-z][A-Za-z\s\.]+$", cand):
        return False

    words = cand.split()
    if len(words) < 1 or len(words) > 4:
        return False

    for w in words:
        w_clean = re.sub(r"[^A-Za-z]", "", w)
        if not w_clean:
            continue
        w_up = w_clean.upper()

        # Reject stopwords, address tokens, government terms
        if w_up in AADHAAR_STOPWORDS:
            return False

        # Reject words with 3 identical consecutive characters
        if re.search(r"(.)\1\1", w_clean.lower()):
            return False

        # If word length >= 2, must contain at least one vowel
        if len(w_clean) >= 2 and not re.search(r"[aeiouyAEIOUY]", w_clean):
            return False

    return True


def extract_aadhaar_name(text: str) -> Tuple[Optional[str], float]:
    """
    Extracts and ranks Aadhaar name candidates using multi-feature evidence:
    - Prioritizes text located near/after name labels or pre-DOB positional regions
    - Rejects address abbreviations (e.g. 'ARPT PART'), government headers, and OCR noise
    - Evaluates linguistic structure (vowels, title case, standard suffixes)
    - Returns (best_name, confidence_score) or ('Uncertain (Needs Review)', 0.0)
      if confidence is insufficient.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return "Uncertain (Needs Review)", 0.0

    # Locate landmark line indices (DOB, Gender, 12-digit number)
    dob_line_idx = None
    gender_line_idx = None
    for idx, l in enumerate(lines):
        if re.search(r"(?:DOB|Date of Birth|Birth|Dos|DO8|\b\d{2}[/\-\.]\d{2}[/\-\.]\d{4}\b)", l, re.IGNORECASE):
            if dob_line_idx is None:
                dob_line_idx = idx
        if re.search(r"\b(MALE|FEMALE|TRANSGENDER|PURUSH|MAHILA)\b", l, re.IGNORECASE):
            if gender_line_idx is None:
                gender_line_idx = idx

    candidates_scored: List[Tuple[str, float]] = []

    # Strategy 1: Explicit label match ("Name: <name>", "Naam: <name>", or "Name\n<name>")
    for idx, l in enumerate(lines):
        lbl_m = re.search(r"(?:Name|Naam)[\s:/=>]+([A-Za-z\s\.]{3,35})", l, re.IGNORECASE)
        if lbl_m:
            cand = lbl_m.group(1).strip()
            if _is_plausible_aadhaar_name(cand):
                candidates_scored.append((cand, 80.0))
        elif re.match(r"^(?:Name|Naam)[\s:/=>]*$", l, re.IGNORECASE):
            # Check next line
            if idx + 1 < len(lines):
                cand = lines[idx + 1].strip()
                if _is_plausible_aadhaar_name(cand):
                    candidates_scored.append((cand, 75.0))

    # Strategy 2: Pre-DOB positional search (Standard UIDAI format: Name precedes DOB)
    if dob_line_idx is not None:
        # Check lines immediately preceding DOB
        for offset, boost in [(1, 60.0), (2, 40.0), (3, 25.0)]:
            target_idx = dob_line_idx - offset
            if target_idx >= 0:
                line_cand = lines[target_idx].strip()
                clean_cand = re.sub(r"^[^A-Za-z]+", "", line_cand).strip()
                if _is_plausible_aadhaar_name(clean_cand):
                    candidates_scored.append((clean_cand, boost))

    # Strategy 3: General scan across document lines before DOB
    max_scan_idx = dob_line_idx if dob_line_idx is not None else len(lines)
    for idx, l in enumerate(lines[:max_scan_idx]):
        clean_cand = re.sub(r"^[^A-Za-z]+", "", l).strip()
        if _is_plausible_aadhaar_name(clean_cand):
            candidates_scored.append((clean_cand, 20.0))

    if not candidates_scored:
        return "Uncertain (Needs Review)", 0.0

    # Aggregate and refine scores for each unique candidate
    best_scores: Dict[str, float] = {}
    for cand, initial_score in candidates_scored:
        words = cand.split()
        score = initial_score

        # Multi-word bonus (Indian names almost always consist of 2-3 words)
        if len(words) == 2:
            score += 25.0
        elif len(words) == 3:
            score += 20.0
        elif len(words) == 1:
            score += 5.0

        # Title Case bonus (e.g. "Ashna Kumari" vs "ASHNA KUMARI")
        if cand.istitle():
            score += 15.0
        elif cand.isupper():
            score += 10.0

        # Standard Indian name tokens boost
        if any(w.upper() in INDIAN_NAME_TOKENS for w in words):
            score += 25.0

        # Length plausibility
        if 6 <= len(cand) <= 25:
            score += 10.0

        # Positional proximity to DOB if known
        if dob_line_idx is not None:
            cand_indices = [i for i, l in enumerate(lines) if cand in l]
            if cand_indices:
                dist = dob_line_idx - cand_indices[0]
                if dist == 1:
                    score += 30.0
                elif dist == 2:
                    score += 15.0
                elif dist < 0:
                    score -= 40.0  # Appears after DOB -> highly suspect

        best_scores[cand] = max(best_scores.get(cand, 0.0), score)

    # Sort candidates by final score descending
    sorted_candidates = sorted(best_scores.items(), key=lambda x: x[1], reverse=True)
    winner_name, winner_score = sorted_candidates[0]

    # Sufficient confidence threshold
    if winner_score >= 45.0:
        return winner_name, round(winner_score, 1)
    else:
        return "Uncertain (Needs Review)", round(winner_score, 1)


def parse_aadhaar_fields(text: str) -> Dict[str, Any]:
    """Extracts Aadhaar fields (ID Number, Name, DOB, Gender)."""
    fields: Dict[str, Any] = {"id_number": None, "dob": None, "gender": None, "name": None}

    # 1. 12-digit Aadhaar Number (standard 4 4 4 grouping with spaces or hyphens, or continuous)
    id_match = re.search(r"\b([2-9]\d{3}[-\s]\d{4}[-\s]\d{4})\b", text)
    if id_match:
        fields["id_number"] = id_match.group(1).replace("-", " ").strip()
    else:
        m12 = re.search(r"\b(\d{4}[-\s]\d{4}[-\s]\d{4})\b", text)
        if m12:
            fields["id_number"] = m12.group(1).replace("-", " ").strip()
        else:
            m_cont = re.search(r"\b([2-9]\d{11})\b", text)
            if m_cont:
                raw_id = m_cont.group(1)
                fields["id_number"] = f"{raw_id[:4]} {raw_id[4:8]} {raw_id[8:]}"

    # 2. Date of Birth
    dob_m = re.search(r"(?:DOB|Date of Birth|Birth|Dos|DO8)[\s:/=>]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", text, re.IGNORECASE)
    if dob_m:
        fields["dob"] = dob_m.group(1)
    else:
        d_fb = re.search(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
        if d_fb:
            fields["dob"] = d_fb.group(1)
        else:
            yob = re.search(r"(?:Year of Birth|YOB)[\s:/=>]*(\d{4})", text, re.IGNORECASE)
            if yob:
                fields["dob"] = f"01/01/{yob.group(1)}"

    # 3. Gender
    if re.search(r"\b(MALE|PURUSH)\b", text, re.IGNORECASE):
        fields["gender"] = "MALE"
    elif re.search(r"\b(FEMALE|MAHILA)\b", text, re.IGNORECASE):
        fields["gender"] = "FEMALE"
    elif re.search(r"\b(TRANSGENDER)\b", text, re.IGNORECASE):
        fields["gender"] = "TRANSGENDER"

    # 4. Name extraction via robust Aadhaar name evidence scoring
    extracted_name, _ = extract_aadhaar_name(text)
    fields["name"] = extracted_name

    return fields


def _clean_pan_token(token: str) -> Optional[str]:
    """Cleans a candidate token and checks if it conforms to Indian PAN card format."""
    token = re.sub(r"[^A-Z0-9]", "", token.upper())
    if len(token) != 10:
        return None
    sub_l = {'0': 'O', '1': 'I', '8': 'B', '5': 'S', '2': 'Z'}
    l_part = "".join(sub_l.get(ch, ch) for ch in token[:5])
    sub_d = {'O': '0', 'D': '0', 'Q': '0', 'I': '1', 'L': '1', 'B': '8', 'S': '5', 'Z': '2'}
    d_part = "".join(sub_d.get(ch, ch) for ch in token[5:9])
    last_ch = sub_l.get(token[9], token[9])
    cand = f"{l_part}{d_part}{last_ch}"
    if re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", cand):
        return cand
    return None


def _is_valid_person_name(cand: str) -> bool:
    """Validates that candidate is a plausible human name and not camera/sensor noise."""
    cand = cand.strip()
    if len(cand) < 3:
        return False
    words = cand.split()
    for w in words:
        if re.search(r"(.)\1\1", w.lower()):  # repeated 3 identical chars e.g. 'waa', 'eee'
            return False
        if len(w) <= 1:
            return False
    return True


def parse_pan_fields(text: str) -> Dict[str, Any]:
    """Extracts PAN fields (PAN ID, Name, Father's Name, DOB) with OCR error recovery."""
    fields: Dict[str, Any] = {"id_number": None, "name": None, "father_name": None, "dob": None, "gender": None}

    # 1. 10-character PAN Number (exact search)
    pan_m = re.search(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", text.upper())
    if pan_m:
        fields["id_number"] = pan_m.group(1)
    else:
        # Token-based scan across entire text for fuzzy matches
        tokens = re.findall(r"\b[A-Z0-9OILDQSBZ]{9,12}\b", text.upper())
        for tok in tokens:
            cand = _clean_pan_token(tok)
            if cand:
                fields["id_number"] = cand
                break

    # If still not found, search with spaces in between characters
    if not fields["id_number"]:
        pan_spaced = re.search(r"\b([A-Z0-9]{3,6})\s+([A-Z0-9]{3,6})\b", text.upper())
        if pan_spaced:
            merged = pan_spaced.group(1) + pan_spaced.group(2)
            cand = _clean_pan_token(merged)
            if cand:
                fields["id_number"] = cand

    # 2. Date of Birth
    dob_m = re.search(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
    if dob_m:
        fields["dob"] = dob_m.group(1)
    else:
        dob_m2 = re.search(r"(?:Date of Birth|DOB|Birth)[\s:]*(\d{2}\s*[/ \-\.]\s*\d{2}\s*[/ \-\.]\s*\d{4})", text, re.IGNORECASE)
        if dob_m2:
            fields["dob"] = re.sub(r"\s+", "", dob_m2.group(1))

    # 3. Name (follows 'Name' label)
    nm = re.search(r"(?:Name)\s*\n+([A-Za-z][A-Za-z ]{2,30})\s*(?:\n|$)", text, re.IGNORECASE)
    if nm:
        cand = nm.group(1).strip()
        if not any(k in cand.upper() for k in ["INCOME", "TAX", "DEPARTMENT", "INDIA", "PERMANENT", "ACCOUNT", "NUMBER"]):
            if _is_valid_person_name(cand):
                fields["name"] = cand
    if not fields["name"]:
        nm_inline = re.search(r"(?:Name)[\s:]*([A-Za-z][A-Za-z ]{2,30})", text, re.IGNORECASE)
        if nm_inline:
            cand = nm_inline.group(1).strip()
            if not any(k in cand.upper() for k in ["INCOME", "TAX", "DEPARTMENT", "INDIA", "PERMANENT", "ACCOUNT", "NUMBER"]):
                if _is_valid_person_name(cand):
                    fields["name"] = cand

    # 4. Father's Name
    fn = re.search(r"(?:Father[\'s]*\s*Name)\s*\n*([A-Za-z][A-Za-z ]{2,30})", text, re.IGNORECASE)
    if fn:
        cand = fn.group(1).strip()
        if not any(k in cand.upper() for k in ["INCOME", "TAX", "DEPARTMENT", "INDIA", "DATE", "BIRTH"]):
            if _is_valid_person_name(cand):
                fields["father_name"] = cand

    # 5. Heuristic candidate line scan if label was omitted or unreadable
    if not fields["name"]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        ignore_words = [
            "INCOME", "TAX", "DEPARTMENT", "INDIA", "PERMANENT", "ACCOUNT", "NUMBER",
            "CARD", "GOVT", "FATHER", "SIGNATURE", "DATE", "BIRTH", "HHH", "HIHI", "WAA",
            "FARARST", "WRAEW", "ANA", "AYAKAR", "VIBHAG", "BHARAT", "SARKAR", "COURT", "BS"
        ]
        # Real person names appear AFTER the header block
        header_passed = False
        candidates = []
        for line in lines:
            line_up = line.upper()
            if "ACCOUNT" in line_up or "CARD" in line_up or "DEPARTMENT" in line_up:
                header_passed = True
                continue
            if not header_passed:
                continue

            clean_l = " ".join(re.findall(r"[A-Za-z]+", line))
            if 4 <= len(clean_l) <= 28 and not any(w in clean_l.upper() for w in ignore_words):
                if _is_valid_person_name(clean_l):
                    candidates.append(clean_l)
        if candidates:
            fields["name"] = candidates[0]
            if len(candidates) > 1 and not fields["father_name"]:
                fields["father_name"] = candidates[1]

    return fields


def _has_structural_mrz_pattern(ocr_text: str) -> bool:
    """
    Verifies whether OCR text exhibits structural characteristics of an ICAO Doc 9303 MRZ zone:
    - At least 2 candidate lines of >= 36 characters with multiple '<' fillers
    - Starting with recognized ICAO type codes (P< for Passport, V< for Visa)
    """
    if not ocr_text:
        return False
    lines = [l.strip().replace(" ", "") for l in ocr_text.splitlines() if l.strip()]
    candidate_lines = [l for l in lines if len(l) >= 36 and l.count("<") >= 2]
    if len(candidate_lines) < 2:
        return False
    for i in range(len(candidate_lines) - 1):
        l1 = candidate_lines[i]
        l2 = candidate_lines[i + 1]
        if (re.match(r"^P[A-Z0-9<]?<", l1) or re.match(r"^V[A-Z0-9<]?<", l1)) and len(l2) >= 36:
            return True
    return False


def extract_document_fields(
    image_input,
    doc_type_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level OCR extraction orchestrator:
    1. Preprocesses image and runs multi-pass OCR
    2. Applies safe OCR cleaning layer to remove obvious noise artifacts
    3. Identifies document type (or applies user hint)
    4. Conditionally runs ICAO Doc 9303 MRZ parser ONLY for travel documents (Passport/Visa)
       with structurally valid MRZ patterns
    5. Extracts structured identity/travel fields with robust fallbacks
    6. Returns unified dictionary with full field coverage
    """
    raw_text, conf = extract_text_and_data(image_input)
    cleaned_text = clean_ocr_text(raw_text)

    NON_MRZ_TYPES = {
        DOC_TYPE_AADHAAR,
        DOC_TYPE_PAN,
        DOC_TYPE_BUSINESS_CARD,
        DOC_TYPE_DRIVING_LICENSE,
        DOC_TYPE_PERMIT,
        DOC_TYPE_NON_IDENTITY
    }
    MRZ_SUPPORTED_TYPES = {DOC_TYPE_PASSPORT, DOC_TYPE_VISA}

    # Fast classification without MRZ data first
    prelim_classification = classify_document_evidence(cleaned_text, user_hint=doc_type_hint, mrz_data=None)
    detected_type = prelim_classification["detected_type"]
    claimed_type = prelim_classification["claimed_type"]

    # Strict rule: MRZ parsing requires a supported document type (PASSPORT/VISA)
    # AND a structurally valid MRZ pattern.
    # Documents claimed or detected as Aadhaar, PAN, Business Card, or DL NEVER invoke MRZ parsing.
    # P< or V< OCR text alone CANNOT trigger MRZ parsing.
    is_non_mrz_document = (
        claimed_type in NON_MRZ_TYPES or
        detected_type in NON_MRZ_TYPES
    )

    is_mrz_supported_doc = (
        not is_non_mrz_document and
        (claimed_type in MRZ_SUPPORTED_TYPES or detected_type in MRZ_SUPPORTED_TYPES)
    )

    has_valid_mrz_structure = (
        _has_structural_mrz_pattern(cleaned_text) or _has_structural_mrz_pattern(raw_text)
    )

    mrz_result = None
    if is_mrz_supported_doc and has_valid_mrz_structure:
        mrz_result = find_and_parse_mrz(cleaned_text) or find_and_parse_mrz(raw_text)

    # Re-evaluate classification with confirmed MRZ data if MRZ was supported and detected
    if mrz_result and mrz_result.get("valid_structure"):
        classification = classify_document_evidence(cleaned_text, user_hint=doc_type_hint, mrz_data=mrz_result)
    else:
        classification = prelim_classification

    detected_type = classification["detected_type"]
    claimed_type = classification["claimed_type"]
    is_claimed_mismatch = classification["is_claimed_mismatch"]
    is_non_identity = classification["is_non_identity"]
    mismatch_reason = classification["mismatch_reason"]

    if mrz_result and mrz_result.get("valid_structure") and detected_type in [DOC_TYPE_UNKNOWN, DOC_TYPE_NON_IDENTITY]:
        detected_type = DOC_TYPE_PASSPORT
        is_non_identity = False

    # Non-MRZ documents (Aadhaar, PAN, Business Card, DL) MUST NEVER carry MRZ data
    if detected_type not in MRZ_SUPPORTED_TYPES:
        mrz_result = None

    # Multi-orientation fallback: if document is UNKNOWN or NON_IDENTITY without clear card, test phone camera inversions
    if detected_type == DOC_TYPE_UNKNOWN:
        if isinstance(image_input, Image.Image):
            cv_base = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, np.ndarray):
            cv_base = image_input.copy()
        else:
            cv_base = None

        if cv_base is not None:
            for rot_flag in [cv2.ROTATE_180, cv2.ROTATE_90_CLOCKWISE, cv2.ROTATE_90_COUNTERCLOCKWISE]:
                rot_cv = cv2.rotate(cv_base, rot_flag)
                prep_rot = preprocess_image_for_ocr(rot_cv, binarize=False)
                try:
                    t_rot = pytesseract.image_to_string(prep_rot, config=r"--oem 3 --psm 3")
                except Exception:
                    continue
                if len(t_rot.strip()) < 20:
                    continue

                clean_rot = clean_ocr_text(t_rot)
                m_rot = None
                if (
                    claimed_type in MRZ_SUPPORTED_TYPES and
                    claimed_type not in NON_MRZ_TYPES and
                    _has_structural_mrz_pattern(clean_rot)
                ):
                    m_rot = find_and_parse_mrz(clean_rot) or find_and_parse_mrz(t_rot)

                c_rot = classify_document_evidence(clean_rot, user_hint=doc_type_hint, mrz_data=m_rot)
                dt_rot = c_rot["detected_type"]
                if m_rot and m_rot.get("valid_structure") and dt_rot == DOC_TYPE_UNKNOWN:
                    dt_rot = DOC_TYPE_PASSPORT
                if dt_rot != DOC_TYPE_UNKNOWN:
                    raw_text = t_rot
                    cleaned_text = clean_rot
                    conf = 75.0
                    mrz_result = m_rot if dt_rot in MRZ_SUPPORTED_TYPES else None
                    detected_type = dt_rot
                    claimed_type = c_rot["claimed_type"]
                    is_claimed_mismatch = c_rot["is_claimed_mismatch"]
                    is_non_identity = c_rot["is_non_identity"]
                    mismatch_reason = c_rot["mismatch_reason"]
                    break

    fields: Dict[str, Any] = {}

    if detected_type == DOC_TYPE_PASSPORT:
        fields = parse_passport_fields(cleaned_text, mrz_result)
    elif detected_type == DOC_TYPE_VISA:
        fields = parse_visa_fields(cleaned_text)
    elif detected_type == DOC_TYPE_DRIVING_LICENSE:
        fields = parse_driving_license_fields(cleaned_text)
    elif detected_type == DOC_TYPE_PERMIT:
        fields = parse_permit_fields(cleaned_text)
    elif detected_type == DOC_TYPE_AADHAAR:
        fields = parse_aadhaar_fields(cleaned_text)
    elif detected_type == DOC_TYPE_PAN:
        fields = parse_pan_fields(cleaned_text)
        # Targeted red-channel enhancement if PAN number was obscured by glare or waves
        if not fields.get("id_number"):
            try:
                if isinstance(image_input, Image.Image):
                    cv_bgr = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
                elif isinstance(image_input, np.ndarray):
                    cv_bgr = image_input.copy()
                else:
                    cv_bgr = None

                if cv_bgr is not None:
                    red_ch = cv_bgr[:, :, 2] if len(cv_bgr.shape) == 3 else cv_bgr
                    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
                    enhanced_red = clahe.apply(red_ch)

                    for psm_mode in [6, 4, 11]:
                        t_extra = pytesseract.image_to_string(enhanced_red, config=f"--oem 3 --psm {psm_mode}")
                        if t_extra:
                            f_extra = parse_pan_fields(clean_ocr_text(t_extra))
                            if f_extra.get("id_number"):
                                fields["id_number"] = f_extra["id_number"]
                            if not fields.get("name") and f_extra.get("name"):
                                fields["name"] = f_extra["name"]
                            if not fields.get("dob") and f_extra.get("dob"):
                                fields["dob"] = f_extra["dob"]
                            if fields.get("id_number"):
                                raw_text += "\n" + t_extra
                                cleaned_text += "\n" + clean_ocr_text(t_extra)
                                break
            except Exception:
                pass
    elif detected_type == DOC_TYPE_BUSINESS_CARD:
        fields = parse_business_card_fields(cleaned_text)
    else:
        # Generic fallback
        fields = {
            "name": None,
            "id_number": None,
            "raw_numbers": re.findall(r"\b[A-Z0-9]{6,16}\b", cleaned_text.upper()),
            "dates": re.findall(r"\b\d{2}[/\-\.]\d{2}[/\-\.]\d{4}\b", cleaned_text)
        }

    return {
        "raw_text": raw_text,
        "cleaned_text": cleaned_text,
        "mean_confidence": conf,
        "ocr_confidence": conf,
        "confidence": conf,
        "doc_type": detected_type,
        "document_type": detected_type,
        "claimed_type": claimed_type,
        "is_claimed_mismatch": is_claimed_mismatch,
        "is_non_identity": is_non_identity,
        "mismatch_reason": mismatch_reason,
        "classification_evidence": classification.get("evidence", {}),
        "uncertainty": classification.get("uncertainty", False),
        "classification_scores": classification.get("scores", {}),
        "fields": fields,
        "mrz": mrz_result
    }
