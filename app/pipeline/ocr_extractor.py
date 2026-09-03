"""
OCR Extraction Module
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188 (Ministry of Home Affairs - Blockchain & Cybersecurity)

Performs Optical Character Recognition (OCR) using pytesseract with
specialized image preprocessing (CLAHE + Bilateral filtering).
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
    DOC_TYPE_UNKNOWN
)
from app.pipeline.mrz_parser import find_and_parse_mrz

# Configure Tesseract binary path if available
if TESSERACT_PATH:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


def preprocess_image_for_ocr(cv_image: np.ndarray) -> np.ndarray:
    """
    Applies image preprocessing to improve OCR accuracy:
    1. Grayscale conversion
    2. Bilateral filtering (smoothes noise while keeping text edges sharp)
    3. CLAHE (Contrast Limited Adaptive Histogram Equalization)
    """
    if len(cv_image.shape) == 3:
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv_image.copy()

    h, w = gray.shape[:2]
    if w < 1000:
        scale = 1000.0 / w
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

    # Bilateral filter reduces noise while preserving text sharpness
    denoised = cv2.bilateralFilter(gray, 9, 75, 75)

    # Adaptive histogram equalization (CLAHE) for high local contrast
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(denoised)

    return enhanced


def extract_text_and_data(image_input) -> Tuple[str, float]:
    """
    Runs pytesseract on the preprocessed image.
    Returns:
    - raw_text: complete extracted text string
    - mean_confidence: average OCR confidence percentage (0 - 100)
    """
    if isinstance(image_input, Image.Image):
        cv_img = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        cv_img = image_input
    else:
        raise ValueError("Unsupported image type for OCR extraction")

    preprocessed = preprocess_image_for_ocr(cv_img)
    custom_config = r"--oem 3 --psm 3"

    try:
        data = pytesseract.image_to_data(preprocessed, output_type=Output.DICT, config=custom_config)
        raw_text = pytesseract.image_to_string(preprocessed, config=custom_config)

        confidences = [
            int(conf) for conf in data["conf"]
            if conf != "-1" and str(conf).isdigit() and int(conf) > 0
        ]
        mean_conf = float(np.mean(confidences)) if confidences else 65.0
        return raw_text, round(mean_conf, 1)

    except Exception as e:
        print(f"[OCR ERROR] Failed to run pytesseract: {e}")
        return "", 0.0


def identify_document_type(text: str, user_hint: Optional[str] = None) -> str:
    """
    Determines document type based on characteristic institutional keywords or user hint.
    """
    if user_hint and user_hint in [
        DOC_TYPE_PASSPORT, DOC_TYPE_VISA, DOC_TYPE_DRIVING_LICENSE,
        DOC_TYPE_PERMIT, DOC_TYPE_AADHAAR, DOC_TYPE_PAN
    ]:
        return user_hint

    text_upper = text.upper()
    clean_norm = " ".join(re.sub(r"[^A-Z0-9\s]", " ", text_upper).split())

    passport_keywords = [
        "PASSPORT", "PASSEPORT", "REPUBLIC OF", "UNITED STATES OF AMERICA",
        "P<", "NATIONALITY", "SURNAME", "GIVEN NAMES", "DATE OF EXPIRY", "PASSPORT NO"
    ]
    visa_keywords = [
        "VISA", "VALID FOR", "ENTRIES", "DURATION OF STAY", "TYPE OF VISA",
        "SCHENGEN", "STAY DURATION", "ENTRY TYPE", "VALID FROM", "VALID UNTIL"
    ]
    dl_keywords = [
        "DRIVING LICENCE", "DRIVING LICENSE", "MOTOR VEHICLES", "TRANSPORT",
        "DL NO", "AUTHORISATION TO DRIVE", "VEHICLE CLASS", "LMV", "MCWG"
    ]
    permit_keywords = [
        "TRAVEL PERMIT", "ENTRY AUTHORIZATION", "RESIDENCE PERMIT", "BORDER TRANSIT",
        "WORK PERMIT", "IMMIGRATION PERMIT"
    ]
    aadhaar_keywords = [
        "AADHAAR", "AADHAR", "UIDAI", "UNIQUE IDENTIFICATION", "AUTHORITY OF INDIA",
        "GOVERNMENT OF INDIA", "GOVT OF INDIA", "BHARAT SARKAR", "MERA AADHAAR", "MERI PEHCHAN"
    ]
    pan_keywords = [
        "INCOME TAX DEPARTMENT", "PERMANENT ACCOUNT NUMBER", "INCOMETAX", "PAN CARD"
    ]

    scores = {
        DOC_TYPE_PASSPORT: sum(2 for kw in passport_keywords if kw in text_upper or kw in clean_norm),
        DOC_TYPE_VISA: sum(2 for kw in visa_keywords if kw in text_upper or kw in clean_norm),
        DOC_TYPE_DRIVING_LICENSE: sum(2 for kw in dl_keywords if kw in text_upper or kw in clean_norm),
        DOC_TYPE_PERMIT: sum(2 for kw in permit_keywords if kw in text_upper or kw in clean_norm),
        DOC_TYPE_AADHAAR: sum(1 for kw in aadhaar_keywords if kw in text_upper or kw in clean_norm),
        DOC_TYPE_PAN: sum(1 for kw in pan_keywords if kw in text_upper or kw in clean_norm)
    }

    # Regex boost
    if re.search(r"P<[A-Z0-9<]{40,}", text):
        scores[DOC_TYPE_PASSPORT] += 6
    if re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text_upper):
        scores[DOC_TYPE_PAN] += 4
    if re.search(r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b", text):
        scores[DOC_TYPE_AADHAAR] += 4

    best_type = max(scores, key=scores.get)
    if scores[best_type] >= 2:
        return best_type

    return DOC_TYPE_UNKNOWN


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


def parse_aadhaar_fields(text: str) -> Dict[str, Any]:
    """Extracts Aadhaar fields."""
    fields: Dict[str, Any] = {"id_number": None, "dob": None, "gender": None, "name": None}
    id_match = re.search(r"\b([2-9]\d{3}\s\d{4}\s\d{4})\b", text)
    if id_match:
        fields["id_number"] = id_match.group(1).strip()
    else:
        m12 = re.search(r"\b(\d{4}\s\d{4}\s\d{4})\b", text)
        if m12:
            fields["id_number"] = m12.group(1).strip()

    dob_m = re.search(r"(?:DOB|Date of Birth|Birth)[\s:]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", text, re.IGNORECASE)
    if dob_m:
        fields["dob"] = dob_m.group(1)
    else:
        d_fb = re.search(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
        if d_fb:
            fields["dob"] = d_fb.group(1)

    if re.search(r"\b(MALE|PURUSH)\b", text, re.IGNORECASE):
        fields["gender"] = "MALE"
    elif re.search(r"\b(FEMALE|MAHILA)\b", text, re.IGNORECASE):
        fields["gender"] = "FEMALE"

    # Name extraction
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        if len(line) > 3 and not any(k in line.upper() for k in ["GOVERNMENT", "INDIA", "AADHAAR", "DOB", "MALE", "FEMALE"]):
            if re.match(r"^[A-Za-z\s]{3,30}$", line):
                fields["name"] = line
                break
    return fields


def parse_pan_fields(text: str) -> Dict[str, Any]:
    """Extracts PAN fields."""
    fields: Dict[str, Any] = {"id_number": None, "name": None, "father_name": None, "dob": None, "gender": None}
    pan_m = re.search(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", text.upper())
    if pan_m:
        fields["id_number"] = pan_m.group(1)
    dob_m = re.search(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", text)
    if dob_m:
        fields["dob"] = dob_m.group(1)
    return fields


def extract_document_fields(
    image_input,
    doc_type_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level OCR extraction orchestrator:
    1. Preprocesses image and runs OCR
    2. Scans for ICAO Doc 9303 MRZ lines
    3. Identifies document type (or applies user hint)
    4. Extracts structured identity/travel fields with fallbacks
    """
    raw_text, conf = extract_text_and_data(image_input)
    mrz_result = find_and_parse_mrz(raw_text)

    # Determine document type
    detected_type = identify_document_type(raw_text, user_hint=doc_type_hint)
    if mrz_result and mrz_result.get("valid_structure") and detected_type == DOC_TYPE_UNKNOWN:
        detected_type = DOC_TYPE_PASSPORT

    fields: Dict[str, Any] = {}

    if detected_type == DOC_TYPE_PASSPORT:
        fields = parse_passport_fields(raw_text, mrz_result)
    elif detected_type == DOC_TYPE_VISA:
        fields = parse_visa_fields(raw_text)
    elif detected_type == DOC_TYPE_DRIVING_LICENSE:
        fields = parse_driving_license_fields(raw_text)
    elif detected_type == DOC_TYPE_PERMIT:
        fields = parse_permit_fields(raw_text)
    elif detected_type == DOC_TYPE_AADHAAR:
        fields = parse_aadhaar_fields(raw_text)
    elif detected_type == DOC_TYPE_PAN:
        fields = parse_pan_fields(raw_text)
    else:
        # Generic fallback
        fields = {
            "raw_numbers": re.findall(r"\b[A-Z0-9]{6,16}\b", raw_text.upper()),
            "dates": re.findall(r"\b\d{2}[/\-\.]\d{2}[/\-\.]\d{4}\b", raw_text)
        }

    return {
        "raw_text": raw_text,
        "mean_confidence": conf,
        "doc_type": detected_type,
        "fields": fields,
        "mrz": mrz_result
    }
