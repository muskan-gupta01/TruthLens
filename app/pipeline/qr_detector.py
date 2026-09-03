"""
QR Code Detection & Cryptographic Data Extraction Module
TruthLens - AI-Based Fake Identity & Document Screening System

Features:
1. Multi-Engine Detection: Combines cv2.QRCodeDetectorAruco and cv2.QRCodeDetector.
2. Multi-Scale & Multi-Pass: Tests multi-scale pyramids, CLAHE, Adaptive Thresholding, and crops.
3. Multi-Orientation: Handles rotated phone camera images (0°, 90°, 180°, 270°).
4. Full UIDAI Support:
   - UIDAI Secure QR Code V2 (Decompresses big-integer DEFLATE stream used in modern 2018+ Aadhaar).
   - Legacy UIDAI XML Barcode payload (<PrintLetterBarcodeData ... />).
   - JSON payloads & key-value tokens.
"""
import re
import xml.etree.ElementTree as ET
import json
import zlib
import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any, Optional, Tuple, List


def _parse_uidai_secure_qr(payload: str) -> Optional[Dict[str, Any]]:
    """
    Parses UIDAI Secure QR Code V2 (used on post-2018 Aadhaar cards, e-Aadhaar, PVC cards).
    The QR data is encoded as a massive Base10 big-integer representing a zlib-compressed byte array.
    Decompressed fields are delimited by byte 255 (0xFF).
    """
    clean_p = payload.strip()
    if not clean_p.isdigit() or len(clean_p) < 200:
        return None

    try:
        big_int = int(clean_p)
        byte_len = (big_int.bit_length() + 7) // 8
        raw_bytes = big_int.to_bytes(byte_len, "big")

        decomp = None
        for w in [16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS]:
            try:
                decomp = zlib.decompress(raw_bytes, w)
                break
            except Exception:
                pass

        if not decomp:
            decomp = zlib.decompress(raw_bytes)

        # Split fields by separator 0xFF (byte 255)
        parts = decomp.split(b"\xff")
        if len(parts) >= 5:
            ref_id = parts[1].decode("utf-8", errors="ignore").strip()
            # In UIDAI V2, first 4 chars of reference_id correspond to last 4 digits of Aadhaar
            last_4 = ref_id[:4] if len(ref_id) >= 4 and ref_id[:4].isdigit() else ""
            name = parts[2].decode("utf-8", errors="ignore").strip()
            dob = parts[3].decode("utf-8", errors="ignore").strip()
            gender_raw = parts[4].decode("utf-8", errors="ignore").strip()

            gender = "MALE" if gender_raw.upper().startswith("M") else (
                "FEMALE" if gender_raw.upper().startswith("F") else gender_raw.upper()
            )

            # Extract location details if available
            address_parts = []
            for idx in [5, 6, 7, 8, 9, 11, 12, 13, 14, 15]:
                if len(parts) > idx:
                    val = parts[idx].decode("utf-8", errors="ignore").strip()
                    if val and len(val) > 1:
                        address_parts.append(val)

            pincode = parts[10].decode("utf-8", errors="ignore").strip() if len(parts) > 10 else ""

            return {
                "name": name,
                "id_number": f"XXXX XXXX {last_4}" if last_4 else ref_id,
                "dob": dob,
                "gender": gender,
                "format": "UIDAI_SECURE_QR_V2",
                "ref_id": ref_id,
                "attributes": {
                    "pincode": pincode,
                    "address": ", ".join(address_parts[:3])
                }
            }
    except Exception:
        pass
    return None


def _parse_aadhaar_xml(payload: str) -> Optional[Dict[str, Any]]:
    """
    Parses standard UIDAI XML barcode data formatted as:
    <PrintLetterBarcodeData uid="123456789012" name="Aakash Verma" gender="M"
    yob="1995" dob="12/05/1995" ... />
    """
    try:
        xml_match = re.search(r"<PrintLetterBarcodeData[^>]*>", payload)
        if not xml_match:
            return None

        xml_content = xml_match.group(0)
        if not xml_content.endswith("/>"):
            xml_content = xml_content[:-1] + "/>"

        root = ET.fromstring(xml_content)
        attrs = {k.lower(): v for k, v in root.attrib.items()}

        uid = attrs.get("uid", "")
        name = attrs.get("name", "")
        gender_code = attrs.get("gender", "")
        gender = "MALE" if gender_code.upper() in ("M", "MALE") else ("FEMALE" if gender_code.upper() in ("F", "FEMALE") else gender_code)
        dob = attrs.get("dob") or attrs.get("yob", "")

        return {
            "name": name,
            "id_number": uid,
            "dob": dob,
            "gender": gender,
            "format": "UIDAI_XML",
            "attributes": attrs
        }
    except Exception:
        return None


def _parse_json_payload(payload: str) -> Optional[Dict[str, Any]]:
    """
    Parses structured JSON payloads embedded in QR codes.
    """
    try:
        data = json.loads(payload)
        if isinstance(data, dict):
            d_norm = {k.lower().replace(" ", "_"): v for k, v in data.items()}
            return {
                "name": str(d_norm.get("name") or d_norm.get("full_name") or ""),
                "id_number": str(d_norm.get("uid") or d_norm.get("aadhaar") or d_norm.get("id_number") or d_norm.get("pan") or ""),
                "dob": str(d_norm.get("dob") or d_norm.get("date_of_birth") or d_norm.get("yob") or ""),
                "gender": str(d_norm.get("gender") or "").upper(),
                "format": "JSON",
                "attributes": d_norm
            }
    except Exception:
        pass
    return None


def _parse_text_payload(payload: str) -> Dict[str, Any]:
    """
    Parses unstructured or line-delimited key: value QR payloads.
    """
    fields = {"name": "", "id_number": "", "dob": "", "gender": "", "format": "RAW_TEXT"}

    # Name match
    name_m = re.search(r"(?:name|nom)\s*[:=]\s*([^\n,]+)", payload, re.IGNORECASE)
    if name_m:
        fields["name"] = name_m.group(1).strip()

    # ID Number match (Aadhaar or PAN)
    id_m = re.search(r"\b([2-9]\d{3}\s?\d{4}\s?\d{4})\b", payload)
    if not id_m:
        id_m = re.search(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", payload)
    if not id_m:
        id_m = re.search(r"\b([X\*\.x]{4}\s?[X\*\.x]{4}\s?\d{4})\b", payload)
    if id_m:
        fields["id_number"] = id_m.group(1).strip()

    # DOB match
    dob_m = re.search(r"(?:dob|birth)\s*[:=]\s*(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})", payload, re.IGNORECASE)
    if not dob_m:
        dob_m = re.search(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b", payload)
    if dob_m:
        fields["dob"] = dob_m.group(1).strip()

    # Gender
    gen_m = re.search(r"\b(MALE|FEMALE|TRANSGENDER)\b", payload, re.IGNORECASE)
    if gen_m:
        fields["gender"] = gen_m.group(1).upper()

    return fields


def parse_qr_payload(payload: str) -> Dict[str, Any]:
    """
    Intelligently parses any decoded QR payload into standardized identity fields.
    Supports modern UIDAI V2 Secure QR (DEFLATE big-int), XML, JSON, and text tokens.
    """
    if not payload:
        return {"name": "", "id_number": "", "dob": "", "gender": "", "format": "EMPTY"}

    # 1. Try UIDAI Secure QR V2 (Compressed big integer)
    v2_result = _parse_uidai_secure_qr(payload)
    if v2_result:
        return v2_result

    # 2. Try UIDAI XML Barcode
    xml_result = _parse_aadhaar_xml(payload)
    if xml_result:
        return xml_result

    # 3. Try JSON
    json_result = _parse_json_payload(payload)
    if json_result:
        return json_result

    # 4. Fallback to Key-Value parsing
    return _parse_text_payload(payload)


def _try_decode_image(detector, cv_img: np.ndarray) -> Tuple[str, Any]:
    """Attempts to decode a QR code from an image using the given OpenCV detector."""
    try:
        decoded_text, points, _ = detector.detectAndDecode(cv_img)
        if decoded_text and len(decoded_text.strip()) > 0:
            return decoded_text.strip(), points
    except Exception:
        pass
    return "", None


def detect_and_decode_qr(image_input) -> Dict[str, Any]:
    """
    Industrial-grade QR detection:
    Applies multi-engine detection (QRCodeDetectorAruco + QRCodeDetector), multi-scale pyramids,
    CLAHE, adaptive thresholding, and regional sub-crops to read real photographed cards.
    """
    if isinstance(image_input, Image.Image):
        cv_img = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        cv_img = image_input.copy()
    else:
        raise ValueError("Unsupported image type for QR detection")

    # Detectors: Aruco is superior for distorted/high-density QRs; standard is fallback
    detectors = [cv2.QRCodeDetectorAruco(), cv2.QRCodeDetector()]

    h, w = cv_img.shape[:2]

    # Generate multi-scale candidate images
    scale_images: List[np.ndarray] = [cv_img]
    if max(h, w) > 1600:
        s1 = 1200.0 / max(h, w)
        scale_images.append(cv2.resize(cv_img, (int(w * s1), int(h * s1)), interpolation=cv2.INTER_AREA))
        s2 = 1600.0 / max(h, w)
        scale_images.append(cv2.resize(cv_img, (int(w * s2), int(h * s2)), interpolation=cv2.INTER_AREA))
    elif max(h, w) < 700:
        scale_images.append(cv2.resize(cv_img, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC))

    decoded_text = ""
    points = None

    # Step 1: Search across multi-scale images with multiple enhancements
    for cur_img in scale_images:
        cur_gray = cv2.cvtColor(cur_img, cv2.COLOR_BGR2GRAY) if len(cur_img.shape) == 3 else cur_img

        # Enhancement variations:
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(cur_gray)
        # Adaptive thresholding handles flash glare and non-uniform shadows on physical cards
        adapt_thresh1 = cv2.adaptiveThreshold(cur_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 25, 5)
        adapt_thresh2 = cv2.adaptiveThreshold(cur_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 41, 7)
        _, otsu_thresh = cv2.threshold(cur_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        passes = [cur_img, cur_gray, clahe, adapt_thresh1, adapt_thresh2, otsu_thresh]

        for detector in detectors:
            for p_img in passes:
                txt, pts = _try_decode_image(detector, p_img)
                if txt:
                    decoded_text = txt
                    points = pts
                    break
            if decoded_text:
                break
        if decoded_text:
            break

    # Step 2: Regional crop scan (if whole-image scan missed a small or peripheral QR code)
    if not decoded_text:
        ch, cw = cv_img.shape[:2]
        crop_boxes = [
            ("right_half", cv_img[0:ch, int(cw * 0.35):cw]),
            ("bottom_right", cv_img[int(ch * 0.25):ch, int(cw * 0.35):cw]),
            ("bottom_half", cv_img[int(ch * 0.35):ch, 0:cw]),
            ("left_half", cv_img[0:ch, 0:int(cw * 0.65)])
        ]
        for _, crop in crop_boxes:
            c_gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if len(crop.shape) == 3 else crop
            c_clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(c_gray)
            c_adapt = cv2.adaptiveThreshold(c_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5)

            for detector in detectors:
                for c_pass in [crop, c_gray, c_clahe, c_adapt]:
                    txt, pts = _try_decode_image(detector, c_pass)
                    if txt:
                        decoded_text = txt
                        points = pts
                        break
                if decoded_text:
                    break
            if decoded_text:
                break

    # Step 3: Multi-rotation scan (for smartphone photos taken in portrait orientation)
    if not decoded_text:
        for rot in [cv2.ROTATE_90_CLOCKWISE, cv2.ROTATE_180, cv2.ROTATE_90_COUNTERCLOCKWISE]:
            rot_img = cv2.rotate(cv_img, rot)
            rot_gray = cv2.cvtColor(rot_img, cv2.COLOR_BGR2GRAY)
            rot_clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(rot_gray)
            rot_adapt = cv2.adaptiveThreshold(rot_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5)

            for detector in detectors:
                for r_pass in [rot_img, rot_clahe, rot_adapt]:
                    txt, pts = _try_decode_image(detector, r_pass)
                    if txt:
                        decoded_text = txt
                        points = pts
                        break
                if decoded_text:
                    break
            if decoded_text:
                break

    detected = points is not None and len(points) > 0
    decoded = bool(decoded_text and len(decoded_text.strip()) > 0)

    bbox = []
    if detected and points is not None:
        try:
            pts = points.reshape(-1, 2).astype(int).tolist()
            bbox = pts
        except Exception:
            bbox = []

    parsed_fields = parse_qr_payload(decoded_text) if decoded else {}

    return {
        "detected": detected,
        "decoded": decoded,
        "raw_payload": decoded_text if decoded else "",
        "fields": parsed_fields,
        "bbox": bbox
    }
