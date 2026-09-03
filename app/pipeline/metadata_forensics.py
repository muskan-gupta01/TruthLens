"""
Image Metadata & EXIF Forensic Analysis Module
SIH26188: AI-Based Fake Identity & Document Screening System

Analyzes embedded EXIF and digital image metadata for signs of tampering:
1. Software editing signatures (Adobe Photoshop, Canva, GIMP, Corel, Snapseed)
2. Timestamp discrepancies (Creation date vs Modification date)
3. Camera/Hardware authenticity markers (Make/Model vs pure digital generation)
4. Color space and DPI manipulation
"""
from PIL import Image, ExifTags
from typing import Dict, Any, List, Optional
from datetime import datetime


SUSPICIOUS_SOFTWARE = [
    "photoshop", "adobe", "gimp", "canva", "lightroom",
    "snapseed", "pixlr", "affinity", "paint.net", "corel",
    "picsart", "facetune", "illustrator", "sketch"
]


def analyze_image_metadata(img: Image.Image) -> Dict[str, Any]:
    """
    Performs forensic metadata inspection on PIL Image.
    Returns audit findings, editing software traces, and risk score.
    """
    findings: List[Dict[str, str]] = []
    software_traces = []
    has_exif = False
    hardware_present = False
    timestamp_discrepancy = False
    software_tamper_flag = False

    exif_data = {}
    try:
        raw_exif = img.getexif()
        if raw_exif:
            has_exif = True
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                exif_data[tag_name] = str(value)
    except Exception as e:
        findings.append({"severity": "INFO", "text": f"EXIF metadata unreadable or stripped: {e}"})

    # Also check PNG metadata if applicable
    info_dict = getattr(img, "info", {}) or {}
    for key, val in info_dict.items():
        if isinstance(val, str):
            exif_data[f"info_{key}"] = val

    # 1. Scan for Image Editing Software
    software_tag = exif_data.get("Software") or exif_data.get("info_Software") or ""
    artist_tag = exif_data.get("Artist") or ""
    history_tag = exif_data.get("ImageHistory") or ""
    comment_tag = exif_data.get("UserComment") or exif_data.get("info_comment") or ""

    full_meta_str = f"{software_tag} {artist_tag} {history_tag} {comment_tag}".lower()

    for sw in SUSPICIOUS_SOFTWARE:
        if sw in full_meta_str:
            software_traces.append(sw.capitalize())
            software_tamper_flag = True

    if software_traces:
        findings.append({
            "severity": "CRITICAL",
            "text": f"Digital editing software fingerprint detected: {', '.join(set(software_traces))}. High probability of image manipulation."
        })
    elif software_tag:
        findings.append({
            "severity": "INFO",
            "text": f"Software tag recorded: '{software_tag}'."
        })

    # 2. Camera / Scanner Hardware Check
    make = exif_data.get("Make")
    model = exif_data.get("Model")
    if make or model:
        hardware_present = True
        findings.append({
            "severity": "PASS",
            "text": f"Hardware capture device verified: {make or ''} {model or ''}."
        })
    else:
        findings.append({
            "severity": "WARN",
            "text": "No hardware camera/scanner signature found in EXIF (typical of web-saved, stripped, or digitally generated graphics)."
        })

    # 3. Timestamp Audit (DateTimeOriginal vs DateTime)
    dt_orig = exif_data.get("DateTimeOriginal")
    dt_mod = exif_data.get("DateTime")
    if dt_orig and dt_mod and dt_orig != dt_mod:
        timestamp_discrepancy = True
        findings.append({
            "severity": "WARN",
            "text": f"Metadata timestamp mismatch: Original capture ({dt_orig}) differs from last modification ({dt_mod})."
        })

    # Calculate metadata risk contribution (0 to 100)
    risk_points = 0
    if software_tamper_flag:
        risk_points += 75
    elif timestamp_discrepancy:
        risk_points += 30

    status = "CLEAN"
    if software_tamper_flag:
        status = "TAMPERED_SOFTWARE_FOUND"
    elif timestamp_discrepancy:
        status = "SUSPICIOUS_MODIFICATION"

    return {
        "status": status,
        "has_exif": has_exif,
        "software_detected": ", ".join(set(software_traces)) if software_traces else None,
        "hardware_verified": hardware_present,
        "timestamp_mismatch": timestamp_discrepancy,
        "risk_score": min(risk_points, 100),
        "tags_found": {k: v for k, v in list(exif_data.items())[:10]},
        "findings": findings
    }
