"""
Master Screening Pipeline Coordinator
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188: Ministry of Home Affairs - Blockchain & Cybersecurity

Orchestrates the 7-step Border Control Screening Workflow:
1. Optical Character Recognition (OCR) + ICAO 9303 MRZ Parsing
2. QR Code Cryptographic Verification (if present)
3. Document Rule Validation (Checksums, Expiry, Border 6-Month Rule)
4. Digital Forensics: Error Level Analysis (ELA Heatmap, Facial ROI Splice, Stamp Check)
5. Metadata Forensics: EXIF signatures, Photoshop/Canva fingerprints
6. Biometric Face Verification: 1:1 Document Photo vs Live Passenger Photo
7. Risk Assessment Engine & Local SQLite Audit Trail Logging
"""
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from PIL import Image
import numpy as np

from app.pipeline.ocr_extractor import extract_document_fields
from app.pipeline.qr_detector import detect_and_decode_qr
from app.pipeline.format_validator import validate_document_rules
from app.pipeline.forensics_ela import run_ela_forensic_analysis
from app.pipeline.metadata_forensics import analyze_image_metadata
from app.pipeline.face_verifier import verify_identity_face
from app.pipeline.cross_verifier import cross_verify_documents
from app.pipeline.risk_engine import compute_risk_assessment
from app.database.db_manager import log_screening
from app.config import (
    DOC_TYPE_PASSPORT,
    DOC_TYPE_VISA,
    DOC_TYPE_DRIVING_LICENSE,
    DOC_TYPE_PERMIT,
    DOC_TYPE_AADHAAR,
    DOC_TYPE_PAN,
    DOC_TYPE_UNKNOWN
)


def run_truthlens_screening(
    doc_image_input,
    live_image_input = None,
    doc_type_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes the full end-to-end AI document screening pipeline.
    
    Args:
    - doc_image_input: PIL Image or OpenCV numpy array of the document
    - live_image_input: Optional live webcam snapshot or presented person photo
    - doc_type_hint: Optional manual document type hint ('PASSPORT', 'VISA', etc.)
    
    Returns:
    - Complete structured screening audit report with risk score, ELA heatmap,
      face crops, checklist, and final decision.
    """
    start_time = time.time()
    screening_id = f"TL-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Ensure doc_image is PIL Image for metadata inspection
    if isinstance(doc_image_input, np.ndarray):
        pil_doc = Image.fromarray(doc_image_input)
    elif isinstance(doc_image_input, Image.Image):
        pil_doc = doc_image_input
    else:
        raise ValueError("Invalid document image input type")

    # =========================================================================
    # STEP 1: OCR EXTRACTION & MRZ PARSER
    # =========================================================================
    ocr_result = extract_document_fields(doc_image_input, doc_type_hint=doc_type_hint)
    doc_type = ocr_result.get("doc_type", DOC_TYPE_UNKNOWN)
    mrz_data = ocr_result.get("mrz")
    fields = ocr_result.get("fields", {})

    # =========================================================================
    # STEP 2: QR CODE DECODE & CRYPTOGRAPHIC CROSS-VERIFICATION
    # =========================================================================
    qr_result = detect_and_decode_qr(doc_image_input)
    if qr_result.get("detected") and qr_result.get("decoded"):
        # If QR contains UIDAI data, sync doc type
        qr_fields = qr_result.get("fields", {})
        if "uidai" in str(qr_fields.get("format", "")).lower():
            doc_type = DOC_TYPE_AADHAAR
            ocr_result["doc_type"] = DOC_TYPE_AADHAAR
            # Fill missing OCR fields only if not present on document
            if not fields.get("id_number") and qr_fields.get("id_number"):
                fields["id_number"] = qr_fields.get("id_number")
            if not fields.get("dob") and qr_fields.get("dob"):
                fields["dob"] = qr_fields.get("dob")

    # Cryptographic cross-verification: Printed Document Text vs Encrypted QR Payload
    cross_result = cross_verify_documents(ocr_result, qr_result)

    # =========================================================================
    # STEP 3: BIOMETRIC FACE EXTRACTION & VERIFICATION
    # =========================================================================
    face_result = verify_identity_face(doc_image_input, live_image_input=live_image_input)
    face_bbox = None
    if face_result.get("doc_bounding_box"):
        b = face_result["doc_bounding_box"]
        face_bbox = (b["x"], b["y"], b["w"], b["h"])

    # =========================================================================
    # STEP 4: DIGITAL IMAGE FORENSICS (ELA, PHOTO SPLICE, STAMP ANALYSIS)
    # =========================================================================
    forensics_result = run_ela_forensic_analysis(doc_image_input, face_bbox=face_bbox, doc_type=doc_type)

    # =========================================================================
    # STEP 5: METADATA & EXIF FORENSICS
    # =========================================================================
    metadata_result = analyze_image_metadata(pil_doc)

    # =========================================================================
    # STEP 6: DOCUMENT RULES & MOCK DATABASE VALIDATION
    # =========================================================================
    validation_result = validate_document_rules(doc_type, fields, mrz_data=mrz_data)

    # =========================================================================
    # STEP 7: DYNAMIC RISK ASSESSMENT ENGINE & FINAL VERDICT
    # =========================================================================
    risk_report = compute_risk_assessment(
        validation_report=validation_result,
        forensics_report=forensics_result,
        metadata_report=metadata_result,
        face_report=face_result,
        ocr_report=ocr_result,
        cross_report=cross_result
    )

    elapsed_ms = round((time.time() - start_time) * 1000.0, 1)

    # Compile explainability audit points
    explainability: List[Dict[str, str]] = []
    for factor in risk_report.get("factors", []):
        explainability.append({
            "severity": factor["severity"],
            "text": f"[{factor['name']}] {factor['description']} (+{factor['points']} pts)"
        })

    # Add QR cross-verification items to audit trail
    if cross_result.get("qr_decoded"):
        for m in cross_result.get("verification_matrix", []):
            if m["status"] == "MATCH":
                explainability.append({
                    "severity": "PASS",
                    "text": f"[QR Match] {m['explanation']}"
                })
            elif m["status"] == "MISMATCH":
                explainability.append({
                    "severity": "CRITICAL",
                    "text": f"[QR Forgery Alert] {m['explanation']}"
                })

    for check in validation_result.get("checklist", []):
        if check["status"] == "PASS":
            explainability.append({
                "severity": "PASS",
                "text": check["detail"]
            })

    # High-level summary statement
    verdict = risk_report["verdict"]
    risk_level = risk_report["level"]
    risk_score = risk_report["score"]

    name_val = fields.get("full_name") or fields.get("name")
    num_val = fields.get("passport_number") or fields.get("visa_number") or fields.get("id_number")

    if doc_type == DOC_TYPE_UNKNOWN or (not name_val and not num_val):
        summary = f"INCOMPLETE SCREENING: Document could not be recognized as a valid institutional identity format (Risk Score: {risk_score}/100)."
    elif risk_level == "LOW":
        summary = f"Document verified authentic across optical, mathematical, and forensic checks (Risk Score: {risk_score}/100)."
    elif risk_level == "MEDIUM":
        summary = f"Review recommended: Document flagged with {len(risk_report['factors'])} minor warning(s) (Risk Score: {risk_score}/100)."
    else:
        summary = f"HIGH RISK ALERT: Rejected due to {len(risk_report['factors'])} security violation(s) (Risk Score: {risk_score}/100)."

    # Master audit record
    full_report = {
        "screening_id": screening_id,
        "timestamp": timestamp_str,
        "doc_type": doc_type,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": 92.0 if risk_level == "LOW" else 88.0,
        "summary": summary,
        "officer_recommendation": risk_report["officer_recommendation"],
        "elapsed_ms": elapsed_ms,
        "ocr": {
            "mean_confidence": ocr_result["mean_confidence"],
            "fields": fields,
            "raw_text": ocr_result["raw_text"],
            "mrz": mrz_data
        },
        "qr": {
            "detected": qr_result.get("detected", False),
            "decoded": qr_result.get("decoded", False),
            "data": qr_result.get("data", ""),
            "fields": qr_result.get("fields", {})
        },
        "validation": validation_result,
        "forensics_ela": forensics_result,
        "metadata_forensics": metadata_result,
        "face_verification": face_result,
        "cross_verification": cross_result,
        "risk_assessment": risk_report,
        "explainability": explainability
    }

    # Log to SQLite local database
    try:
        log_screening(full_report)
    except Exception as e:
        print(f"[DB ERROR] Failed to log screening: {e}")

    return full_report
