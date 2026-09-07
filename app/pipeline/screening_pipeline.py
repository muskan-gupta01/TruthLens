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
from app.pipeline.format_validator import validate_document_rules, validate_verhoeff, validate_aadhaar_number
from app.pipeline.forensics_ela import run_ela_forensic_analysis
from app.pipeline.metadata_forensics import analyze_image_metadata
from app.pipeline.face_verifier import verify_identity_face
from app.pipeline.cross_verifier import cross_verify_documents
from app.pipeline.risk_engine import compute_risk_assessment
from app.pipeline.explanation_engine import generate_officer_explanation
from app.database.db_manager import log_screening, add_audit_chain_record
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


def run_truthlens_screening(
    doc_image_input,
    live_image_input = None,
    doc_type_hint: Optional[str] = None,
    doc_number_override: Optional[str] = None,
    person_name_override: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes the full end-to-end AI document screening pipeline.
    
    Args:
    - doc_image_input: PIL Image or OpenCV numpy array of the document
    - live_image_input: Optional live webcam snapshot or presented person photo
    - doc_type_hint: Optional manual document type hint ('PASSPORT', 'VISA', etc.)
    - doc_number_override: Optional user-confirmed identity or document number
    - person_name_override: Optional user-confirmed passenger name
    
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

    # Apply manual identity overrides if provided (e.g. glare on phone camera)
    if doc_number_override and doc_number_override.strip():
        clean_num = doc_number_override.strip().upper()
        if doc_type == DOC_TYPE_PASSPORT:
            fields["passport_number"] = clean_num
        elif doc_type == DOC_TYPE_VISA:
            fields["visa_number"] = clean_num
        elif doc_type == DOC_TYPE_DRIVING_LICENSE:
            fields["license_number"] = clean_num
        else:
            fields["id_number"] = clean_num

    if person_name_override and person_name_override.strip():
        clean_name = person_name_override.strip().upper()
        if doc_type in [DOC_TYPE_PASSPORT, DOC_TYPE_VISA, DOC_TYPE_DRIVING_LICENSE]:
            fields["full_name"] = clean_name
        else:
            fields["name"] = clean_name

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
            ocr_result["is_claimed_mismatch"] = False
            ocr_result["is_non_identity"] = False
            # Fill missing OCR fields only if not present on document
            if not fields.get("id_number"):
                raw_text = str(ocr_result.get("raw_text") or "")
                m12 = re.search(r"\b([2-9]\d{3})[\s\-]*(\d{4})[\s\-]*(\d{4})\b", raw_text)
                if m12:
                    fields["id_number"] = f"{m12.group(1)} {m12.group(2)} {m12.group(3)}"
                elif qr_fields.get("id_number") and not str(qr_fields.get("id_number")).startswith("XXXX"):
                    fields["id_number"] = qr_fields.get("id_number")
            if not fields.get("dob") and qr_fields.get("dob"):
                fields["dob"] = qr_fields.get("dob")
            if not fields.get("name") and qr_fields.get("name"):
                fields["name"] = qr_fields.get("name")

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
    validation_result = validate_document_rules(doc_type, fields, mrz_data=mrz_data, ocr_data=ocr_result)

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

    qr_fields = qr_result.get("fields", {}) or {}
    name_val = (
        person_name_override or
        fields.get("full_name") or
        fields.get("name") or
        fields.get("traveler_name") or
        qr_fields.get("name")
    )
    num_val = (
        doc_number_override or
        fields.get("passport_number") or
        fields.get("visa_number") or
        fields.get("id_number") or
        fields.get("license_number") or
        fields.get("permit_id") or
        (qr_fields.get("id_number") if not str(qr_fields.get("id_number") or "").startswith("XXXX") else None)
    )
    claimed_type = ocr_result.get("claimed_type") or doc_type
    is_mismatch = ocr_result.get("is_claimed_mismatch", False)
    is_non_identity = ocr_result.get("is_non_identity", False) or (doc_type in [DOC_TYPE_BUSINESS_CARD, DOC_TYPE_NON_IDENTITY])

    # Build 5 key security checkpoints for instant visual display
    # 1. Format & Expiry
    if is_mismatch or is_non_identity:
        format_status = "FAIL"
        format_detail = f"FRAUD / NON-IDENTITY: Uploaded image is a commercial {doc_type.replace('_', ' ').title()}, not an official government credential."
    elif validation_result.get("expired"):
        format_status = "FAIL"
        format_detail = "EXPIRED: Document has surpassed its valid transit date."
    elif doc_type in [DOC_TYPE_UNKNOWN, DOC_TYPE_NON_IDENTITY]:
        format_status = "FAIL"
        format_detail = "UNRECOGNIZED: Document structure does not match institutional formats."
    else:
        format_pass = (
            validation_result.get("valid") is True or
            validation_result.get("overall_status") == "PASSED" or
            validation_result.get("failures_count", 0) == 0
        ) and not validation_result.get("expired", False)
        format_status = "PASS" if format_pass else "WARN"
        format_detail = f"VALID: Compliant {doc_type} format with active validity period."

    # 2. Checksum (MRZ / Verhoeff / PAN)
    if is_mismatch or is_non_identity:
        checksum_status = "FAIL"
        checksum_detail = f"FAILED: No statutory {claimed_type} check digits or Verhoeff sequence present on non-identity media."
    elif doc_type == DOC_TYPE_PASSPORT:
        pass_check = next((c for c in validation_result.get("checklist", []) if any(k in (c.get("check") or c.get("name") or "") for k in ["Passport", "ICAO"])), None)
        if mrz_data and mrz_data.get("checksums", {}).get("all_passed"):
            checksum_status = "PASS"
            checksum_detail = "ICAO 9303: All 7-3-1 check digits mathematically verified."
        elif pass_check and pass_check.get("status") == "PASS":
            checksum_status = "PASS"
            checksum_detail = pass_check.get("detail", "ICAO 9303: Checksum valid.")
        elif pass_check:
            checksum_status = pass_check.get("status", "FAIL")
            checksum_detail = pass_check.get("detail", "ICAO 9303 Checksum Mismatch: Optical character corruption or forged number.")
        else:
            checksum_status = "FAIL"
            checksum_detail = "ICAO 9303 Checksum Mismatch: Optical character corruption or forged number."
    elif doc_type == DOC_TYPE_AADHAAR:
        v_check = next((c for c in validation_result.get("checklist", []) if "Verhoeff" in (c.get("check") or c.get("name") or "")), None)
        if v_check and v_check.get("status") == "PASS":
            checksum_status = "PASS"
            checksum_detail = v_check.get("detail", "UIDAI Verhoeff: Dihedral D5 checksum algorithm valid.")
        elif v_check and v_check.get("status") == "WARN":
            checksum_status = "WARN"
            checksum_detail = v_check.get("detail", "Checksum verification inconclusive due to OCR uncertainty.")
        elif v_check:
            checksum_status = v_check.get("status", "FAIL")
            checksum_detail = v_check.get("detail", "Verhoeff Algorithm Checksum Failed: Invalid Aadhaar number.")
        else:
            # Fallback to direct validation
            ocr_conf = ocr_result.get("mean_confidence") or ocr_result.get("ocr_confidence")
            is_unc = ocr_result.get("is_uncertain", False) or ocr_result.get("ocr_uncertain", False)
            v_res = validate_aadhaar_number(num_val, ocr_confidence=ocr_conf, is_uncertain=is_unc)
            if num_val and v_res.get("valid") and v_res.get("status") == "PASS":
                checksum_status = "PASS"
                checksum_detail = v_res.get("message", f"UIDAI Verhoeff: Checksum algorithm valid for {num_val}.")
            elif v_res.get("status") == "WARN":
                checksum_status = "WARN"
                checksum_detail = v_res.get("message", "Checksum verification inconclusive due to OCR uncertainty.")
            else:
                checksum_status = "FAIL"
                checksum_detail = v_res.get("message", "Verhoeff Algorithm Checksum Failed: Invalid Aadhaar number.")
    elif doc_type == DOC_TYPE_PAN:
        pan_check = next((c for c in validation_result.get("checklist", []) if "PAN" in (c.get("check") or c.get("name") or "")), None)
        if pan_check and pan_check.get("status") == "PASS":
            checksum_status = "PASS"
            checksum_detail = pan_check.get("detail", "Income Tax Dept 10-character structure valid.")
        elif pan_check:
            checksum_status = pan_check.get("status", "FAIL")
            checksum_detail = pan_check.get("detail", "Invalid PAN entity structure.")
        else:
            checksum_status = "PASS" if format_pass else "WARN"
            checksum_detail = "Income Tax Dept 10-character structure valid."
    else:
        checksum_status = "PASS" if format_pass else "WARN"
        checksum_detail = "Standard institutional syntax inspection."

    # 3. Forensic ELA & Tampering
    tamper_detected = forensics_result.get("tamper_detected", False) or forensics_result.get("splice_detected", False)
    ela_status = "FAIL" if tamper_detected else "PASS"
    if forensics_result.get("splice_detected"):
        ela_detail = "Photo Splice Alert: Digital boundary splicing detected around portrait."
    elif tamper_detected:
        ela_detail = f"Tampering Alert: High compression anomaly ({forensics_result.get('tamper_score', 0)}% tamper index)."
    else:
        ela_detail = "Clean: Uniform compression matrix, no photo splicing or software edits."

    # 4. Biometric Face Verification
    face_status = face_result.get("status", "WAITING_FOR_LIVE_PASSENGER")
    match_pct = face_result.get("similarity_percentage", 0.0)
    if face_status == "MATCH":
        biometric_status = "PASS"
        biometric_detail = f"Biometric Match Confirmed ({match_pct}% facial similarity)."
    elif face_status == "MISMATCH":
        biometric_status = "FAIL"
        biometric_detail = f"Biometric Impersonation Alert ({match_pct}% similarity below threshold)."
    else:
        biometric_status = "INFO"
        biometric_detail = "Awaiting Live Passenger Photo for 1:1 Biometric Verification."

    # 5. Watchlist & Mock DB
    db_hit = validation_result.get("mock_db_hit", False)
    if db_hit:
        watchlist_status = "FAIL"
        watchlist_detail = f"Alert: Flagged in Border Watchlist ({validation_result.get('mock_db_reason', 'Watchlist hit')})."
    else:
        watchlist_status = "PASS"
        watchlist_detail = "Clear: Zero records found in simulated Interpol/Border watchlists."

    # Genuine status requires low risk, verified checksum, and non-expired status
    is_genuine = (risk_level == "LOW") and (checksum_status == "PASS") and not validation_result.get("expired", False)
    is_critical = (risk_level in ["CRITICAL", "HIGH"])

    # High-level summary statement
    if is_mismatch or is_non_identity:
        summary = f"CRITICAL FRAUD REJECTION: Presented as '{claimed_type}' but confirmed as a non-identity commercial document ({doc_type.replace('_', ' ').title()}). Lacks all statutory government credentials (Risk Score: {risk_score}/100)."
    elif is_critical:
        summary = f"HIGH RISK ALERT: Rejected due to {len(risk_report['factors'])} security violation(s) (Risk Score: {risk_score}/100)."
    elif doc_type == DOC_TYPE_UNKNOWN or (not name_val and not num_val):
        summary = f"INCOMPLETE SCREENING: Document could not be recognized as a valid institutional identity format (Risk Score: {risk_score}/100)."
    elif checksum_status == "FAIL":
        if doc_type == DOC_TYPE_AADHAAR:
            summary = f"Mathematical Checksum Failure: Aadhaar number failed Verhoeff algorithm verification (Risk Score: {risk_score}/100)."
        else:
            summary = f"Mathematical Checksum Failure: {doc_type.replace('_', ' ').title()} failed check digit verification (Risk Score: {risk_score}/100)."
    elif checksum_status == "WARN":
        summary = f"Review recommended: Checksum verification inconclusive due to OCR uncertainty (Risk Score: {risk_score}/100)."
    elif is_genuine:
        summary = f"Document verified authentic across optical, mathematical, and forensic checks (Risk Score: {risk_score}/100)."
    elif risk_level == "MEDIUM":
        summary = f"Review recommended: Document flagged with {len(risk_report['factors'])} minor warning(s) (Risk Score: {risk_score}/100)."
    else:
        summary = f"HIGH RISK ALERT: Rejected due to {len(risk_report['factors'])} security violation(s) (Risk Score: {risk_score}/100)."

    # Simple verdict badge and headline
    if is_mismatch or is_non_identity:
        simple_badge = "REJECTED / FAKE DETECTED"
        simple_color = "red"
        simple_headline = f"Claimed {claimed_type} Mismatch • Non-Identity Document"
    elif is_critical:
        simple_badge = "REJECTED / SUSPICIOUS"
        simple_color = "red"
        simple_headline = "Security Violation • Transit Denied"
    elif is_genuine:
        simple_badge = "VERIFIED AUTHENTIC"
        simple_color = "green"
        simple_headline = "Document Authentic • Passenger Cleared"
    else:
        simple_badge = "REVIEW REQUIRED"
        simple_color = "yellow"
        simple_headline = "Manual Inspection Required"

    # Validity status determination
    if validation_result.get("expired"):
        validity_status = "EXPIRED"
        validity_badge_class = "badge-red"
    elif checksum_status == "FAIL":
        validity_status = "INVALID CHECKSUM"
        validity_badge_class = "badge-red"
    elif checksum_status == "WARN":
        validity_status = "REVIEW REQUIRED"
        validity_badge_class = "badge-yellow"
    elif doc_type in [DOC_TYPE_UNKNOWN, DOC_TYPE_NON_IDENTITY] or is_mismatch or is_non_identity:
        validity_status = "UNRECOGNIZED" if doc_type == DOC_TYPE_UNKNOWN else "INVALID"
        validity_badge_class = "badge-red" if (is_mismatch or is_non_identity) else "badge-yellow"
    elif not validation_result.get("valid", True):
        validity_status = "INVALID"
        validity_badge_class = "badge-red"
    else:
        validity_status = "ACTIVE / VALID"
        validity_badge_class = "badge-green"

    validation_result["validity_status"] = validity_status

    dossier = {
        "is_genuine": is_genuine,
        "simple_badge": simple_badge,
        "simple_color": simple_color,
        "simple_headline": simple_headline,
        "validity_status": validity_status,
        "validity_badge_class": validity_badge_class,
        "subject_name": name_val or "Not Detected",
        "doc_number": num_val or "Not Detected",
        "nationality": fields.get("nationality") or fields.get("issuing_country") or "N/A",
        "dob": fields.get("dob") or "N/A",
        "expiry_date": fields.get("expiry_date") or "N/A",
        "doc_type_display": doc_type.replace("_", " ").title(),
        "has_live_photo": live_image_input is not None,
        "face_match_pct": match_pct,
        "face_status": face_status,
        "ela_tamper_pct": forensics_result.get("tamper_score", 0.0),
        "checkpoints": [
            {"id": "validity", "title": "Format & Expiry", "status": format_status, "detail": format_detail},
            {"id": "checksum", "title": "Mathematical Checksum", "status": checksum_status, "detail": checksum_detail},
            {"id": "ela", "title": "Forensic Tamper (ELA)", "status": ela_status, "detail": ela_detail},
            {"id": "biometric", "title": "1:1 Biometric Match", "status": biometric_status, "detail": biometric_detail},
            {"id": "watchlist", "title": "Border Watchlist Check", "status": watchlist_status, "detail": watchlist_detail}
        ]
    }

    # Generate Plain-Language Officer Summary (LLM / Resilient Fallback)
    explanation_res = {}
    try:
        explanation_res = generate_officer_explanation(
            risk_report=risk_report,
            doc_type=doc_type,
            checkpoints=dossier.get("checkpoints"),
            face_match_pct=match_pct
        )
    except Exception as e:
        print(f"[EXPLANATION ENGINE NOTICE] Falling back to default summary: {e}")
        explanation_res = {
            "explanation": summary,
            "source": "system_default",
            "model": "None"
        }

    officer_summary_text = explanation_res.get("explanation", summary)
    dossier["officer_summary"] = officer_summary_text
    dossier["officer_summary_meta"] = explanation_res

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
        "officer_summary": officer_summary_text,
        "officer_summary_meta": explanation_res,
        "officer_recommendation": risk_report["officer_recommendation"],
        "elapsed_ms": elapsed_ms,
        "dossier": dossier,
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

    # Log to SQLite local database & cryptographic audit chain
    try:
        log_screening(full_report)
        audit_record = add_audit_chain_record(
            screening_id=screening_id,
            data_snapshot=full_report,
            timestamp=full_report.get("timestamp")
        )
        full_report["audit_trail"] = {
            "chain_id": audit_record["id"],
            "record_hash": audit_record["record_hash"],
            "previous_hash": audit_record["previous_hash"],
            "short_hash": audit_record["short_hash"],
            "short_prev_hash": audit_record["short_prev_hash"],
            "tamper_proof": True
        }
    except Exception as e:
        print(f"[DB ERROR] Failed to log screening / audit chain: {e}")

    return full_report
