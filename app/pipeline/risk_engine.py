"""
Dynamic Risk Assessment & Explainable Decision Engine
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188: Ministry of Home Affairs - Blockchain & Cybersecurity

Calculates a calibrated risk score (0-100) and aggregates contributing risk factors from:
1. Document Validation failures & Checksum mismatches
2. Expired document / Border validity violations
3. Mock Database Watchlist & Blacklist alerts
4. Digital Forensics (ELA Heatmap, Facial ROI Splice, Stamp Forgery, EXIF editing traces)
5. Biometric Face Verification (1:1 Document Photo vs Live Passenger Photo)
6. OCR confidence & Missing mandatory identity fields

Generates human-in-the-loop recommendation and Final Screening Verdict.
"""
from typing import Dict, Any, List, Tuple, Optional
from app.config import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_MED,
    RISK_THRESHOLD_HIGH,
    VERDICT_VERIFIED,
    VERDICT_REVIEW,
    VERDICT_HIGH_RISK
)


def compute_risk_assessment(
    validation_report: Dict[str, Any],
    forensics_report: Dict[str, Any],
    metadata_report: Dict[str, Any],
    face_report: Dict[str, Any],
    ocr_report: Dict[str, Any],
    cross_report: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Computes transparent risk score and contributing factors breakdown.
    Returns:
    - score: integer 0-100
    - level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    - verdict: 'VERIFIED / LOW RISK' | 'NEEDS MANUAL REVIEW' | 'HIGH RISK / SUSPICIOUS DOCUMENT'
    - factors: List of itemized factor dicts with factor name, point impact, and explanation
    - summary: executive summary for security officers
    """
    raw_score = 0
    factors: List[Dict[str, Any]] = []

    # =========================================================================
    # 1. MOCK DATABASE WATCHLIST HIT (CRITICAL SEVERITY)
    # =========================================================================
    mock_hit = validation_report.get("mock_database_hit")
    if mock_hit:
        pts = 45
        raw_score += pts
        factors.append({
            "category": "WATCHLIST_MATCH",
            "points": pts,
            "severity": "CRITICAL",
            "name": f"Mock Watchlist Match: {mock_hit.get('status')}",
            "description": f"{mock_hit.get('reason')} ({mock_hit.get('notes')})"
        })

    # =========================================================================
    # 2. DOCUMENT VALIDATION & CHECKSUM FAILURES
    # =========================================================================
    failures = validation_report.get("failures_count", 0)
    warnings = validation_report.get("warnings_count", 0)

    # Check for expired document specifically
    is_expired = False
    for check in validation_report.get("checklist", []):
        if "EXPIRED" in str(check.get("detail", "")).upper():
            is_expired = True
            break

    if is_expired:
        pts = 30
        raw_score += pts
        factors.append({
            "category": "DOCUMENT_EXPIRED",
            "points": pts,
            "severity": "HIGH",
            "name": "Document Validity Expired",
            "description": "Travel document has exceeded official expiry date. Inadmissible for border transit."
        })
    elif failures > 0 and not mock_hit:
        pts = min(40, failures * 25)
        raw_score += pts
        factors.append({
            "category": "VALIDATION_FAILURE",
            "points": pts,
            "severity": "HIGH",
            "name": f"{failures} Document Rule/Checksum Failure(s)",
            "description": "Mathematical checksum mismatch (ICAO/Verhoeff) or malformed document syntax."
        })

    if warnings > 0:
        pts = min(15, warnings * 6)
        raw_score += pts
        factors.append({
            "category": "VALIDATION_WARNING",
            "points": pts,
            "severity": "WARN",
            "name": f"{warnings} Regulatory Warning(s)",
            "description": "Notice regarding validity duration, repeated submission, or minor formatting."
        })

    # =========================================================================
    # 3. FORENSICS & TAMPERING DETECTION
    # =========================================================================
    tamper_score = forensics_report.get("tamper_score", 0.0)
    photo_spliced = forensics_report.get("photo_spliced", False)
    stamp_suspicious = forensics_report.get("stamp_analysis", {}).get("is_suspicious", False)

    if photo_spliced:
        pts = 35
        raw_score += pts
        factors.append({
            "category": "PHOTO_REPLACEMENT",
            "points": pts,
            "severity": "CRITICAL",
            "name": "Photo Replacement / Face Splice Detected",
            "description": "Compression ratio discrepancy between facial portrait ROI and document surface."
        })
    elif tamper_score >= 40.0:
        pts = int(min(35, tamper_score * 0.45))
        raw_score += pts
        factors.append({
            "category": "IMAGE_TAMPERING",
            "points": pts,
            "severity": "HIGH",
            "name": f"Digital Modification Detected (ELA Index {tamper_score}%)",
            "description": f"{forensics_report.get('anomaly_regions_count', 0)} localized anomalous regions found with non-uniform compression."
        })
    elif tamper_score >= 20.0:
        pts = 12
        raw_score += pts
        factors.append({
            "category": "SUSPICIOUS_COMPRESSION",
            "points": pts,
            "severity": "WARN",
            "name": "Minor Compression Inconsistency",
            "description": f"Elevated compression noise ({tamper_score}%) observed on document surface."
        })

    if stamp_suspicious:
        pts = 15
        raw_score += pts
        factors.append({
            "category": "STAMP_FORGERY",
            "points": pts,
            "severity": "HIGH",
            "name": "Suspect Visa/Border Entry Stamp",
            "description": "Stamp displays unnaturally sharp digital edges lacking physical paper ink bleed."
        })

    # =========================================================================
    # 4. EXIF & METADATA ANALYSIS
    # =========================================================================
    software_detected = metadata_report.get("software_detected")
    if software_detected:
        pts = 25
        raw_score += pts
        factors.append({
            "category": "SOFTWARE_SIGNATURE",
            "points": pts,
            "severity": "HIGH",
            "name": f"Editing Software Detected ({software_detected})",
            "description": "Image metadata contains signatures of digital manipulation software."
        })
    elif metadata_report.get("timestamp_mismatch"):
        pts = 8
        raw_score += pts
        factors.append({
            "category": "TIMESTAMP_MISMATCH",
            "points": pts,
            "severity": "WARN",
            "name": "Metadata Modification Timestamp Discrepancy",
            "description": "Original image creation date does not align with file modification record."
        })

    # =========================================================================
    # 5. BIOMETRIC FACE VERIFICATION
    # =========================================================================
    face_verdict = face_report.get("verdict")
    match_pct = face_report.get("match_percentage", 0.0)

    if face_report.get("is_live_provided"):
        if face_verdict == "MISMATCH":
            pts = 35
            raw_score += pts
            factors.append({
                "category": "FACE_MISMATCH",
                "points": pts,
                "severity": "CRITICAL",
                "name": f"Biometric Face Mismatch ({match_pct}%)",
                "description": "Document owner's photograph does NOT match the presented live individual. Impersonation risk!"
            })
        elif face_verdict == "POSSIBLE MISMATCH":
            pts = 18
            raw_score += pts
            factors.append({
                "category": "BORDERLINE_FACE_MATCH",
                "points": pts,
                "severity": "WARN",
                "name": f"Borderline Biometric Match ({match_pct}%)",
                "description": "Moderate facial feature discrepancy. Security officer physical inspection recommended."
            })
    else:
        # No live photo provided - slight informational note
        factors.append({
            "category": "NO_LIVE_PHOTO",
            "points": 0,
            "severity": "INFO",
            "name": "Live Passenger Photo Pending",
            "description": "Biometric face verification awaiting live passenger photograph input."
        })

    # =========================================================================
    # 6. OCR & MISSING MANDATORY FIELDS
    # =========================================================================
    fields = ocr_report.get("fields", {})
    name = fields.get("full_name") or fields.get("name")
    doc_id = fields.get("passport_number") or fields.get("visa_number") or fields.get("id_number")
    doc_type = ocr_report.get("doc_type", "UNKNOWN")

    is_unrecognized = (doc_type == "UNKNOWN") or (not name and not doc_id)

    if is_unrecognized:
        pts = 45
        raw_score += pts
        factors.append({
            "category": "UNRECOGNIZED_DOCUMENT",
            "points": pts,
            "severity": "HIGH",
            "name": "Unrecognized Document Type / Empty Extraction",
            "description": "System could not identify a valid travel/identity format. Mandatory attributes (Name, Document ID) could not be extracted."
        })
    elif not name or not doc_id:
        pts = 15
        raw_score += pts
        factors.append({
            "category": "MISSING_FIELDS",
            "points": pts,
            "severity": "WARN",
            "name": "Missing Mandatory Identity Fields",
            "description": "Core identity attributes could not be extracted with sufficient confidence."
        })

    # =========================================================================
    # 7. CRYPTOGRAPHIC QR CODE VS PRINTED IDENTITY CROSS-VERIFICATION
    # =========================================================================
    if cross_report and cross_report.get("qr_decoded"):
        if cross_report.get("has_critical_mismatch"):
            pts = 65
            raw_score += pts
            mismatch_items = [
                f"[{m['field']}] {m['explanation']}"
                for m in cross_report.get("verification_matrix", [])
                if m.get("status") == "MISMATCH"
            ]
            desc = "; ".join(mismatch_items) if mismatch_items else "Printed document surface contradicts cryptographic QR record."
            factors.append({
                "category": "CRYPTOGRAPHIC_QR_CONFLICT",
                "points": pts,
                "severity": "CRITICAL",
                "name": "Cryptographic Identity Tampering Alert",
                "description": desc
            })
        elif cross_report.get("overall_match_score", 0) >= 80.0:
            # Verified cryptographic integrity
            factors.append({
                "category": "CRYPTOGRAPHIC_QR_VERIFIED",
                "points": 0,
                "severity": "PASS",
                "name": "Cryptographic QR Identity Verified",
                "description": "Printed document identity data matches cryptographic QR record."
            })

    # Normalized risk score 0 - 100
    final_score = int(min(100, max(0, raw_score)))

    # Risk level classification
    if is_unrecognized:
        risk_level = "HIGH" if final_score >= 60 else "MEDIUM"
        verdict = VERDICT_HIGH_RISK if final_score >= 60 else "NEEDS MANUAL REVIEW"
        officer_rec = "UNVERIFIED INTAKE: Document type unrecognized or illegible. Mandatory identity fields missing. Officer must conduct manual physical inspection and re-scan under proper lighting."
    elif final_score <= RISK_THRESHOLD_LOW:
        risk_level = "LOW"
        verdict = VERDICT_VERIFIED
        officer_rec = "Clear for transit. Document verified authentic across optical, mathematical, and forensic layers."
    elif final_score <= RISK_THRESHOLD_MED:
        risk_level = "MEDIUM"
        verdict = VERDICT_REVIEW
        officer_rec = "Secondary manual inspection recommended. Document exhibits minor inconsistencies or warnings."
    elif final_score <= RISK_THRESHOLD_HIGH:
        risk_level = "HIGH"
        verdict = VERDICT_HIGH_RISK
        officer_rec = "High-risk document alert. Detailed physical examination and supervisor authorization required."
    else:
        risk_level = "CRITICAL"
        verdict = VERDICT_HIGH_RISK
        officer_rec = "CRITICAL SECURITY BREACH. Potential counterfeit, photo splice, impersonation, or watchlist hit. Escalate to border security supervisor immediately."

    return {
        "score": final_score,
        "level": risk_level,
        "verdict": verdict,
        "officer_recommendation": officer_rec,
        "factors": factors,
        "factor_count": len(factors)
    }
