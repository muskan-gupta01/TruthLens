"""
Dynamic Risk Assessment & Explainable Decision Engine
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188: Ministry of Home Affairs - Blockchain & Cybersecurity

Calculates a heuristic risk score (0-100) and aggregates contributing risk factors from:
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

    # Inspect specifically for mathematical checksum failure vs OCR uncertainty
    has_checksum_failure = False
    has_checksum_warning = False
    checksum_check_name = ""
    checksum_failure_desc = ""
    checksum_warning_desc = ""

    for check in validation_report.get("checklist", []):
        chk_title = check.get("check", "")
        if any(k in chk_title for k in ["Checksum", "Verhoeff", "ICAO", "PAN Syntax"]):
            if check.get("status") == "FAIL":
                has_checksum_failure = True
                checksum_check_name = chk_title
                checksum_failure_desc = check.get("detail", "Mathematical checksum verification failed.")
            elif check.get("status") == "WARN":
                has_checksum_warning = True
                checksum_check_name = chk_title
                checksum_warning_desc = check.get("detail", "Checksum uncertainty due to optical scan noise.")

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

    # Process mathematical checksum failure or validation failures
    if has_checksum_failure:
        pts_cs = 40
        raw_score += pts_cs
        factors.append({
            "category": "CHECKSUM_FAILURE",
            "points": pts_cs,
            "severity": "HIGH",
            "name": f"Mathematical Checksum Failure ({checksum_check_name})",
            "description": checksum_failure_desc
        })
        other_failures = max(0, failures - 1)
        if other_failures > 0:
            pts_oth = min(20, other_failures * 10)
            raw_score += pts_oth
            factors.append({
                "category": "VALIDATION_FAILURE",
                "points": pts_oth,
                "severity": "HIGH",
                "name": f"{other_failures} Additional Document Rule Failure(s)",
                "description": "Syntax or mandatory field validation discrepancies."
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

    # Process warnings (including OCR uncertainty)
    if has_checksum_warning:
        pts_warn = 8
        raw_score += pts_warn
        factors.append({
            "category": "OCR_CHECKSUM_UNCERTAINTY",
            "points": pts_warn,
            "severity": "WARN",
            "name": "Aadhaar Checksum Optical Ambiguity (OCR Uncertainty)",
            "description": checksum_warning_desc
        })
        other_warnings = max(0, warnings - 1)
        if other_warnings > 0:
            pts_other_w = min(12, other_warnings * 5)
            raw_score += pts_other_w
            factors.append({
                "category": "VALIDATION_WARNING",
                "points": pts_other_w,
                "severity": "WARN",
                "name": f"{other_warnings} Regulatory Warning(s)",
                "description": "Notice regarding validity duration, repeated submission, or minor formatting."
            })
    elif warnings > 0:
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
    # 6. OCR, MISSING MANDATORY FIELDS & DOCUMENT MISMATCH / FRAUD
    # =========================================================================
    fields = ocr_report.get("fields", {})
    name = fields.get("full_name") or fields.get("name")
    doc_id = fields.get("passport_number") or fields.get("visa_number") or fields.get("id_number")
    doc_type = ocr_report.get("doc_type", "UNKNOWN")
    claimed_type = ocr_report.get("claimed_type") or doc_type
    is_mismatch = ocr_report.get("is_claimed_mismatch", False)
    is_non_identity = ocr_report.get("is_non_identity", False) or (doc_type in ["BUSINESS_CARD", "NON_IDENTITY_DOCUMENT"])

    if is_mismatch or is_non_identity:
        pts = 90
        raw_score += pts
        if is_non_identity:
            factors.append({
                "category": "DOCUMENT_TYPE_FRAUD",
                "points": pts,
                "severity": "CRITICAL",
                "name": f"Document Impersonation: {claimed_type} vs {doc_type.replace('_', ' ').title()}",
                "description": (
                    f"Severe fraud & identity deception attempt: Intake registered as official '{claimed_type}', "
                    f"but multi-modal analysis confirmed a non-identity commercial document ({doc_type.replace('_', ' ').title()}) "
                    f"lacking all statutory government credentials, seals, and checksums."
                )
            })
        else:
            factors.append({
                "category": "DOCUMENT_TYPE_MISMATCH",
                "points": pts,
                "severity": "CRITICAL",
                "name": f"Document Type Conflict: Claimed {claimed_type} vs Detected {doc_type.replace('_', ' ').title()}",
                "description": (
                    f"Document intake mismatch: Intake registered as official '{claimed_type}', "
                    f"but automated optical and format classification identified document characteristics matching '{doc_type.replace('_', ' ').title()}'."
                )
            })
        if not doc_id:
            pts_id = 25
            raw_score += pts_id
            factors.append({
                "category": "MISSING_MANDATORY_ID",
                "points": pts_id,
                "severity": "CRITICAL",
                "name": f"Missing Statutory {claimed_type} Identifier",
                "description": f"No valid {claimed_type} number detected. Document completely invalid for identity screening."
            })
    elif doc_type == "UNKNOWN":
        pts = 60
        raw_score += pts
        factors.append({
            "category": "UNRECOGNIZED_DOCUMENT",
            "points": pts,
            "severity": "HIGH",
            "name": "Unrecognized Document Type / Non-Identity Upload",
            "description": "System could not identify a valid institutional identity or travel format."
        })
    elif not name and not doc_id:
        # Document header was identified (e.g. PAN card / Aadhaar), but text contrast was poor
        pts = 25
        raw_score += pts
        factors.append({
            "category": "BLURRY_CAMERA_CAPTURE",
            "points": pts,
            "severity": "WARN",
            "name": f"Low Contrast / Blurry Capture ({doc_type})",
            "description": f"Document identified as {doc_type}, but optical resolution was too low to read ID numbers clearly. Retake photo under direct light."
        })
    elif not name or not doc_id:
        pts = 15
        raw_score += pts
        factors.append({
            "category": "MISSING_FIELDS",
            "points": pts,
            "severity": "WARN",
            "name": "Partial Identity Field Extraction",
            "description": "Core identity attributes partially extracted. Secondary manual verification recommended."
        })

    # =========================================================================
    # 7. QR CODE VS PRINTED IDENTITY CROSS-VERIFICATION
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
            desc = "; ".join(mismatch_items) if mismatch_items else "Printed document surface contradicts decoded QR record."
            factors.append({
                "category": "QR_CROSS_CHECK_CONFLICT",
                "points": pts,
                "severity": "CRITICAL",
                "name": "QR ↔ OCR Identity Mismatch Alert",
                "description": desc
            })
        elif cross_report.get("overall_match_score", 0) >= 80.0:
            # Verified cross-consistency
            factors.append({
                "category": "QR_CROSS_CHECK_VERIFIED",
                "points": 0,
                "severity": "PASS",
                "name": "QR Cross-Verification Confirmed",
                "description": "Printed document identity data matches decoded QR payload."
            })

    # Normalized risk score 0 - 100
    final_score = int(min(100, max(0, raw_score)))

    # If confirmed mathematical checksum failure occurred:
    # It must NEVER be cleared as VERIFIED / LOW RISK (score <= 29)
    if has_checksum_failure and not (is_mismatch or is_non_identity):
        final_score = max(final_score, 40)

    # Risk level classification
    is_unrecognized = (doc_type == "UNKNOWN")
    if is_mismatch or is_non_identity:
        final_score = max(final_score, 95)  # Guaranteed 95 - 100 critical score for fraud / non-identity
        risk_level = "CRITICAL"
        verdict = VERDICT_HIGH_RISK
        if is_non_identity:
            officer_rec = (
                f"CRITICAL SECURITY REJECTION: Immediate denial of entry/intake. Traveler submitted a non-identity commercial "
                f"document ({doc_type.replace('_', ' ').title()}) represented as an official {claimed_type}. "
                "Potential deliberate fraud or document deception. Escalate to supervisory border authority."
            )
        else:
            officer_rec = (
                f"CRITICAL DOCUMENT MISMATCH: Immediate intake rejection. Submitted document identified as "
                f"'{doc_type.replace('_', ' ').title()}', conflicting with declared '{claimed_type}'. "
                "Verify traveler identity credentials manually."
            )
    elif is_unrecognized:
        risk_level = "HIGH" if final_score >= 60 else "MEDIUM"
        verdict = VERDICT_HIGH_RISK if final_score >= 60 else "NEEDS MANUAL REVIEW"
        officer_rec = "UNVERIFIED INTAKE: Document type unrecognized or illegible. Mandatory identity fields missing. Officer must conduct manual physical inspection and re-scan under proper lighting."
    elif final_score <= RISK_THRESHOLD_LOW:
        risk_level = "LOW"
        verdict = VERDICT_VERIFIED
        if has_checksum_warning:
            officer_rec = "Clear for transit. Document verified with minor optical scan ambiguity in checksum sequence. Secondary visual check recommended if uncertainty persists."
        else:
            officer_rec = "Clear for transit. Document verified authentic across optical, mathematical, and forensic layers."
    elif final_score <= RISK_THRESHOLD_MED:
        risk_level = "MEDIUM"
        verdict = VERDICT_REVIEW
        if has_checksum_failure:
            officer_rec = "Secondary physical inspection required. Document flagged with mathematical checksum failure (Verhoeff/ICAO). Verify physical document credentials."
        else:
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
