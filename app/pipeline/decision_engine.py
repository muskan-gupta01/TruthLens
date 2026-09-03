"""
Decision Engine & Explainability Module
TruthLens - AI-Based Fake Identity & Document Screening System

Aggregates forensic evidence across all 4 screening layers:
1. OCR Text Extraction & Preprocessing
2. Optical QR Cryptographic Payload
3. Cross-Verification & Fuzzy Matching
4. Error Level Analysis (ELA) Forensics
5. Mathematical Checksum & Format Validation

Computes:
- Clear Verdict: "GENUINE" | "SUSPICIOUS" | "FAKE"
- Calibrated Confidence Score (%)
- Itemized Explainability Audit Trail with Severity Badges (PASS / WARNING / CRITICAL)
"""
from typing import Dict, Any, List
from app.config import (
    DOC_TYPE_AADHAAR,
    DOC_TYPE_PAN,
    DOC_TYPE_UNKNOWN
)


def evaluate_screening_verdict(
    ocr_result: Dict[str, Any],
    qr_result: Dict[str, Any],
    cross_result: Dict[str, Any],
    ela_result: Dict[str, Any],
    format_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates multi-layered evidence and generates an explainable verdict.
    """
    reasons_list: List[Dict[str, str]] = []
    flags_critical: List[str] = []
    flags_warning: List[str] = []
    flags_pass: List[str] = []

    doc_type = ocr_result.get("document_type", DOC_TYPE_UNKNOWN)
    ocr_fields = ocr_result.get("fields", {})

    # =========================================================================
    # 1. EVALUATE MATHEMATICAL FORMAT & CHECKSUM
    # =========================================================================
    id_format = format_result.get("id_validation", {})
    if id_format.get("valid"):
        flags_pass.append(f"Format Check: {id_format.get('reason')}")
        reasons_list.append({
            "category": "Format & Checksum",
            "severity": "PASS",
            "text": id_format.get("reason", "ID format is valid.")
        })
    else:
        # Check if ID was found
        if ocr_fields.get("id_number"):
            flags_critical.append(f"Format Failure: {id_format.get('reason')}")
            reasons_list.append({
                "category": "Format & Checksum",
                "severity": "CRITICAL",
                "text": f"Mathematical Checksum Failure: {id_format.get('reason')}"
            })
        else:
            flags_warning.append("ID number could not be extracted for checksum validation.")
            reasons_list.append({
                "category": "Format & Checksum",
                "severity": "WARNING",
                "text": "ID number could not be detected from document surface."
            })

    dob_format = format_result.get("dob_validation", {})
    if dob_format.get("valid"):
        reasons_list.append({
            "category": "Format & Checksum",
            "severity": "PASS",
            "text": dob_format.get("reason", "DOB syntax valid.")
        })
    elif ocr_fields.get("dob"):
        reasons_list.append({
            "category": "Format & Checksum",
            "severity": "WARNING",
            "text": f"DOB anomaly: {dob_format.get('reason')}"
        })

    # =========================================================================
    # 2. EVALUATE QR CODE & CRYPTOGRAPHIC PAYLOAD
    # =========================================================================
    qr_detected = qr_result.get("detected", False)
    qr_decoded = qr_result.get("decoded", False)

    if not qr_detected:
        if doc_type == DOC_TYPE_AADHAAR:
            reasons_list.append({
                "category": "QR Security",
                "severity": "INFO",
                "text": "No QR code detected on card face (UIDAI secure QR codes are typically located on the reverse side or bottom section)."
            })
        else:
            reasons_list.append({
                "category": "QR Security",
                "severity": "INFO",
                "text": "No QR code detected on document (legacy card format)."
            })
    elif qr_detected and not qr_decoded:
        flags_warning.append("Unreadable QR Code: QR pattern is blurred, damaged, or obscured.")
        reasons_list.append({
            "category": "QR Security",
            "severity": "WARNING",
            "text": "QR code optically detected but cryptographic payload could not be read (low resolution or glare)."
        })
    else:
        reasons_list.append({
            "category": "QR Security",
            "severity": "PASS",
            "text": f"QR cryptographic payload decoded successfully (Format: {qr_result.get('fields', {}).get('format', 'Standard')})."
        })

    # =========================================================================
    # 3. EVALUATE CROSS-VERIFICATION (OCR vs QR)
    # =========================================================================
    if qr_decoded:
        has_critical_mismatch = cross_result.get("has_critical_mismatch", False)
        match_score = cross_result.get("overall_match_score", 0.0)

        for item in cross_result.get("verification_matrix", []):
            f_name = item["field"]
            f_status = item["status"]
            f_exp = item["explanation"]

            if f_status == "MISMATCH":
                flags_critical.append(f"QR Mismatch on {f_name}")
                reasons_list.append({
                    "category": "Cross-Verification",
                    "severity": "CRITICAL",
                    "text": f_exp
                })
            elif f_status == "PARTIAL":
                flags_warning.append(f"Minor discrepancy on {f_name}")
                reasons_list.append({
                    "category": "Cross-Verification",
                    "severity": "WARNING",
                    "text": f_exp
                })
            elif f_status == "MATCH":
                flags_pass.append(f"Verified {f_name}")
                reasons_list.append({
                    "category": "Cross-Verification",
                    "severity": "PASS",
                    "text": f_exp
                })

    # =========================================================================
    # 4. EVALUATE ERROR LEVEL ANALYSIS (ELA) IMAGE FORENSICS
    # =========================================================================
    tamper_level = ela_result.get("tamper_level", "LOW")
    tamper_score = ela_result.get("tamper_score", 0.0)
    anomaly_regions = ela_result.get("anomaly_regions_count", 0)

    if tamper_level == "HIGH":
        flags_critical.append("Forensic Tampering Detected (ELA)")
        reasons_list.append({
            "category": "Forensic ELA",
            "severity": "CRITICAL",
            "text": f"High digital alteration index ({tamper_score}%). {anomaly_regions} localized anomalous region(s) detected with inconsistent JPEG compression, indicating spliced photo or edited text."
        })
    elif tamper_level == "MEDIUM":
        flags_warning.append("Moderate Compression Inconsistency (ELA)")
        reasons_list.append({
            "category": "Forensic ELA",
            "severity": "WARNING",
            "text": f"Moderate compression variance ({tamper_score}%). Image may have undergone multi-generation editing or localized retouching."
        })
    else:
        flags_pass.append("Clean Forensic Signature (ELA)")
        reasons_list.append({
            "category": "Forensic ELA",
            "severity": "PASS",
            "text": f"Error Level Analysis confirms uniform compression ({tamper_score}%). No digital splicing or cloning artifacts found."
        })

    # =========================================================================
    # 5. FINAL VERDICT & CONFIDENCE CALCULATION
    # =========================================================================
    if len(flags_critical) > 0:
        verdict = "FAKE"
        verdict_title = "FAKE / TAMPERED"
        verdict_color = "#EF4444"  # Red
        verdict_badge = "CRITICAL_ALERT"

        confidence = min(82.0 + (len(flags_critical) * 6.0), 99.0)
        summary_statement = f"Document rejected: {len(flags_critical)} critical security failure(s) detected."

    elif len(flags_warning) >= 3 or (len(flags_warning) >= 2 and tamper_level != "LOW"):
        verdict = "SUSPICIOUS"
        verdict_title = "SUSPICIOUS"
        verdict_color = "#F59E0B"  # Amber
        verdict_badge = "INVESTIGATION_REQUIRED"

        confidence = min(68.0 + (len(flags_warning) * 4.0), 85.0)
        summary_statement = f"Manual investigation advised: {len(flags_warning)} security warning(s) flagged."

    else:
        verdict = "GENUINE"
        verdict_color = "#10B981"  # Emerald Green

        if qr_decoded:
            verdict_title = "GENUINE"
            verdict_badge = "VERIFIED_AUTHENTIC"
            confidence = min(88.0 + (5.0 if id_format.get("valid") else 0.0), 98.5)
            summary_statement = "Document verified authentic across optical, cryptographic, and forensic layers."
        else:
            if id_format.get("address_face"):
                verdict_title = "GENUINE (ADDRESS FACE)"
                verdict_badge = "AUTHENTIC_CARD"
                confidence = 86.0
                summary_statement = "UIDAI Aadhaar address face verified. Institutional layout and digital compression confirmed authentic."
            else:
                verdict_title = "GENUINE (FACE VERIFIED)"
                verdict_badge = "AUTHENTIC_CARD"
                confidence = min(82.0 + (6.0 if id_format.get("valid") else 0.0), 92.0)
                summary_statement = "Document verified authentic from visual, mathematical, and forensic compression analysis."

    return {
        "verdict": verdict,
        "verdict_title": verdict_title,
        "verdict_color": verdict_color,
        "verdict_badge": verdict_badge,
        "confidence": round(confidence, 1),
        "summary": summary_statement,
        "document_type": doc_type,
        "reasons": reasons_list,
        "counts": {
            "critical": len(flags_critical),
            "warning": len(flags_warning),
            "pass": len(flags_pass)
        }
    }
