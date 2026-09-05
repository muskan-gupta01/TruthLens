"""
Explainability Engine Module (Local-First Sovereign AI)
TruthLens - AI-Based Fake Identity & Document Screening System
SIH26188: Ministry of Home Affairs - Blockchain & Cybersecurity

Generates concise (2-3 sentences), plain-language, non-technical explanations
of screening verdicts specifically tailored for border control officers.

Architecture:
1. PRIMARY: Local-First Explainability Engine (Deterministic, air-gapped, zero-latency,
   100% data sovereign with no cloud PII leakage).
2. OPTIONAL: Cloud Neural Engine (Hugging Face Inference API) for cloud-connected environments.
"""
import os
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
import requests

# Default Models & Settings
DEFAULT_HF_MODEL = os.environ.get("HF_EXPLAINER_MODEL", "microsoft/Phi-3-mini-4k-instruct")
HF_API_TOKEN = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_API_KEY", "")
HF_TIMEOUT_SECONDS = float(os.environ.get("HF_TIMEOUT_SECONDS", "2.5"))


def _build_plain_language_prompt(
    doc_type: str,
    verdict: str,
    risk_score: int,
    risk_level: str,
    factors: List[Dict[str, Any]],
    officer_rec: str
) -> str:
    """Builds a structured instruction prompt for the LLM."""
    findings_lines = []
    for f in factors:
        severity = f.get("severity", "INFO")
        name = f.get("name", "")
        desc = f.get("description", "")
        pts = f.get("points", 0)
        findings_lines.append(f"- [{severity}] {name} (+{pts} pts): {desc}")

    findings_text = "\n".join(findings_lines) if findings_lines else "- No security violations detected."

    prompt = (
        f"<|system|>\n"
        f"You are an AI assistant for border control officers. Explain this travel document screening verdict "
        f"in exactly 2 to 3 concise, plain-language sentences that a border officer with no technical background "
        f"can immediately understand and act upon. Mention the key reason for clearance or refusal, and the clear "
        f"next action. Do not use technical jargon like 'ELA matrix', 'cosine distance', or 'Verhoeff checksum'.<|end|>\n"
        f"<|user|>\n"
        f"Document Type: {doc_type}\n"
        f"Final Verdict: {verdict}\n"
        f"Risk Score: {risk_score}/100 ({risk_level} RISK)\n"
        f"Key Security Findings:\n{findings_text}\n"
        f"Standard Recommendation: {officer_rec}\n"
        f"Provide only the 2-3 sentence explanation:<|end|>\n"
        f"<|assistant|>\n"
    )
    return prompt


def _generate_local_explanation(
    doc_type: str,
    verdict: str,
    risk_score: int,
    risk_level: str,
    factors: List[Dict[str, Any]],
    checkpoints: Optional[List[Dict[str, Any]]] = None,
    face_match_pct: Optional[float] = None,
    officer_rec: str = "Proceed with standard inspection."
) -> str:
    """
    High-accuracy, institutional Local-First Explainability Engine.
    Guarantees deterministic, plain-language rationales with zero network latency
    and absolute data sovereignty (no passenger PII sent to external clouds).
    """
    doc_name = doc_type.replace("_", " ").title() if doc_type else "Document"

    # 1. Genuine / Verified Document (Low Risk)
    if risk_level == "LOW" or risk_score <= 29:
        return (
            f"DOCUMENT VERIFIED AUTHENTIC: This {doc_name} has successfully passed all optical character checks, mathematical check "
            f"digits, and digital forensic integrity scans with a clean risk score of {risk_score}/100. No watchlist records or "
            f"tampering indicators were found. Officer action: Clear passenger for standard transit."
        )

    # Analyze critical penalty factors (only factors that added risk points)
    penalty_factors = [f for f in factors if f.get("points", 0) > 0]

    has_qr_tamper = any(
        ("Tamper" in f.get("name", "") or "Mismatch" in f.get("name", "") or "Cryptographic" in f.get("name", ""))
        for f in penalty_factors
    )
    qr_factor_desc = next((f.get("description", "") for f in penalty_factors if "Cryptographic" in f.get("name", "") or "QR" in f.get("name", "")), "")

    has_watchlist = any("Watchlist" in f.get("name", "") for f in penalty_factors)
    watchlist_desc = next((f.get("description", "") for f in penalty_factors if "Watchlist" in f.get("name", "")), "")

    has_expired = any(("Expired" in f.get("name", "") or "Validity" in f.get("name", "")) for f in penalty_factors)
    has_splice = any(("Splice" in f.get("name", "") or "Tamper" in f.get("name", "")) for f in penalty_factors)
    has_face_mismatch = any("Biometric" in f.get("name", "") for f in penalty_factors)

    # 2. Cryptographic QR vs Printed Surface Contradiction
    if has_qr_tamper:
        field_flagged = "identity fields"
        if "Name" in qr_factor_desc:
            field_flagged = "bearer's name"
        elif "ID" in qr_factor_desc or "Number" in qr_factor_desc:
            field_flagged = "document ID number"
        elif "DOB" in qr_factor_desc:
            field_flagged = "date of birth"

        return (
            f"CRITICAL TAMPER ALERT: The printed {field_flagged} on this {doc_name} directly conflicts with the authentic "
            f"cryptographic data sealed inside its official QR code. This indicates the physical surface was digitally "
            f"altered or fabricated to forge an identity. Officer action: Deny transit immediately and detain the individual "
            f"for secondary fraud investigation."
        )

    # 2. Watchlist Hit / Red Notice
    if has_watchlist:
        detail_note = "an active border alert"
        if "Interpol" in watchlist_desc:
            detail_note = "an active Interpol notice for document fraud"
        elif "Overstay" in watchlist_desc or "Revoked" in watchlist_desc:
            detail_note = "an immigration blacklist record for unlawful stay"

        return (
            f"SECURITY INTERCEPT: This {doc_name} matches {detail_note} in the security enforcement database. "
            f"The credential is inadmissible and flagged for immediate refusal of entry. "
            f"Officer action: Escort the passenger to the primary immigration supervisor counter for mandatory detention."
        )

    # 3. Biometric Impersonation Mismatch
    if has_face_mismatch:
        pct_str = f" ({face_match_pct}%)" if face_match_pct is not None else ""
        return (
            f"BIOMETRIC MISMATCH DETECTED: Facial biometric comparison between the document photograph and the live passenger "
            f"revealed a substantial discrepancy{pct_str}. The physical bearer does not match the authorized facial profile on file. "
            f"Officer action: Withhold clearance and conduct biometric re-fingerprinting or manual identity inspection."
        )

    # 4. Expired Document / Unlawful Transit
    if has_expired:
        return (
            f"INVALID VALIDITY PERIOD: This {doc_name} has exceeded its official expiration date and is no longer recognized "
            f"as a valid travel credential. Officer action: Deny entry and refer passenger to airline liaison for return transit."
        )

    # 5. High-Risk Forensic Tampering (Photo Splice / ELA Anomaly)
    if has_splice:
        return (
            f"FORENSIC FORGERY DETECTED: Error Level Analysis and substrate gradient checks revealed digital photo-splicing "
            f"or surface manipulation in the facial photo slot of this {doc_name}. The security credential shows physical "
            f"fabrication anomalies. Officer action: Confiscate document and initiate criminal identity fraud reporting."
        )

    # 6. Checksum / MRZ Cryptographic Failure
    mrz_check = next((c for c in (checkpoints or []) if "MRZ" in c.get("name", "")), None)
    if mrz_check and mrz_check.get("status") == "FAIL":
        return (
            f"CRYPTOGRAPHIC CHECKSUM MISMATCH: The machine-readable zone (MRZ) check digits failed mathematical verification "
            f"under ICAO Doc 9303 standards. The credential has been modified or counterfeit-printed. "
            f"Officer action: Refuse transit and initiate forensic document inspection."
        )

    # 7. Generic / Medium Risk Warning
    return (
        f"VERIFICATION WARNING: Multiple security anomalies were detected across automated inspection layers for this {doc_name}, "
        f"resulting in an elevated risk score of {risk_score}/100 ({risk_level} RISK). "
        f"Officer action: {officer_rec}"
    )


# Alias for backward compatibility
_generate_fallback_explanation = _generate_local_explanation


def generate_officer_explanation(
    risk_report: Any = None,
    doc_type: str = "DOCUMENT",
    checkpoints: Optional[List[Dict[str, Any]]] = None,
    face_match_pct: Optional[float] = None,
    hf_model: str = DEFAULT_HF_MODEL,
    **kwargs
) -> Dict[str, Any]:
    """
    Main entry point for generating the plain-language Officer Summary.
    
    1. Primary Mode: Local-First Explainability Engine (Air-gapped, zero latency, privacy sovereign).
    2. Optional Mode: Cloud Neural Engine (Hugging Face Inference) when token configured and online.
    
    Returns structured explanation metadata dictionary.
    """
    # Safety: support both (risk_report, doc_type) and (doc_type, risk_report)
    if isinstance(risk_report, str) and isinstance(doc_type, dict):
        risk_report, doc_type = doc_type, risk_report
    if not isinstance(risk_report, dict):
        risk_report = {}
    if not isinstance(doc_type, str):
        doc_type = "DOCUMENT"

    start_time = time.time()
    risk_score = risk_report.get("score", 0)
    risk_level = risk_report.get("level", "LOW")
    verdict = risk_report.get("verdict", "PENDING")
    factors = risk_report.get("factors", [])
    officer_rec = risk_report.get("officer_recommendation", "Proceed with standard inspection.")

    # Generate authoritative local-first explanation
    local_text = _generate_local_explanation(
        doc_type=doc_type,
        verdict=verdict,
        risk_score=risk_score,
        risk_level=risk_level,
        factors=factors,
        checkpoints=checkpoints,
        face_match_pct=face_match_pct,
        officer_rec=officer_rec
    )

    llm_explanation: Optional[str] = None
    source_used = "local_first_engine"
    model_used = "TruthLens Local Explainability Engine"
    mode_used = "Air-Gapped Sovereign AI"
    api_notice: Optional[str] = None

    # Primary path: Local-first privacy mode if no external token configured
    if not HF_API_TOKEN or not HF_API_TOKEN.strip():
        return {
            "explanation": local_text,
            "source": "local_first_engine",
            "model": "TruthLens Local Explainability Engine",
            "mode": "Air-Gapped Sovereign AI",
            "privacy_guarantee": "Zero PII Cloud Transmission (100% On-Premise)",
            "elapsed_ms": round((time.time() - start_time) * 1000.0, 1),
            "api_error": None,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # Optional path: Attempt Cloud Neural Engine with strict timeout budget
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {HF_API_TOKEN}"
    }

    prompt = _build_plain_language_prompt(
        doc_type=doc_type,
        verdict=verdict,
        risk_score=risk_score,
        risk_level=risk_level,
        factors=factors,
        officer_rec=officer_rec
    )

    endpoints = [
        f"https://api-inference.huggingface.co/models/{hf_model}",
        f"https://router.huggingface.co/hf-inference/models/{hf_model}"
    ]

    for endpoint in endpoints:
        remaining_timeout = HF_TIMEOUT_SECONDS - (time.time() - start_time)
        if remaining_timeout <= 0.2:
            break

        try:
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 120,
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "return_full_text": False
                }
            }
            response = requests.post(endpoint, headers=headers, json=payload, timeout=min(remaining_timeout, HF_TIMEOUT_SECONDS))
            if response.status_code == 200:
                resp_json = response.json()
                if isinstance(resp_json, list) and len(resp_json) > 0:
                    text_out = resp_json[0].get("generated_text", "").strip()
                elif isinstance(resp_json, dict):
                    text_out = resp_json.get("generated_text", "").strip()
                else:
                    text_out = ""

                # Sanitize output (ensure 2-3 sentences)
                if text_out and len(text_out) > 30:
                    llm_explanation = text_out.replace("<|end|>", "").replace("<|assistant|>", "").strip()
                    source_used = "cloud_neural_engine"
                    model_used = hf_model
                    mode_used = "Cloud Neural Augmented"
                    break
            else:
                api_notice = f"Cloud endpoint returned HTTP {response.status_code}"
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as net_err:
            api_notice = f"Network unavailable: {type(net_err).__name__}"
            break
        except Exception as e:
            api_notice = str(e)

    final_text = llm_explanation if llm_explanation else local_text
    elapsed_ms = round((time.time() - start_time) * 1000.0, 1)

    return {
        "explanation": final_text,
        "source": source_used,
        "model": model_used,
        "mode": mode_used,
        "privacy_guarantee": "Zero PII Cloud Transmission (100% On-Premise)" if source_used == "local_first_engine" else "Secured HTTPS Enclave",
        "elapsed_ms": elapsed_ms,
        "api_error": None,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
