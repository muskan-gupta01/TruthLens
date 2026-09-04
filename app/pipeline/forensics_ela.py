"""
Image Forensics & Error Level Analysis (ELA) Module
TruthLens - AI-Based Fake Identity & Document Screening System

Implements Error Level Analysis (ELA) using PIL and OpenCV:
1. Resaves image in memory at fixed JPEG compression quality (90%).
2. Calculates pixel difference between original and recompressed image.
3. Amplifies difference to highlight digital alterations, pasted photos, or edited text.
4. Generates a colorized forensic heatmap (JET / INFERNO) and localized tamper bounding boxes.
5. Computes statistical ELA anomaly score (0-100%).
"""
import io
import base64
import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from typing import Dict, Any, Tuple, List, Optional

from app.config import (
    ELA_JPEG_QUALITY,
    ELA_SCALE_FACTOR,
    ELA_TAMPER_THRESHOLD_HIGH,
    ELA_TAMPER_THRESHOLD_MED
)


def compute_ela(
    image_input,
    quality: int = ELA_JPEG_QUALITY,
    scale_factor: int = ELA_SCALE_FACTOR
) -> Tuple[Image.Image, np.ndarray, float, float]:
    """
    Performs Error Level Analysis on the input image:
    1. Resaves image in memory buffer at designated JPEG quality.
    2. Computes absolute difference between original and resaved image.
    3. Amplifies difference for visual forensic evaluation.
    """
    if isinstance(image_input, np.ndarray):
        rgb_arr = cv2.cvtColor(image_input, cv2.COLOR_BGR2RGB) if len(image_input.shape) == 3 else image_input
        original = Image.fromarray(rgb_arr).convert("RGB")
    elif isinstance(image_input, Image.Image):
        original = image_input.convert("RGB")
    else:
        raise ValueError("Unsupported image type for ELA")

    # Resave in-memory as JPEG at designated quality (90%)
    buffer = io.BytesIO()
    original.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer).convert("RGB")

    # Absolute pixel difference: |Original - Resaved|
    ela_diff = ImageChops.difference(original, resaved)

    # Convert difference to numpy array
    diff_arr = np.array(ela_diff, dtype=np.float32)
    diff_gray = cv2.cvtColor(diff_arr.astype(np.uint8), cv2.COLOR_RGB2GRAY)

    mean_diff = float(np.mean(diff_gray))
    max_diff = float(np.max(diff_gray))

    # Scale the difference image for human visualization
    extrema = ela_diff.getextrema()
    max_component = max([ex[1] for ex in extrema]) if extrema else 1
    if max_component == 0:
        max_component = 1

    scale = min(255.0 / max_component, float(scale_factor))
    ela_scaled = ImageEnhance.Brightness(ela_diff).enhance(scale)

    return ela_scaled, diff_gray, mean_diff, max_diff


def generate_heatmap_and_anomalies(
    original_bgr: np.ndarray,
    diff_gray: np.ndarray
) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, int]], float]:
    """
    Generates a colorized forensic heatmap from ELA difference data.
    Detects localized clusters with anomalously high compression errors (spliced/tampered elements).
    Excludes normal font anti-aliasing edge strokes and whole-card border frames.
    """
    h, w = diff_gray.shape[:2]
    total_pixels = h * w
    mean_diff = float(np.mean(diff_gray))

    # Amplify differences: Multiply diff_gray by 16x (clipped at 255) to bring out compression variance
    diff_amplified = np.clip(diff_gray.astype(np.float32) * 16.0, 0, 255).astype(np.uint8)

    # Apply Jet ColorMap: Deep Blue = low error / uniform compression; Yellow/Red = high error / edited
    heatmap_bgr = cv2.applyColorMap(diff_amplified, cv2.COLORMAP_JET)

    # Regional 2D anomaly detection via local sliding window:
    # A genuine document has low recompression error (< 1.0) across all regions.
    # A spliced element (photo or pasted patch) exhibits sustained elevated error across a 2D block.
    local_mean = cv2.boxFilter(diff_gray.astype(np.float32), -1, (35, 35))
    anomaly_thresh_val = max(mean_diff * 3.0, 3.2)
    anomaly_mask = (local_mean >= anomaly_thresh_val).astype(np.uint8) * 255

    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (15, 15))
    closed = cv2.morphologyEx(anomaly_mask, cv2.MORPH_CLOSE, kernel)

    contours, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    anomaly_regions = []

    # Blend original and heatmap for forensic overlay inspection
    overlay_bgr = original_bgr.copy()
    cv2.addWeighted(heatmap_bgr, 0.45, overlay_bgr, 0.55, 0, overlay_bgr)

    min_area = total_pixels * 0.012  # ~1.2% of card area
    anomalous_pixels_count = 0

    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area > min_area:
            x, y, cw, ch = cv2.boundingRect(cnt)
            # Filter out outer card border lines
            if cw > w * 0.75 or ch > h * 0.75:
                continue
            # Filter out thin horizontal text headers (normal bold text has high aspect ratio)
            aspect = cw / max(ch, 1)
            if aspect > 2.8 or ch < 35:
                continue

            reg_mean = float(np.mean(diff_gray[y:y+ch, x:x+cw]))
            if reg_mean >= 3.0:
                anomaly_regions.append({
                    "x": int(x), "y": int(y), "w": int(cw), "h": int(ch),
                    "area": int(area), "mean": round(reg_mean, 2)
                })
                anomalous_pixels_count += area
                # Draw glowing red forensic detection box
                cv2.rectangle(overlay_bgr, (x, y), (x + cw, y + ch), (0, 0, 255), 2)
                cv2.putText(
                    overlay_bgr,
                    "ALERT: ANOMALY REGION",
                    (x, max(y - 6, 15)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.45,
                    (0, 0, 255),
                    1
                )

    tamper_percentage = float(anomalous_pixels_count / total_pixels) * 100.0
    return heatmap_bgr, overlay_bgr, anomaly_regions, round(tamper_percentage, 2)


def analyze_stamp_forgery(original_bgr: np.ndarray) -> Dict[str, Any]:
    """
    Analyzes visa/border entry stamps for authenticity markers:
    1. Ink bleed and color gradient dispersion into paper substrate
    2. Digital stamp cloning / flat alpha overlay detection
    """
    hsv = cv2.cvtColor(original_bgr, cv2.COLOR_BGR2HSV)
    # Target typical immigration stamp ink colors (red/violet/blue)
    mask_red1 = cv2.inRange(hsv, np.array([0, 70, 50]), np.array([12, 255, 255]))
    mask_red2 = cv2.inRange(hsv, np.array([168, 70, 50]), np.array([180, 255, 255]))
    mask_blue = cv2.inRange(hsv, np.array([95, 70, 50]), np.array([135, 255, 255]))
    stamp_mask = mask_red1 | mask_red2 | mask_blue

    # Find stamp contours (circular, oval, or rectangular official border stamps)
    contours, _ = cv2.findContours(stamp_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    detected_stamps = 0
    suspicious_stamps = 0
    stamp_reasons = []

    h, w = original_bgr.shape[:2]
    min_stamp_area = (h * w) * 0.008
    max_stamp_area = (h * w) * 0.15

    for cnt in contours:
        area = cv2.contourArea(cnt)
        if min_stamp_area <= area <= max_stamp_area:
            x, y, sw, sh = cv2.boundingRect(cnt)
            # A real border stamp is not located in the document header bar
            if y < h * 0.20 or sw > w * 0.40 or sh > h * 0.40:
                continue
            aspect = float(sw) / max(1, sh)
            if not (0.55 <= aspect <= 1.8):
                continue

            detected_stamps += 1
            # Check edge sharpness: authentic physical rubber stamps have ink absorption bleed
            roi_stamp = stamp_mask[y:y+sh, x:x+sw]
            lap = cv2.Laplacian(roi_stamp, cv2.CV_64F)
            edge_sharpness = np.var(lap)
            # Flat digital vector paste has unnaturally crisp boundary without bleed
            if edge_sharpness > 2400.0:
                suspicious_stamps += 1
                stamp_reasons.append("Unnaturally sharp stamp boundary detected without physical paper ink dispersion (suggests digital paste).")


    is_forged = suspicious_stamps > 0
    return {
        "stamps_detected": detected_stamps,
        "suspicious_count": suspicious_stamps,
        "is_suspicious": is_forged,
        "reasons": stamp_reasons if stamp_reasons else ["Stamps appear authentic with natural ink bleed."] if detected_stamps > 0 else ["No prominent colored border stamps detected."]
    }


def analyze_photo_splice(
    diff_gray: np.ndarray,
    cv_img: Optional[np.ndarray] = None,
    face_bbox: Optional[Tuple[int, int, int, int]] = None
) -> Tuple[bool, float, str]:
    """
    Compares the ELA recompression error rate & high-frequency noise variance
    inside the facial portrait region against the surrounding card substrate.
    If the face region has significantly higher/lower compression error or incompatible
    sensor noise, it indicates a digital photo replacement splice.
    """
    if not face_bbox:
        return False, 0.0, "No face bounding box provided for splice audit."

    x, y, w, h = face_bbox
    h_img, w_img = diff_gray.shape[:2]

    # Constrain to bounds
    x = max(0, min(x, w_img - 1))
    y = max(0, min(y, h_img - 1))
    w = max(1, min(w, w_img - x))
    h = max(1, min(h, h_img - y))

    face_diff = diff_gray[y:y+h, x:x+w]
    face_mean = float(np.mean(face_diff))

    # Sample localized card substrate margin immediately surrounding the portrait
    pad_w = int(w * 0.40)
    pad_h = int(h * 0.40)
    x1 = max(0, x - pad_w)
    y1 = max(0, y - pad_h)
    x2 = min(w_img, x + w + pad_w)
    y2 = min(h_img, y + h + pad_h)

    local_bg_mask = np.zeros_like(diff_gray, dtype=bool)
    local_bg_mask[y1:y2, x1:x2] = True
    local_bg_mask[y:y+h, x:x+w] = False

    if np.any(local_bg_mask):
        bg_mean = float(np.mean(diff_gray[local_bg_mask]))
    else:
        bg_mask = np.ones_like(diff_gray, dtype=bool)
        bg_mask[y:y+h, x:x+w] = False
        bg_mean = float(np.mean(diff_gray[bg_mask]))

    ratio = face_mean / max(0.1, bg_mean)
    # A genuine digital splice shows distinct localized compression divergence
    is_spliced = (ratio > 2.85 and face_mean > 3.0) or (ratio < 0.25 and bg_mean > 4.5)

    # Check high-frequency noise disparity if cv_img is supplied
    noise_ratio = 1.0
    if cv_img is not None:
        try:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY).astype(np.float32)
            blur = cv2.GaussianBlur(gray, (5, 5), 0)
            noise = np.abs(gray - blur)
            face_noise = float(np.mean(noise[y:y+h, x:x+w]))
            ref_mask = local_bg_mask if np.any(local_bg_mask) else bg_mask
            bg_noise = float(np.mean(noise[ref_mask]))
            noise_ratio = face_noise / max(0.1, bg_noise)
            if (noise_ratio > 3.2 or noise_ratio < 0.25) and face_mean > 2.5:
                is_spliced = True
        except Exception:
            pass

    explanation = (
        f"Photo replacement splice detected: Portrait compression ratio ({round(ratio, 2)}x) "
        f"and noise profile ({round(noise_ratio, 2)}x) conflict with document substrate."
        if is_spliced else
        f"Portrait compression ({round(ratio, 2)}x) is consistent with card surface."
    )
    return is_spliced, round(ratio, 2), explanation


def run_ela_forensic_analysis(
    image_input,
    face_bbox: Optional[Tuple[int, int, int, int]] = None,
    doc_type: str = "UNKNOWN"
) -> Dict[str, Any]:
    """
    Unified forensic screening pipeline:
    1. Error Level Analysis (ELA)
    2. Colorized Heatmap + Regional Anomaly Bounding Boxes
    3. Facial Photo Splicing Detection with Visual Red Highlight Boxes
    4. Stamp Forgery & Ink Analysis (Passports & Visas)
    5. Annotated Evidence Overlay & Itemized Explainable Tamper Score (0-100%)
    """
    if isinstance(image_input, Image.Image):
        rgb_arr = np.array(image_input.convert("RGB"))
        cv_img = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        cv_img = image_input.copy()
    else:
        raise ValueError("Unsupported image type for ELA analysis")

    ela_img, diff_gray, mean_diff, max_diff = compute_ela(cv_img)
    heatmap_bgr, overlay_bgr, anomalies, tamper_pct = generate_heatmap_and_anomalies(cv_img, diff_gray)

    # Photo splice check
    photo_spliced, splice_ratio, splice_expl = analyze_photo_splice(diff_gray, cv_img=cv_img, face_bbox=face_bbox)

    # Stamp analysis (only relevant for Passports and Visas)
    if doc_type in ["PASSPORT", "VISA"]:
        stamp_report = analyze_stamp_forgery(cv_img)
    else:
        stamp_report = {
            "stamps_detected": 0,
            "suspicious_count": 0,
            "is_suspicious": False,
            "reasons": ["Domestic ID (no border entry stamps expected)."]
        }

    visual_tamper_boxes = []

    # 1. Annotate Spliced Photo on overlay image
    if photo_spliced and face_bbox is not None:
        fx, fy, fw, fh = face_bbox
        cv2.rectangle(overlay_bgr, (fx, fy), (fx + fw, fy + fh), (0, 0, 255), 3)
        cv2.rectangle(overlay_bgr, (fx, max(0, fy - 22)), (fx + min(fw, 240), fy), (0, 0, 255), -1)
        cv2.putText(
            overlay_bgr,
            "ALERT: SPLICED PHOTO",
            (fx + 5, fy - 6),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.42,
            (255, 255, 255),
            1,
            cv2.LINE_AA
        )
        visual_tamper_boxes.append({
            "type": "PHOTO_SPLICE",
            "x": int(fx), "y": int(fy), "w": int(fw), "h": int(fh),
            "label": "Spliced / Replaced Portrait"
        })

    # 2. Add existing anomaly regions to visual tamper boxes
    for anom in anomalies:
        visual_tamper_boxes.append({
            "type": "COMPRESSION_ANOMALY",
            "x": anom["x"], "y": anom["y"], "w": anom["w"], "h": anom["h"],
            "label": "Localized Compression Discrepancy"
        })

    # Encode images to base64 for frontend display (AFTER annotations are drawn)
    _, h_buf = cv2.imencode(".jpg", heatmap_bgr, [cv2.IMWRITE_JPEG_QUALITY, 85])
    heatmap_b64 = "data:image/jpeg;base64," + base64.b64encode(h_buf).decode("utf-8")

    _, o_buf = cv2.imencode(".jpg", overlay_bgr, [cv2.IMWRITE_JPEG_QUALITY, 85])
    overlay_b64 = "data:image/jpeg;base64," + base64.b64encode(o_buf).decode("utf-8")

    # Compute calibrated tamper index (0 - 100%)
    tamper_score = 0.0
    detection_reasons = []

    if anomalies:
        cluster_points = min(50.0, len(anomalies) * 22.0)
        tamper_score += cluster_points
        detection_reasons.append(f"{len(anomalies)} localized anomalous region(s) with inconsistent JPEG recompression.")

    if photo_spliced:
        tamper_score += 45.0
        detection_reasons.append(splice_expl)

    if stamp_report["is_suspicious"]:
        tamper_score += 25.0
        detection_reasons.extend(stamp_report["reasons"])

    if mean_diff > 3.0:
        tamper_score += 20.0
        detection_reasons.append("High overall noise floor across entire document image.")

    tamper_score = round(min(100.0, max(0.0, tamper_score)), 1)

    if tamper_score >= 50.0:
        status_label = "HIGH RISK (Tampered / Spliced)"
        risk_level = "HIGH"
    elif tamper_score >= 25.0:
        status_label = "SUSPICIOUS (Possible Alteration)"
        risk_level = "MEDIUM"
    else:
        status_label = "AUTHENTIC (Uniform Compression)"
        risk_level = "LOW"
        detection_reasons = ["Uniform error level distribution across document surface. No digital splicing or cloning artifacts found."]

    return {
        "tamper_score": tamper_score,
        "tamper_level": risk_level,
        "mean_diff": round(mean_diff, 2),
        "max_diff": round(max_diff, 2),
        "status_label": status_label,
        "risk_level": risk_level,
        "anomaly_regions_count": len(anomalies),
        "anomaly_regions": anomalies,
        "visual_tamper_boxes": visual_tamper_boxes,
        "anomaly_percentage": tamper_pct,
        "photo_spliced": photo_spliced,
        "photo_splice_ratio": splice_ratio,
        "stamp_analysis": stamp_report,
        "detection_reasons": detection_reasons,
        "findings": detection_reasons,
        "heatmap_data_uri": heatmap_b64,
        "overlay_data_uri": overlay_b64,
        "heatmap_base64": heatmap_b64,
        "overlay_base64": overlay_b64
    }

