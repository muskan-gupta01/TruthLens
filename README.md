# TruthLens — AI-Based Fake Identity & Document Screening System
**SIH Problem Statement SIH26188 | Ministry of Home Affairs (MHA) | Category: Blockchain & Cybersecurity**

---

## 🛡️ Project Overview

**TruthLens** is an automated, explainable AI document screening and forensic identity verification platform built for **border checkpoints, immigration terminals, and law enforcement facilities**.

Border checkpoints process thousands of travel documents daily—including **passports, visas, national IDs, driving licenses, and transit permits**. Manual verification is slow, prone to fatigue and human error, and struggles to identify sophisticated digital forgeries, photo replacement splices, altered dates of birth, or identity impersonation.

TruthLens addresses this by providing a complete, deterministic, and explainable **7-step screening workflow**:

```
   [ Upload Document + Live Passenger Photo ]
                      │
                      ▼
   ┌──────────────────────────────────────────┐
   │ 1. OCR Extraction & ICAO 9303 MRZ Parser │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 2. QR Code Cryptographic Decode          │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 3. Document Standards & Rules Validation │
   │    (ICAO 9303, Verhoeff D5, Expiry Date) │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 4. Digital Image Forensics (ELA Heatmap) │
   │    (Photo Splice, Tamper ROIs, Stamps)   │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 5. EXIF & Image Metadata Forensics       │
   │    (Photoshop/Canva Fingerprint Check)   │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 6. 1:1 Biometric Face Verification       │
   │    (Document Photo vs Live Passenger)    │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ 7. Mock Verification Database Check      │
   │    (Watchlists, Interpol Notices, Dups)  │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ Dynamic Risk Engine & Final Verdict      │
   │ Score: 0-100 • Contributing Factors      │
   │ ✓ VERIFIED  ⚠ REVIEW  ✕ HIGH RISK        │
   └──────────────────┬───────────────────────┘
                      ▼
   ┌──────────────────────────────────────────┐
   │ Persistent SQLite Audit & PDF Certificate│
   └──────────────────────────────────────────┘
```

---

## 🚀 Key Modules & Capabilities

### Module 1: OCR Extraction & MRZ Decoding
- **Supported Documents:** Passports, Visas, National Identity Cards (Aadhaar & PAN), Driving Licenses, and Travel Permits.
- **ICAO Doc 9303 Machine Readable Zone (MRZ) Parser:** Parses Type-3 (TD3) 2-line passport MRZ and Type-1 (TD1) 3-line ID card MRZ.
- **Checksum Verification:** Evaluates 7-3-1 cyclic weighting check digits on Document Number, Date of Birth, Expiry Date, and Overall Composite checksum.
- **Visual Inspection Zone Extraction:** Extracts Full Name, Document Number, Nationality, DOB, Gender, Issue Date, Expiry Date, Visa Type, Stay Duration, and Entries.

### Module 2: Document Standards & Regulatory Validation
- **Mathematical Algorithms:**
  - Official **UIDAI Verhoeff $D_5$ Dihedral Group Checksum** for Aadhaar numbers (catches 100% of single-digit errors and transposed numbers).
  - Income Tax Department PAN structural syntax and 4th-character entity type classification.
- **Travel Document Expiry Checks:**
  - Automated detection of expired documents.
  - Border **6-month passport validity rule** warning for international transit.
- **Regulatory Checklist:** Clearly itemizes all validation checks as:
  - `✓ Valid`
  - `⚠ Warning`
  - `✕ Invalid`

### Module 3: Tampering Detection (Core AI Innovation)
- **Error Level Analysis (ELA):** Resaves input images in-memory at 90% JPEG quality, computes absolute difference, amplifies variance, and renders a vivid colorized **JET heatmap overlay**.
- **Photo Replacement / Facial Splicing Detection:** Automatically detects facial portrait bounding boxes and measures compression delta ratios between facial ROI and surrounding document substrate (detects pasted headshots).
- **Border Entry Stamp Analysis:** Inspects immigration stamps for physical ink bleed vs flat vector digital paste.
- **Metadata & EXIF Forensics:** Scans EXIF headers for editing software signatures (*Adobe Photoshop, Canva, GIMP, Snapseed*) and timestamp discrepancies.

### Module 4: Biometric Face Verification
- **1:1 Identity Matching:** Automatically crops facial portrait from travel documents and compares it against a presented live passenger photograph (file upload or browser webcam capture).
- **Multi-Scale Feature Comparison:** Combines HSV color histogram correlation, grayscale structural gradients, and edge continuity.
- **Output:** Biometric Similarity Percentage (0-100%), Confidence score, status (`MATCH`, `POSSIBLE MISMATCH`, `MISMATCH`), and side-by-side cropped face previews.

### Dynamic Risk Assessment Engine
- Calculates transparent **0–100 composite risk score**:
  - `0–29: LOW RISK` (`✓ VERIFIED / LOW RISK`)
  - `30–59: MEDIUM RISK` (`⚠ NEEDS MANUAL REVIEW`)
  - `60–79: HIGH RISK` (`✕ HIGH RISK / SUSPICIOUS DOCUMENT`)
  - `80–100: CRITICAL RISK` (`✕ HIGH RISK / SUSPICIOUS DOCUMENT`)
- **Transparent Contributing Factors:** Itemizes exact point additions (e.g. `Mock Watchlist Match: +45`, `Photo Splice Detected: +35`, `Face Mismatch: +35`, `Expired Document: +30`).
- Generates security officer enforcement recommendations.

### Mock Verification Database & Audit History
- **Persistent Local SQLite Database (`database/truthlens.db`):**
  - `mock_watchlists`: Seeded with simulated Interpol Red Notices, stolen blank passport alerts, overstay tourist visas, and suspended licenses.
  - `screening_history`: Stores complete audit logs of every screening transaction.
- **Printable Screening Certificate:** Formatted PDF / print modal for law enforcement records.

> [!IMPORTANT]
> **Disclaimer**: All watchlist entries and verification database checks are simulated mock data strictly for demonstration purposes and are labeled: `"DEMO DATA – NOT CONNECTED TO GOVERNMENT DATABASES"`.

---

## 🛠️ Technology Stack

- **Backend Server:** Python 3.9+, FastAPI, Uvicorn, Pydantic
- **OCR Engine:** Tesseract OCR (`pytesseract`) with CLAHE & Bilateral filtering
- **Computer Vision & Image Forensics:** OpenCV 5.0, Pillow (PIL), NumPy, SciPy
- **Local Database:** SQLite3 (Python native)
- **Frontend Dashboard:** HTML5, CSS3 (Vanilla Cyber/Border Theme), JavaScript (Vanilla ES6+ with WebRTC Webcam support)

---

## 📁 Project Directory Structure

```
TruthLens/
├── app/
│   ├── config.py                 # System configuration, paths, and thresholds
│   ├── main.py                   # FastAPI application & API endpoints
│   ├── database/
│   │   ├── __init__.py
│   │   └── db_manager.py         # SQLite audit history & mock watchlist manager
│   └── pipeline/
│       ├── __init__.py
│       ├── ocr_extractor.py      # OCR extraction for Passport, Visa, ID, DL, Permit
│       ├── mrz_parser.py         # ICAO Doc 9303 MRZ decoder & check digit validator
│       ├── format_validator.py   # Verhoeff, PAN, expiry, & border rule validation
│       ├── forensics_ela.py      # Error Level Analysis, photo splice, & stamp check
│       ├── metadata_forensics.py # EXIF metadata audit & software fingerprints
│       ├── face_verifier.py      # 1:1 Biometric face verification & cropping
│       ├── risk_engine.py        # 0-100 risk score & contributing factors engine
│       ├── screening_pipeline.py # 7-step master screening pipeline orchestrator
│       ├── qr_detector.py        # OpenCV native QR code detector & decoder
│       └── cross_verifier.py     # Cross-matching OCR vs cryptographic records
├── database/
│   └── truthlens.db              # SQLite persistent database file
├── static/
│   ├── index.html                # 10-section cybersecurity border dashboard
│   ├── css/
│   │   └── style.css             # Cyber/government dark UI & print stylesheet
│   └── js/
│       └── app.js                # Interactive client controller & webcam capture
├── sample_docs/                  # Pre-generated synthetic travel documents & portraits
├── generate_samples.py           # Synthetic document & portrait asset generator
├── test_pipeline.py              # Automated verification test suite (5/5 scenarios)
├── requirements.txt              # Validated Python dependencies
├── run.py                        # Server launcher script
└── README.md                     # Documentation & demonstration manual
```

---

## ⚡ Quick Start & Installation

### 1. Prerequisites
- Python 3.9 or higher
- Tesseract OCR (auto-detected at `C:\Program Files\Tesseract-OCR\tesseract.exe` on Windows, or via system PATH)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate Demonstration Assets
```bash
python generate_samples.py
```

### 4. Run Automated Test Suite
```bash
python test_pipeline.py
```
*(Confirms 5/5 automated test scenarios pass successfully).*

### 5. Launch TruthLens Server
```bash
python run.py
```
Access the application in your web browser:
- **Interactive Dashboard:** `http://127.0.0.1:8000`
- **API Documentation (Swagger):** `http://127.0.0.1:8000/docs`
- **Health Check Diagnostics:** `http://127.0.0.1:8000/api/health`

---

## 🎯 How to Demonstrate to SIH Judges

TruthLens includes **1-click Hackathon Demonstration Scenarios** directly on the Dashboard and Screening tabs:

### Scenario 1: Genuine Passport + Live Passenger Match (Low Risk)
1. On the **Dashboard** or **Document Screening** tab, click **"Scenario 1: Genuine Passport + Face Match"**.
2. Notice:
   - Document loaded: Genuine US Passport (`Johnathan Doe`, Passport `A89412051`).
   - Live photo loaded: Matching portrait of Johnathan Doe.
3. The screening pipeline executes automatically:
   - **OCR Tab:** All 7 ICAO MRZ fields extracted with **100% verified check digits**.
   - **Validation Tab:** All checks `✓ Valid` (Passport number, DOB, Expiry in 2032).
   - **Tampering Tab:** 0.0% Tamper Score (Uniform compression, no software traces).
   - **Face Verification Tab:** **82.5% Biometric Match** (`MATCH CONFIRMED`).
   - **Risk Assessment Tab:** **Risk Score: 6/100 (LOW RISK)** → Verdict: `VERIFIED / LOW RISK`.

### Scenario 2: Expired Visa + Watchlist Alert (High Risk / Rejected)
1. Click **"Scenario 2: Expired Visa (Watchlist Alert)"**.
2. Document loaded: Schengen Tourist Visa (`Maria Gonzalez`, Visa `V9284710`).
3. Results:
   - **Validation Tab:** Flagged with `✕ Invalid` (Expired on 15/01/2024).
   - **Mock Database Hit:** Alert triggered: *"Revoked Tourist Visa: Unlawful Stay Violation"*.
   - **Risk Assessment Tab:** **Risk Score: 100/100 (CRITICAL RISK)** → Verdict: `HIGH RISK / SUSPICIOUS DOCUMENT`.

### Scenario 3: Tampered Passport + Impersonation (Critical Risk / Rejected)
1. Click **"Scenario 3: Tampered Passport + Impersonation"**.
2. Document loaded: Tampered Passport with altered printed name `Vikram Mehta` and spliced face photo, with an impersonating live passenger photo.
3. Results:
   - **Tampering Tab:** Spliced headshot detected with compression ratio mismatch and corrupted MRZ checksum.
   - **Face Verification Tab:** **Biometric Mismatch (32.5% similarity)** (`MISMATCH`).
   - **Mock Database:** Flagged under Interpol Red Notice for `Vikram Mehta`.
   - **Risk Assessment Tab:** **Risk Score: 86/100 (CRITICAL RISK)** → Verdict: `HIGH RISK / SUSPICIOUS DOCUMENT`.

### Certificate Download & Audit History
1. Click **"🖨️ Download Screening Certificate"** on any screening result to view the printable certificate modal and print / save as PDF.
2. Open the **Screening History** tab to view the persistent SQLite audit trail of all screened travelers.
3. Open the **Mock Database** tab to inspect the simulated border control watchlist.

---

## ⚖️ Legal & Ethical Notice
TruthLens is a research prototype developed for the **Smart India Hackathon (SIH26188)**. The system is designed to provide **decision-support recommendations** to human security personnel. Enforcement decisions must always involve human officer oversight. Watchlist databases included in this repository are synthetic mock data for technical demonstration purposes only.
