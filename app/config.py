"""
TruthLens Configuration Module
AI-Based Fake Identity & Document Screening System
Built for SIH26188 (Ministry of Home Affairs - Blockchain & Cybersecurity)
"""
import os
import shutil
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
SAMPLE_DOCS_DIR = BASE_DIR / "sample_docs"
TEMP_DIR = BASE_DIR / "temp"

TEMP_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Tesseract executable configuration
# Detect system path or standard Windows install paths
TESSERACT_PATH = os.environ.get("TESSERACT_PATH")
if not TESSERACT_PATH:
    default_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe")
    ]
    for p in default_paths:
        if os.path.exists(p):
            TESSERACT_PATH = p
            break
    if not TESSERACT_PATH:
        # Fallback to system PATH lookup
        which_tess = shutil.which("tesseract")
        if which_tess:
            TESSERACT_PATH = which_tess

# Error Level Analysis (ELA) parameters
ELA_JPEG_QUALITY = 90          # Quality factor for resaving image
ELA_SCALE_FACTOR = 18          # Difference amplification factor
ELA_TAMPER_THRESHOLD_HIGH = 35 # Mean difference threshold for high tamper risk
ELA_TAMPER_THRESHOLD_MED = 20  # Mean difference threshold for suspicious risk

# Fuzzy matching thresholds
FUZZY_MATCH_THRESHOLD_PASS = 80   # Score >= 80 is considered a match
FUZZY_MATCH_THRESHOLD_WARN = 65   # Score 65-79 considered minor discrepancy / typo

# Document Types supported
DOC_TYPE_PASSPORT = "PASSPORT"
DOC_TYPE_VISA = "VISA"
DOC_TYPE_DRIVING_LICENSE = "DRIVING_LICENSE"
DOC_TYPE_PERMIT = "PERMIT"
DOC_TYPE_AADHAAR = "AADHAAR"
DOC_TYPE_PAN = "PAN"
DOC_TYPE_BUSINESS_CARD = "BUSINESS_CARD"
DOC_TYPE_NON_IDENTITY = "NON_IDENTITY_DOCUMENT"
DOC_TYPE_UNKNOWN = "UNKNOWN"

# Database configuration
DB_DIR = BASE_DIR / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "truthlens.db"

# Risk Thresholds
RISK_THRESHOLD_LOW = 29
RISK_THRESHOLD_MED = 59
RISK_THRESHOLD_HIGH = 79

# Verdict Strings
VERDICT_VERIFIED = "VERIFIED / LOW RISK"
VERDICT_REVIEW = "NEEDS MANUAL REVIEW"
VERDICT_HIGH_RISK = "HIGH RISK / SUSPICIOUS DOCUMENT"

