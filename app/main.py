"""
TruthLens FastAPI Application Server
Built for SIH26188: AI-Based Fake Identity & Document Screening System
Ministry of Home Affairs - Category: Blockchain & Cybersecurity

Endpoints:
- GET /                    : Serves the cybersecurity dashboard UI
- GET /api/health          : System health check & OCR/CV diagnostics
- GET /api/stats           : KPI counters and risk distribution for dashboard
- GET /api/samples         : Curated demonstration document samples
- GET /api/samples/{id}    : Serves sample document image
- POST /api/screen         : Full 7-step screening analysis endpoint
- GET /api/history         : Local SQLite audit screening history
- GET /api/history/{id}    : Detailed screening report retrieval
- GET /api/mock-db         : Mock border verification database records
"""
import io
import os
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image, ImageOps

from app.config import (
    STATIC_DIR,
    SAMPLE_DOCS_DIR,
    TEMP_DIR,
    TESSERACT_PATH
)
from app.pipeline.screening_pipeline import run_truthlens_screening
from app.database.db_manager import (
    get_history,
    get_screening_by_id,
    get_all_mock_watchlists,
    get_dashboard_statistics,
    register_user,
    authenticate_user,
    create_user_session,
    validate_user_session,
    delete_user_session,
    get_user_by_id
)

app = FastAPI(
    title="TruthLens - AI-Based Fake Identity & Document Screening System",
    description="Border Checkpoint AI Screening Platform combining OCR, ICAO 9303 MRZ, Verhoeff checksums, Error Level Analysis (ELA), EXIF metadata forensics, and 1:1 Biometric Face Verification.",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directory
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _extract_session_token(request: Request) -> Optional[str]:
    """Extracts session token from cookie, Authorization header, or query param."""
    token = request.cookies.get("session_token")
    if token:
        return token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return request.query_params.get("token")


def _decode_image_file(upload: UploadFile) -> Image.Image:
    """Safely decodes an uploaded file into an EXIF-oriented PIL Image."""
    contents = upload.file.read()
    img = Image.open(io.BytesIO(contents))
    try:
        img = ImageOps.exif_transpose(img)
    except Exception:
        pass
    return img.convert("RGB")


def _decode_base64_image(b64_str: str) -> Image.Image:
    """Decodes a base64 Data URI string into an EXIF-oriented PIL Image."""
    if "," in b64_str:
        b64_str = b64_str.split(",", 1)[1]
    decoded = base64.b64decode(b64_str)
    img = Image.open(io.BytesIO(decoded))
    try:
        img = ImageOps.exif_transpose(img)
    except Exception:
        pass
    return img.convert("RGB")


@app.get("/", response_class=HTMLResponse)
async def serve_landing(request: Request):
    """Serves the main TruthLens landing page with integrated login & registration."""
    landing_path = STATIC_DIR / "landing.html"
    if not landing_path.exists():
        index_path = STATIC_DIR / "index.html"
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    with open(landing_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request):
    """Serves the login page. Redirects to /dashboard if already authenticated."""
    token = _extract_session_token(request)
    if token and validate_user_session(token):
        return RedirectResponse(url="/dashboard", status_code=303)

    landing_path = STATIC_DIR / "landing.html"
    if not landing_path.exists():
        raise HTTPException(status_code=404, detail="Landing HTML not found")
    with open(landing_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the protected TruthLens Border Control Dashboard UI."""
    token = _extract_session_token(request)
    user = validate_user_session(token) if token else None
    if not user:
        return RedirectResponse(url="/login?redirect=/dashboard", status_code=303)

    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Index HTML not found")
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/presentation", response_class=HTMLResponse)
async def serve_presentation():
    """Serves the interactive slide deck for SIH hackathon presentation."""
    pres_path = STATIC_DIR / "presentation.html"
    if not pres_path.exists():
        raise HTTPException(status_code=404, detail="Presentation HTML not found")
    with open(pres_path, "r", encoding="utf-8") as f:
        return f.read()


# ============================================================================
# AUTHENTICATION API ENDPOINTS
# ============================================================================

@app.post("/api/auth/register")
async def api_register(request: Request):
    """Registers a new user and creates an active session."""
    data = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        form = await request.form()
        data = dict(form)

    full_name = str(data.get("full_name", "")).strip()
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", "")).strip()
    confirm_password = str(data.get("confirm_password", "")).strip()
    phone = str(data.get("phone", "")).strip()
    gender = str(data.get("gender", "")).strip()

    if not full_name or not email or not password:
        raise HTTPException(status_code=400, detail="Full name, email, and password are required")

    if confirm_password and password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")

    try:
        user = register_user(
            full_name=full_name,
            email=email,
            password=password,
            phone=phone,
            gender=gender,
            role="OFFICER"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    session_info = create_user_session(user["user_id"], user["email"])
    token = session_info["session_token"]

    res = JSONResponse(content={
        "success": True,
        "message": "Account created successfully",
        "token": token,
        "user": user,
        "redirect_url": "/dashboard"
    })
    res.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/"
    )
    return res


@app.post("/api/auth/login")
async def api_login(request: Request):
    """Authenticates user credentials and starts a secure session."""
    data = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        form = await request.form()
        data = dict(form)

    email = str(data.get("email", "")).strip()
    password = str(data.get("password", "")).strip()

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    session_info = create_user_session(user["user_id"], user["email"])
    token = session_info["session_token"]

    res = JSONResponse(content={
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": user,
        "redirect_url": "/dashboard"
    })
    res.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/"
    )
    return res


@app.post("/api/auth/logout")
async def api_logout(request: Request):
    """Terminates the active session and clears auth cookies."""
    token = _extract_session_token(request)
    if token:
        delete_user_session(token)
    res = JSONResponse(content={"success": True, "message": "Logged out successfully", "redirect_url": "/login"})
    res.delete_cookie(key="session_token", path="/")
    return res


@app.get("/api/auth/me")
async def api_current_user(request: Request):
    """Returns the currently authenticated officer's profile."""
    token = _extract_session_token(request)
    if not token:
        return {"authenticated": False, "user": None}
    user = validate_user_session(token)
    if not user:
        return {"authenticated": False, "user": None}
    return {"authenticated": True, "user": user}



@app.get("/api/health")
async def health_check():
    """System health check & forensic engine diagnostics."""
    import cv2
    import pytesseract

    tess_version = "Unknown"
    tess_ok = False
    try:
        tess_version = pytesseract.get_tesseract_version()
        tess_ok = True
    except Exception as e:
        tess_version = str(e)

    return {
        "status": "ONLINE",
        "system": "TruthLens Border Screening System",
        "problem_statement": "SIH26188",
        "ministry": "Ministry of Home Affairs",
        "category": "Blockchain & Cybersecurity",
        "tesseract": {
            "available": tess_ok,
            "path": TESSERACT_PATH,
            "version": str(tess_version)
        },
        "opencv_version": cv2.__version__,
        "database": "SQLite3 (Local Persistent Audit Trail)",
        "modules": [
            "Module 1: OCR Extraction (ICAO Doc 9303 MRZ + Visual Inspection)",
            "Module 2: Document Rule & Checksum Validation",
            "Module 3: Tampering Detection (ELA Heatmap, Photo Splice, Stamp Check)",
            "Module 4: Biometric Face Verification (1:1 Document vs Live Passenger)",
            "Module 5: Mock Border Verification Database & Watchlists"
        ]
    }


@app.get("/api/stats")
async def get_stats():
    """Returns dashboard statistics (total screened, verified, high risk, distribution)."""
    return get_dashboard_statistics()


@app.get("/api/samples")
async def list_sample_documents():
    """
    Returns curated demo samples for instant judging and testing.
    """
    samples = [
        {
            "id": "demo_passport_genuine",
            "title": "Genuine US Passport",
            "doc_type": "PASSPORT",
            "expected_verdict": "VERIFIED / LOW RISK",
            "description": "Authentic ICAO Doc 9303 compliant Passport (Johnathan Doe) with verified 7-3-1 mathematical check digits.",
            "badge_color": "emerald",
            "filename": "demo_passport_genuine.jpg",
            "matching_live_portrait": "demo_person_live_match.jpg"
        },
        {
            "id": "demo_visa_expired",
            "title": "Expired Schengen Visa (Watchlist Alert)",
            "doc_type": "VISA",
            "expected_verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
            "description": "Expired French tourist visa flagged in Mock Watchlist for overstay violation (Maria Gonzalez).",
            "badge_color": "rose",
            "filename": "demo_visa_expired.jpg",
            "matching_live_portrait": None
        },
        {
            "id": "demo_passport_tampered",
            "title": "Tampered Passport & Spliced Portrait",
            "doc_type": "PASSPORT",
            "expected_verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
            "description": "Spliced headshot with compression mismatch, altered name 'Vikram Mehta' (Interpol notice), and invalid MRZ checksum.",
            "badge_color": "rose",
            "filename": "demo_passport_tampered.jpg",
            "matching_live_portrait": "demo_person_live_mismatch.jpg"
        },
        {
            "id": "sample_genuine_aadhaar",
            "title": "Genuine UIDAI Aadhaar Card",
            "doc_type": "AADHAAR",
            "expected_verdict": "VERIFIED / LOW RISK",
            "description": "Authentic UIDAI Aadhaar with verified Verhoeff checksum algorithm and cryptographic QR match.",
            "badge_color": "emerald",
            "filename": "sample_genuine_aadhaar.jpg",
            "matching_live_portrait": None
        },
        {
            "id": "sample_tampered_name_aadhaar",
            "title": "Tampered Aadhaar (Altered Printed Name)",
            "doc_type": "AADHAAR",
            "expected_verdict": "HIGH RISK / SUSPICIOUS DOCUMENT",
            "description": "Photoshop altered printed name 'Vikram Mehta' contradicts cryptographic QR record 'Aakash Verma'.",
            "badge_color": "rose",
            "filename": "sample_tampered_name_aadhaar.jpg",
            "matching_live_portrait": None
        },
        {
            "id": "sample_genuine_pan",
            "title": "Genuine Income Tax PAN Card",
            "doc_type": "PAN",
            "expected_verdict": "VERIFIED / LOW RISK",
            "description": "Income Tax Department format verified, valid 4th entity char 'P', clean ELA forensics.",
            "badge_color": "emerald",
            "filename": "sample_genuine_pan.jpg",
            "matching_live_portrait": None
        }
    ]
    return {"samples": samples}


@app.get("/api/samples/{sample_id}")
async def get_sample_image(sample_id: str):
    """Serves a test sample image file."""
    clean_id = sample_id.replace(".jpg", "").replace(".png", "")
    filename = f"{clean_id}.jpg"
    file_path = SAMPLE_DOCS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample image not found")
    return FileResponse(path=str(file_path), media_type="image/jpeg")


@app.post("/api/screen")
async def screen_document(
    file: Optional[UploadFile] = File(None),
    live_file: Optional[UploadFile] = File(None),
    sample_id: Optional[str] = Form(None),
    live_sample_id: Optional[str] = Form(None),
    image_base64: Optional[str] = Form(None),
    live_base64: Optional[str] = Form(None),
    doc_type: Optional[str] = Form(None),
    doc_number: Optional[str] = Form(None),
    person_name: Optional[str] = Form(None)
):
    """
    Main Border Screening Endpoint:
    Accepts:
    1. Document image (File, Sample ID, or Base64)
    2. Optional Live Passenger Photo (File, Live Sample ID, Webcam Base64)
    3. Optional Document Type Hint
    4. Optional Manual / Confirmed Document Number & Passenger Name
    Executes the 7-step screening pipeline and returns full audit report.
    """
    doc_img = None
    live_img = None

    # Resolve document image
    if file and file.filename:
        try:
            doc_img = _decode_image_file(file)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid document image: {e}")
    elif sample_id:
        clean_id = sample_id.replace(".jpg", "").replace(".png", "")
        file_path = SAMPLE_DOCS_DIR / f"{clean_id}.jpg"
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Sample document '{sample_id}' not found")
        try:
            doc_img = Image.open(file_path).convert("RGB")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to open sample: {e}")
    elif image_base64:
        try:
            doc_img = _decode_base64_image(image_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decode base64 document: {e}")
    else:
        raise HTTPException(status_code=400, detail="No document provided. Upload an image or select a demo sample.")

    # Resolve optional live passenger photo
    if live_file and live_file.filename:
        try:
            live_img = _decode_image_file(live_file)
        except Exception:
            pass
    elif live_sample_id:
        clean_live_id = live_sample_id.replace(".jpg", "").replace(".png", "")
        live_path = SAMPLE_DOCS_DIR / f"{clean_live_id}.jpg"
        if live_path.exists():
            try:
                live_img = Image.open(live_path).convert("RGB")
            except Exception:
                pass
    elif live_base64:
        try:
            live_img = _decode_base64_image(live_base64)
        except Exception:
            pass

    # Execute TruthLens border screening pipeline
    try:
        result = run_truthlens_screening(
            doc_image_input=doc_img,
            live_image_input=live_img,
            doc_type_hint=doc_type,
            doc_number_override=doc_number,
            person_name_override=person_name
        )
        return JSONResponse(content=result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Screening pipeline error: {str(e)}")


@app.get("/api/history")
async def get_screening_history_endpoint():
    """Retrieves previous screening audit records from SQLite."""
    history = get_history(limit=50)
    return {"history": history}


@app.get("/api/history/{screening_id}")
async def get_screening_report_endpoint(screening_id: str):
    """Retrieves full JSON audit record for a given screening ID."""
    report = get_screening_by_id(screening_id)
    if not report:
        raise HTTPException(status_code=404, detail="Screening report not found")
    return JSONResponse(content=report)


@app.get("/api/mock-db")
async def get_mock_database_endpoint():
    """Returns all mock border verification database records."""
    records = get_all_mock_watchlists()
    return {
        "disclaimer": "DEMO DATA – NOT CONNECTED TO GOVERNMENT DATABASES",
        "description": "Simulated border control watchlist, stolen passport registry, and revocation notices for demonstration purposes.",
        "records": records
    }

