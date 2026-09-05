"""
TruthLens Database Manager & Mock Border Verification Database
SIH26188: AI-Based Fake Identity & Document Screening System

Handles:
1. SQLite local persistence for screening audit trail & history
2. Mock Border Control Verification Database (Watchlists, Stolen Travel Docs, Expired/Blacklisted Docs)
3. Duplicate document screening detection (anti-fraud ring)

NOTICE: All watchlist data is simulated mock data for demonstration purposes.
"""
import sqlite3
import json
import uuid
import hashlib
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from app.config import DB_PATH, DB_DIR

# Ensure DB directory exists
DB_DIR.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Returns an active SQLite connection with row factory set to sqlite3.Row."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with a cryptographically random salt."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a plain password against the stored salt:hash format."""
    try:
        if not stored_hash or ":" not in stored_hash:
            return False
        salt, key = stored_hash.split(":", 1)
        test_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return hmac.compare_digest(test_key.hex(), key)
    except Exception:
        return False


def init_database():
    """Creates tables if they do not exist and seeds initial mock watchlist records & demo users."""
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Mock Watchlist Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mock_watchlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_number TEXT NOT NULL,
            doc_type TEXT NOT NULL,
            person_name TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            issuing_country TEXT DEFAULT 'IND',
            notes TEXT DEFAULT ''
        )
    """)

    # 2. Screening History Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS screening_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            screening_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            doc_type TEXT NOT NULL,
            person_name TEXT,
            doc_number TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            verdict TEXT NOT NULL,
            summary TEXT,
            full_data_json TEXT NOT NULL
        )
    """)

    # 3. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT DEFAULT '',
            gender TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'OFFICER',
            created_at TEXT NOT NULL
        )
    """)

    # 4. User Sessions Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    # 5. Tamper-Proof Audit Chain Table (Hash-Chaining)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            screening_id TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            data_snapshot TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_chain_screening ON audit_chain(screening_id)
    """)

    # Seed mock records if table is empty
    cursor.execute("SELECT COUNT(*) FROM mock_watchlists")
    count = cursor.fetchone()[0]

    if count == 0:
        mock_data = [
            ("L898902C3", "PASSPORT", "VIKRAM MEHTA", "BLACKLISTED", "Interpol Red Notice: Cross-Border Document Fraud Ring", "IND", "Flagged at Delhi IGI Airport 2025"),
            ("A12345678", "PASSPORT", "ROBERT LANGDON", "EXPIRED_REVOKED", "Document Reported Lost / Revoked by Issuing State", "USA", "Replacement passport issued"),
            ("V9284710", "VISA", "MARIA GONZALEZ", "EXPIRED_REVOKED", "Revoked Tourist Visa: Unlawful Stay Violation", "FRA", "Schengen Overstay Flag"),
            ("P90412845", "PASSPORT", "ALEXANDRE DUPONT", "INTERPOL_STOLEN", "Stolen Blank Passport Stock Alert", "FRA", "Interpol SLTD Database Alert"),
            ("987654321099", "AADHAAR", "AAKASH VERMA", "FRAUD_SUSPECT", "Known Fabricated Number (Checksum Failure Signature)", "IND", "MHA Fraud Bulletin 2025/11"),
            ("DL-0420110012345", "DRIVING_LICENSE", "RAJESH KUMAR", "BLACKLISTED", "Suspended Driving License - Fake Commercial Endorsement", "IND", "Regional Transport Authority Alert"),
            ("ABCPS9999F", "PAN", "SURESH PATEL", "FRAUD_SUSPECT", "De-duplicated / Cancelled Duplicate PAN Card", "IND", "ITD De-duplication Registry")
        ]
        cursor.executemany("""
            INSERT INTO mock_watchlists 
            (doc_number, doc_type, person_name, status, reason, issuing_country, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, mock_data)

    # Seed demo users if users table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    if user_count == 0:
        default_officer_pwd = hash_password("TruthLens@2025")
        default_admin_pwd = hash_password("Admin@123")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO users (user_id, full_name, email, phone, gender, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"TL-USR-{uuid.uuid4().hex[:8].upper()}",
            "Immigration Officer",
            "officer@truthlens.gov.in",
            "+91 98765 43210",
            "Male",
            default_officer_pwd,
            "OFFICER",
            now_str
        ))
        cursor.execute("""
            INSERT INTO users (user_id, full_name, email, phone, gender, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"TL-USR-{uuid.uuid4().hex[:8].upper()}",
            "Muskan Gupta",
            "admin@truthlens.gov.in",
            "+91 99999 88888",
            "Female",
            default_admin_pwd,
            "SUPERVISOR",
            now_str
        ))
        default_officer2_pwd = hash_password("Officer2@2026")
        cursor.execute("""
            INSERT INTO users (user_id, full_name, email, phone, gender, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"TL-USR-{uuid.uuid4().hex[:8].upper()}",
            "Border Officer 2",
            "officer2@truthlens.gov.in",
            "+91 98111 22233",
            "Male",
            default_officer2_pwd,
            "OFFICER",
            now_str
        ))

    conn.commit()
    conn.close()


def query_mock_database(doc_number: Optional[str], person_name: Optional[str] = None, doc_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Queries the mock border control verification database for matches.
    Priority:
    1. Exact normalized doc_number match
    2. Name match ONLY if doc_number is absent or doc_type matches and name is distinct
    """
    if not doc_number and not person_name:
        return None

    conn = get_connection()
    cursor = conn.cursor()

    normalized_doc = "".join(str(doc_number).upper().split()) if doc_number else ""
    normalized_name = " ".join(str(person_name).upper().split()) if person_name else ""

    # Priority 1: Match by document number
    if normalized_doc:
        query = """
            SELECT * FROM mock_watchlists 
            WHERE REPLACE(UPPER(doc_number), ' ', '') = ?
        """
        cursor.execute(query, (normalized_doc,))
        row = cursor.fetchone()
        if row:
            conn.close()
            return {
                "matched": True,
                "doc_number": row["doc_number"],
                "doc_type": row["doc_type"],
                "person_name": row["person_name"],
                "status": row["status"],
                "reason": row["reason"],
                "issuing_country": row["issuing_country"],
                "notes": row["notes"]
            }

    # Priority 2: Match by full name only when doc_number was missing or doc_type matches watchlist
    if normalized_name and len(normalized_name) > 6 and not normalized_doc:
        query_name = "SELECT * FROM mock_watchlists WHERE UPPER(person_name) = ?"
        cursor.execute(query_name, (normalized_name,))
        row = cursor.fetchone()
        if row:
            conn.close()
            return {
                "matched": True,
                "doc_number": row["doc_number"],
                "doc_type": row["doc_type"],
                "person_name": row["person_name"],
                "status": row["status"],
                "reason": row["reason"],
                "issuing_country": row["issuing_country"],
                "notes": row["notes"]
            }

    conn.close()
    return None



def check_duplicate_screenings(doc_number: Optional[str]) -> int:
    """Returns number of previous screenings recorded for this document number."""
    if not doc_number:
        return 0
    clean = "".join(str(doc_number).upper().split())
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM screening_history 
        WHERE REPLACE(UPPER(doc_number), ' ', '') = ?
    """, (clean,))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def log_screening(data: Dict[str, Any]) -> str:
    """Logs a completed screening into the SQLite audit table."""
    conn = get_connection()
    cursor = conn.cursor()

    screening_id = data.get("screening_id") or f"TL-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc_type = data.get("doc_type", "UNKNOWN")

    dossier = data.get("dossier", {}) or {}
    sub_name = dossier.get("subject_name")
    if sub_name and sub_name not in ["Not Detected", "UNSPECIFIED", "N/A", ""]:
        person_name = sub_name
    else:
        person_name = (
            data.get("ocr", {}).get("fields", {}).get("name")
            or data.get("ocr", {}).get("fields", {}).get("full_name")
            or data.get("ocr", {}).get("fields", {}).get("traveler_name")
            or data.get("qr", {}).get("fields", {}).get("name")
            or data.get("cross_verification", {}).get("qr_data", {}).get("name")
            or "UNSPECIFIED"
        )

    # Detect if Aadhaar back side was uploaded without printed name
    if person_name == "UNSPECIFIED" and doc_type == "AADHAAR":
        raw_ocr = str(data.get("ocr", {}).get("raw_text", "")).upper()
        if "AADHAAR IS PROOF" in raw_ocr or "PROOF OF IDENTITY" in raw_ocr or "UNIQUE IDENTIFICATION" in raw_ocr:
            person_name = "Subject (Aadhaar Back Side)"

    doc_no = dossier.get("doc_number")
    if doc_no and doc_no not in ["Not Detected", "N/A", ""]:
        doc_number = doc_no
    else:
        doc_number = (
            data.get("ocr", {}).get("fields", {}).get("id_number")
            or data.get("ocr", {}).get("fields", {}).get("passport_number")
            or data.get("ocr", {}).get("fields", {}).get("visa_number")
            or data.get("ocr", {}).get("fields", {}).get("license_number")
            or data.get("ocr", {}).get("fields", {}).get("permit_id")
            or data.get("qr", {}).get("fields", {}).get("id_number")
            or "N/A"
        )

    risk_score = data.get("risk_assessment", {}).get("score", 0)
    risk_level = data.get("risk_assessment", {}).get("level", "LOW")
    verdict = data.get("verdict", "UNKNOWN")
    summary = data.get("summary", "")
    full_json = json.dumps(data)

    cursor.execute("""
        INSERT OR REPLACE INTO screening_history 
        (screening_id, timestamp, doc_type, person_name, doc_number, risk_score, risk_level, verdict, summary, full_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (screening_id, timestamp, doc_type, person_name, doc_number, risk_score, risk_level, verdict, summary, full_json))

    conn.commit()
    conn.close()
    return screening_id


def clear_history():
    """Deletes all screening audit logs and clears audit chain from SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM screening_history")
    cursor.execute("DELETE FROM audit_chain")
    conn.commit()
    conn.close()


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent screening audit logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT screening_id, timestamp, doc_type, person_name, doc_number, risk_score, risk_level, verdict, summary
        FROM screening_history
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_screening_by_id(screening_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full JSON screening result for a given screening ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT full_data_json FROM screening_history WHERE screening_id = ?", (screening_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["full_data_json"])
    return None


# ============================================================================
# CRYPTOGRAPHIC AUDIT CHAIN (HASH-CHAINING)
# ============================================================================

GENESIS_HASH = "0" * 64


def get_latest_audit_hash() -> str:
    """Returns the record_hash of the latest entry in audit_chain, or genesis hash if empty."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT record_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if row and row["record_hash"]:
        return str(row["record_hash"])
    return GENESIS_HASH


def add_audit_chain_record(
    screening_id: str,
    data_snapshot: Any,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends a new cryptographically signed block to the audit_chain.
    Computes: record_hash = SHA-256(data_snapshot + previous_hash + timestamp)
    Uses genesis hash ("0"*64) if chain is empty.
    """
    # Deterministic canonical serialization of data_snapshot
    if isinstance(data_snapshot, (dict, list)):
        snapshot_str = json.dumps(data_snapshot, sort_keys=True)
    else:
        snapshot_str = str(data_snapshot)

    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prev_hash = get_latest_audit_hash()

    # Cryptographic hash computation
    payload = f"{snapshot_str}{prev_hash}{ts}"
    record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_chain (timestamp, screening_id, record_hash, previous_hash, data_snapshot)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, screening_id, record_hash, prev_hash, snapshot_str))
    chain_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": chain_id,
        "screening_id": screening_id,
        "timestamp": ts,
        "record_hash": record_hash,
        "previous_hash": prev_hash,
        "short_hash": record_hash[:8],
        "short_prev_hash": prev_hash[:8]
    }


def verify_audit_chain() -> Dict[str, Any]:
    """
    Cryptographically verifies the entire audit hash-chain from genesis to latest.
    Detects both payload tampering (data_snapshot modification) and broken linkage (previous_hash tampering).
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, screening_id, record_hash, previous_hash, data_snapshot 
        FROM audit_chain ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    total = len(rows)
    if total == 0:
        return {
            "valid": True,
            "total_records": 0,
            "verified_count": 0,
            "broken_at": None,
            "message": "Audit chain is empty. Genesis state intact."
        }

    expected_prev = GENESIS_HASH

    for idx, row in enumerate(rows):
        r_id = row["id"]
        r_ts = row["timestamp"]
        r_sid = row["screening_id"]
        r_hash = row["record_hash"]
        r_prev = row["previous_hash"]
        r_data = row["data_snapshot"]

        # 1. Verify previous_hash linkage
        if r_prev != expected_prev:
            return {
                "valid": False,
                "total_records": total,
                "verified_count": idx,
                "broken_at": r_id,
                "reason": f"Broken chain link at record #{r_id}: previous_hash '{r_prev[:8]}...' does not match preceding record's hash '{expected_prev[:8]}...'",
                "details": {
                    "record_id": r_id,
                    "screening_id": r_sid,
                    "timestamp": r_ts,
                    "stored_previous_hash": r_prev,
                    "expected_previous_hash": expected_prev
                }
            }

        # 2. Recompute SHA-256(data_snapshot + previous_hash + timestamp)
        payload = f"{r_data}{r_prev}{r_ts}"
        computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if computed_hash != r_hash:
            return {
                "valid": False,
                "total_records": total,
                "verified_count": idx,
                "broken_at": r_id,
                "reason": f"Cryptographic tamper detected at record #{r_id}: recomputed hash '{computed_hash[:8]}...' does not match stored hash '{r_hash[:8]}...'",
                "details": {
                    "record_id": r_id,
                    "screening_id": r_sid,
                    "timestamp": r_ts,
                    "stored_hash": r_hash,
                    "recomputed_hash": computed_hash
                }
            }

        # Advance expected previous hash to this block's hash
        expected_prev = r_hash

    return {
        "valid": True,
        "total_records": total,
        "verified_count": total,
        "broken_at": None,
        "message": f"All {total} audit records cryptographically verified. Hash chain is 100% intact."
    }


def get_audit_chain_records(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent audit chain blocks formatted for frontend visualization."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.timestamp, a.screening_id, a.record_hash, a.previous_hash, a.data_snapshot,
               h.doc_type, h.doc_number, h.person_name, h.verdict
        FROM audit_chain a
        LEFT JOIN screening_history h ON a.screening_id = h.screening_id
        ORDER BY a.id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        doc_type = r["doc_type"] if ("doc_type" in r.keys() and r["doc_type"]) else None
        doc_number = r["doc_number"] if ("doc_number" in r.keys() and r["doc_number"]) else None
        person_name = r["person_name"] if ("person_name" in r.keys() and r["person_name"]) else None
        verdict = r["verdict"] if ("verdict" in r.keys() and r["verdict"]) else None

        # Fallback to data_snapshot if not present in screening_history
        if (not doc_number or not doc_type) and r["data_snapshot"]:
            try:
                snap = json.loads(r["data_snapshot"])
                if not doc_type:
                    doc_type = snap.get("doc_type")
                if not doc_number:
                    doc_number = snap.get("doc_number") or snap.get("ocr", {}).get("fields", {}).get("passport_number") or snap.get("ocr", {}).get("fields", {}).get("id_number")
                if not person_name:
                    person_name = snap.get("person_name")
                if not verdict:
                    verdict = snap.get("verdict")
            except Exception:
                pass

        result.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "screening_id": r["screening_id"],
            "record_hash": r["record_hash"],
            "previous_hash": r["previous_hash"],
            "short_hash": r["record_hash"][:8],
            "short_prev_hash": r["previous_hash"][:8],
            "doc_type": doc_type or "DOCUMENT",
            "doc_number": doc_number or "N/A",
            "person_name": person_name or "N/A",
            "verdict": verdict or "RECORDED"
        })
    # Return in chronological order so it reads left-to-right (genesis to latest)
    result.reverse()
    return result


def get_all_mock_watchlists() -> List[Dict[str, Any]]:
    """Returns all mock database records for the dashboard viewer."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mock_watchlists ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dashboard_statistics() -> Dict[str, Any]:
    """Computes summary KPI stats and risk distribution for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM screening_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM screening_history WHERE verdict LIKE '%VERIFIED%' OR risk_level = 'LOW'")
    verified = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM screening_history WHERE verdict LIKE '%REVIEW%' OR risk_level = 'MEDIUM'")
    review = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM screening_history WHERE verdict LIKE '%HIGH RISK%' OR risk_level IN ('HIGH', 'CRITICAL')")
    high_risk = cursor.fetchone()[0]

    # Distribution counts
    cursor.execute("SELECT risk_level, COUNT(*) FROM screening_history GROUP BY risk_level")
    dist = {row[0]: row[1] for row in cursor.fetchall()}

    conn.close()

    return {
        "total_screened": total,
        "verified_count": verified,
        "review_count": review,
        "high_risk_count": high_risk,
        "distribution": {
            "LOW": dist.get("LOW", 0),
            "MEDIUM": dist.get("MEDIUM", 0),
            "HIGH": dist.get("HIGH", 0),
            "CRITICAL": dist.get("CRITICAL", 0)
        }
    }


def register_user(
    full_name: str,
    email: str,
    password: str,
    phone: str = "",
    gender: str = "",
    role: str = "OFFICER"
) -> Dict[str, Any]:
    """Registers a new user in the SQLite database."""
    clean_email = email.strip().lower()
    clean_name = full_name.strip()
    if not clean_email or not clean_name or not password:
        raise ValueError("Full name, email, and password are required")

    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?", (clean_email,))
    if cursor.fetchone():
        conn.close()
        raise ValueError("An account with this email address already exists")

    user_id = f"TL-USR-{uuid.uuid4().hex[:8].upper()}"
    pwd_hash = hash_password(password)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO users (user_id, full_name, email, phone, gender, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, clean_name, clean_email, phone.strip(), gender.strip(), pwd_hash, role, now_str))

    conn.commit()
    conn.close()

    return {
        "user_id": user_id,
        "full_name": clean_name,
        "email": clean_email,
        "phone": phone.strip(),
        "gender": gender.strip(),
        "role": role,
        "created_at": now_str
    }


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticates a user via email and password."""
    clean_email = email.strip().lower()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, full_name, email, phone, gender, password_hash, role, created_at
        FROM users WHERE LOWER(email) = ?
    """, (clean_email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    if not verify_password(password, row["password_hash"]):
        return None

    return {
        "user_id": row["user_id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "phone": row["phone"],
        "gender": row["gender"],
        "role": row["role"],
        "created_at": row["created_at"]
    }


def create_user_session(user_id: str, email: str, duration_hours: int = 168) -> Dict[str, Any]:
    """Creates a new user session token valid for duration_hours (default 7 days)."""
    session_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (now + timedelta(hours=duration_hours)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_sessions (session_token, user_id, email, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_token, user_id, email.lower().strip(), created_at, expires_at))
    conn.commit()
    conn.close()

    return {
        "session_token": session_token,
        "expires_at": expires_at
    }


def validate_user_session(session_token: str) -> Optional[Dict[str, Any]]:
    """Validates an active session token and returns the corresponding user."""
    if not session_token:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.session_token, s.user_id, s.expires_at,
               u.full_name, u.email, u.phone, u.gender, u.role, u.created_at
        FROM user_sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ?
    """, (session_token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    # Check expiration
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if row["expires_at"] < now_str:
        cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        conn.close()
        return None

    conn.close()
    return {
        "user_id": row["user_id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "phone": row["phone"],
        "gender": row["gender"],
        "role": row["role"],
        "session_token": row["session_token"]
    }


def delete_user_session(session_token: str) -> bool:
    """Deletes an active session (logout)."""
    if not session_token:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
    affected = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return affected


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by user_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, full_name, email, phone, gender, role, created_at
        FROM users WHERE user_id = ?
    """, (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


# Auto-initialize on import
init_database()
