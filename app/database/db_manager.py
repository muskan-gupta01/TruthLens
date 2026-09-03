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
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.config import DB_PATH, DB_DIR

# Ensure DB directory exists
DB_DIR.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Returns an active SQLite connection with row factory set to sqlite3.Row."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Creates tables if they do not exist and seeds initial mock watchlist records."""
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
    person_name = data.get("ocr", {}).get("fields", {}).get("name") or data.get("ocr", {}).get("fields", {}).get("full_name") or "UNSPECIFIED"
    doc_number = data.get("ocr", {}).get("fields", {}).get("id_number") or data.get("ocr", {}).get("fields", {}).get("passport_number") or data.get("ocr", {}).get("fields", {}).get("visa_number")
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


# Auto-initialize on import
init_database()
