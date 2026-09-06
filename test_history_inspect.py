"""
TruthLens Automated Verification: History Inspect Detail View & Document Upload Serving
Built for SIH26188: AI-Based Fake Identity & Document Screening System
"""
import os
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from PIL import Image
import io

from app.main import app
from app.config import UPLOADS_DIR, SAMPLE_DOCS_DIR
from app.database.db_manager import (
    authenticate_user,
    create_user_session,
    init_database
)

client = TestClient(app)


class TestHistoryInspectDetailView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_database()
        # Authenticate officer session
        user = authenticate_user("officer@truthlens.gov.in", "TruthLens@2025")
        assert user is not None, "Failed to authenticate test officer"
        session_info = create_user_session(user["user_id"], user["email"])
        cls.token = session_info["session_token"]
        cls.auth_headers = {"Authorization": f"Bearer {cls.token}"}
        cls.auth_cookies = {"session_token": cls.token}

    def test_01_unauthenticated_document_access_blocked(self):
        """Verify GET /api/history/{id}/document strictly requires authentication (401)."""
        res = client.get("/api/history/TL-TEST-123456/document")
        self.assertEqual(res.status_code, 401, "Unauthenticated access must return 401 Unauthorized")
        print("  >>> PASS: Unauthenticated access to /api/history/{id}/document rejected with 401.")

    def test_02_path_traversal_prevention(self):
        """Verify directory traversal payloads are safely blocked."""
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2fconfig",
            "TL-2026/../../../sample_docs",
            "valid-id/../secret",
            "valid;rm -rf"
        ]
        for payload in traversal_payloads:
            res = client.get(f"/api/history/{payload}/document", headers=self.auth_headers)
            self.assertIn(
                res.status_code,
                [400, 404],
                f"Path traversal payload '{payload}' must be rejected with 400 or 404, got {res.status_code}"
            )
        print("  >>> PASS: Path traversal attacks safely rejected with 400/404.")

    def test_03_missing_document_fallback_message(self):
        """Verify missing/unavailable original document returns 404 'Original document unavailable'."""
        res = client.get("/api/history/TL-NONEXISTENT-000000/document", headers=self.auth_headers)
        self.assertEqual(res.status_code, 404)
        data = res.json()
        self.assertIn("Original document unavailable", data.get("detail", ""))
        print("  >>> PASS: Non-existent document returns 404 with exact detail 'Original document unavailable'.")

    def test_04_inspect_record_a_and_record_b_distinct_documents(self):
        """
        Verify that screening two distinct documents (Record A and Record B) stores
        and serves each record's exact original document without placeholders or cross-contamination.
        """
        # Document A: Genuine US Passport
        passport_path = SAMPLE_DOCS_DIR / "demo_passport_genuine.jpg"
        self.assertTrue(passport_path.exists(), "Passport sample document missing")
        passport_bytes = passport_path.read_bytes()

        # Document B: Genuine Aadhaar Card
        aadhaar_path = SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg"
        self.assertTrue(aadhaar_path.exists(), "Aadhaar sample document missing")
        aadhaar_bytes = aadhaar_path.read_bytes()

        # Screen Document A (Upload file)
        res_a = client.post(
            "/api/screen",
            headers=self.auth_headers,
            files={"file": ("passport_johnathan.jpg", passport_bytes, "image/jpeg")},
            data={"doc_type": "PASSPORT"}
        )
        self.assertEqual(res_a.status_code, 200, f"Screening Document A failed: {res_a.text}")
        data_a = res_a.json()
        id_a = data_a["screening_id"]
        self.assertTrue(id_a.startswith("TL-"))
        self.assertEqual(data_a["doc_type"], "PASSPORT")

        # Screen Document B (Upload file)
        res_b = client.post(
            "/api/screen",
            headers=self.auth_headers,
            files={"file": ("aadhaar_ashna.jpg", aadhaar_bytes, "image/jpeg")},
            data={"doc_type": "AADHAAR"}
        )
        self.assertEqual(res_b.status_code, 200, f"Screening Document B failed: {res_b.text}")
        data_b = res_b.json()
        id_b = data_b["screening_id"]
        self.assertTrue(id_b.startswith("TL-"))
        self.assertEqual(data_b["doc_type"], "AADHAAR")

        self.assertNotEqual(id_a, id_b, "Screening IDs must be distinct")

        # Fetch Document A via authenticated inspect endpoint
        doc_res_a = client.get(f"/api/history/{id_a}/document", headers=self.auth_headers)
        self.assertEqual(doc_res_a.status_code, 200)
        self.assertEqual(doc_res_a.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(doc_res_a.headers.get("Content-Type"), "image/jpeg")
        retrieved_bytes_a = doc_res_a.content

        # Fetch Document B via authenticated inspect endpoint
        doc_res_b = client.get(f"/api/history/{id_b}/document", headers=self.auth_headers)
        self.assertEqual(doc_res_b.status_code, 200)
        self.assertEqual(doc_res_b.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(doc_res_b.headers.get("Content-Type"), "image/jpeg")
        retrieved_bytes_b = doc_res_b.content

        # Exact byte comparisons
        self.assertEqual(retrieved_bytes_a, passport_bytes, "Retrieved Record A document must match uploaded Passport bit-for-bit")
        self.assertEqual(retrieved_bytes_b, aadhaar_bytes, "Retrieved Record B document must match uploaded Aadhaar bit-for-bit")
        self.assertNotEqual(retrieved_bytes_a, retrieved_bytes_b, "Document A and Document B must be completely distinct")

        # Verify via cookie auth as well
        cookie_res_a = client.get(f"/api/history/{id_a}/document", cookies=self.auth_cookies)
        self.assertEqual(cookie_res_a.status_code, 200)
        self.assertEqual(cookie_res_a.content, passport_bytes)

        print(f"  >>> PASS: Inspect Record A ({id_a}) returns Document A ({len(retrieved_bytes_a)} bytes).")
        print(f"  >>> PASS: Inspect Record B ({id_b}) returns Document B ({len(retrieved_bytes_b)} bytes).")
        print("  >>> PASS: Distinct corresponding documents verified with no placeholders or cross-record bleed.")

    def test_05_png_format_support(self):
        """Verify common formats including PNG are supported and served correctly."""
        # Create a valid test PNG in-memory
        img = Image.new("RGB", (200, 200), color=(0, 173, 181))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        res = client.post(
            "/api/screen",
            headers=self.auth_headers,
            files={"file": ("custom_id.png", png_bytes, "image/png")},
            data={"doc_type": "NON_IDENTITY_DOCUMENT"}
        )
        self.assertEqual(res.status_code, 200)
        id_png = res.json()["screening_id"]

        doc_res = client.get(f"/api/history/{id_png}/document", headers=self.auth_headers)
        self.assertEqual(doc_res.status_code, 200)
        self.assertEqual(doc_res.headers.get("Content-Type"), "image/png")
        self.assertEqual(doc_res.content, png_bytes)
        print("  >>> PASS: PNG document upload and serving verified.")

    def test_06_ui_state_contract_mutual_exclusivity(self):
        """
        Verify that index.html, style.css, and app.js implement the strict
        mutually exclusive 3-state contract (loading, success, error).
        """
        html_path = Path(__file__).parent / "static" / "index.html"
        css_path = Path(__file__).parent / "static" / "css" / "style.css"
        js_path = Path(__file__).parent / "static" / "js" / "app.js"

        self.assertTrue(html_path.exists())
        self.assertTrue(css_path.exists())
        self.assertTrue(js_path.exists())

        html_text = html_path.read_text(encoding="utf-8")
        css_text = css_path.read_text(encoding="utf-8")
        js_text = js_path.read_text(encoding="utf-8")

        # HTML contract: exactly one viewport containing the 3 state elements
        self.assertIn('id="inspect-preview-viewport"', html_text)
        self.assertIn('id="inspect-doc-img"', html_text)
        self.assertIn('id="inspect-doc-loading"', html_text)
        self.assertIn('id="inspect-doc-unavailable"', html_text)
        self.assertIn('Loading original document...', html_text)
        self.assertIn('Original document unavailable', html_text)

        # CSS contract: mutually exclusive data-state rules
        self.assertIn('#inspect-preview-viewport[data-state="loading"] #inspect-doc-loading', css_text)
        self.assertIn('#inspect-preview-viewport[data-state="loading"] #inspect-doc-img', css_text)
        self.assertIn('#inspect-preview-viewport[data-state="success"] #inspect-doc-img', css_text)
        self.assertIn('#inspect-preview-viewport[data-state="success"] #inspect-doc-loading', css_text)
        self.assertIn('#inspect-preview-viewport[data-state="error"] #inspect-doc-unavailable', css_text)
        self.assertIn('#inspect-preview-viewport[data-state="error"] #inspect-doc-loading', css_text)

        # JS contract: state transitions and sequence counters
        self.assertIn('INSPECT_DOC_STATES = {', js_text)
        self.assertIn('LOADING: \'loading\'', js_text)
        self.assertIn('SUCCESS: \'success\'', js_text)
        self.assertIn('ERROR: \'error\'', js_text)
        self.assertIn('setInspectDocState(state)', js_text)
        self.assertIn('historyInspectSeq', js_text)
        self.assertIn('inspectDocRequestSeq', js_text)

        print("  >>> PASS: UI state contract (Loading / Success / Error) mutually exclusive structure verified.")

    def test_07_repeated_inspect_interleaved_records(self):
        """
        Verify repeated Inspect clicks across valid and missing documents:
        Record 1 (Success) -> Record 2 (Missing/Unavailable) -> Record 3 (Success)
        ensuring each returns the exact correct status and payload without state bleed.
        """
        # Create 2 valid dummy screening records
        img1 = Image.new("RGB", (100, 100), color=(10, 20, 30))
        buf1 = io.BytesIO()
        img1.save(buf1, format="JPEG")
        bytes1 = buf1.getvalue()

        img2 = Image.new("RGB", (120, 120), color=(70, 80, 90))
        buf2 = io.BytesIO()
        img2.save(buf2, format="JPEG")
        bytes2 = buf2.getvalue()

        res1 = client.post(
            "/api/screen",
            headers=self.auth_headers,
            files={"file": ("doc1.jpg", bytes1, "image/jpeg")},
            data={"doc_type": "NON_IDENTITY_DOCUMENT"}
        )
        self.assertEqual(res1.status_code, 200)
        id1 = res1.json()["screening_id"]

        res2 = client.post(
            "/api/screen",
            headers=self.auth_headers,
            files={"file": ("doc2.jpg", bytes2, "image/jpeg")},
            data={"doc_type": "NON_IDENTITY_DOCUMENT"}
        )
        self.assertEqual(res2.status_code, 200)
        id2 = res2.json()["screening_id"]

        missing_id = "TL-DOESNOTEXIST-999"

        # Inspect 1: Doc 1 -> SUCCESS (200)
        insp1 = client.get(f"/api/history/{id1}/document", headers=self.auth_headers)
        self.assertEqual(insp1.status_code, 200)
        self.assertEqual(insp1.content, bytes1)

        # Inspect 2: Missing Record -> ERROR (404 with detail 'Original document unavailable')
        insp_missing = client.get(f"/api/history/{missing_id}/document", headers=self.auth_headers)
        self.assertEqual(insp_missing.status_code, 404)
        self.assertIn("Original document unavailable", insp_missing.json().get("detail", ""))

        # Inspect 3: Doc 2 -> SUCCESS (200)
        insp2 = client.get(f"/api/history/{id2}/document", headers=self.auth_headers)
        self.assertEqual(insp2.status_code, 200)
        self.assertEqual(insp2.content, bytes2)

        # Inspect 4: Repeated Inspect back to Doc 1 -> SUCCESS (200)
        insp1_repeat = client.get(f"/api/history/{id1}/document", headers=self.auth_headers)
        self.assertEqual(insp1_repeat.status_code, 200)
        self.assertEqual(insp1_repeat.content, bytes1)

        # Ensure no cross-contamination between any of the repeated requests
        self.assertNotEqual(insp1.content, insp2.content)
        self.assertEqual(insp1.content, insp1_repeat.content)

        print("  >>> PASS: Repeated Inspect sequence (Success -> Unavailable -> Success -> Repeat) strictly verified.")


if __name__ == "__main__":
    print("=" * 70)
    print("TRUTHLENS HISTORY INSPECT & DOCUMENT PREVIEW VERIFICATION SUITE")
    print("=" * 70)
    unittest.main(verbosity=2)

