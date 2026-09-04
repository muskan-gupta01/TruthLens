"""
TruthLens Authentication & Route Protection Verification Test Suite
"""
import sys
import uuid
from fastapi.testclient import TestClient

from app.main import app
import app.database.db_manager as db

client = TestClient(app)

def run_auth_tests():
    print("=" * 70)
    print("TRUTHLENS AUTHENTICATION & SESSION VERIFICATION SUITE")
    print("=" * 70)

    # 1. Test Seed User Login
    print("\n[TEST 1] Testing Default Officer Login...")
    res = client.post("/api/auth/login", json={
        "email": "officer@truthlens.gov.in",
        "password": "TruthLens@2025"
    })
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    login_data = res.json()
    assert login_data.get("success") is True, "Login response success was not True"
    assert "token" in login_data, "No token returned"
    assert login_data["user"]["email"] == "officer@truthlens.gov.in"
    token = login_data["token"]
    print("  >>> PASS: Seed officer login verified!")

    # 2. Test Invalid Password
    print("\n[TEST 2] Testing Invalid Password Rejection...")
    res = client.post("/api/auth/login", json={
        "email": "officer@truthlens.gov.in",
        "password": "WrongPassword!123"
    })
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print("  >>> PASS: Invalid password correctly rejected with 401 Unauthorized.")

    # 3. Test New User Registration
    test_email = f"officer.{uuid.uuid4().hex[:6]}@truthlens.gov.in"
    print(f"\n[TEST 3] Testing New Officer Registration ({test_email})...")
    res = client.post("/api/auth/register", json={
        "full_name": "Test Officer Sharma",
        "email": test_email,
        "phone": "+91 9123456789",
        "gender": "Female",
        "password": "SecurePassword@123",
        "confirm_password": "SecurePassword@123"
    })
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    reg_data = res.json()
    assert reg_data.get("success") is True
    assert reg_data["user"]["full_name"] == "Test Officer Sharma"
    new_token = reg_data["token"]
    print("  >>> PASS: User registered and session created.")

    # 4. Test Duplicate Email Registration
    print("\n[TEST 4] Testing Duplicate Email Rejection...")
    res = client.post("/api/auth/register", json={
        "full_name": "Duplicate Test",
        "email": test_email,
        "password": "SecurePassword@123",
        "confirm_password": "SecurePassword@123"
    })
    assert res.status_code == 400, f"Expected 400, got {res.status_code}"
    print("  >>> PASS: Duplicate email registration blocked.")

    # 5. Test /api/auth/me with Bearer Token
    print("\n[TEST 5] Testing /api/auth/me with Bearer Token...")
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert res.status_code == 200
    me_data = res.json()
    assert me_data.get("authenticated") is True
    assert me_data["user"]["email"] == test_email
    print("  >>> PASS: /api/auth/me correctly identifies authenticated user.")

    # 6. Test /api/auth/me with Cookie
    print("\n[TEST 6] Testing /api/auth/me with Session Cookie...")
    client_cookie = TestClient(app, cookies={"session_token": new_token})
    res = client_cookie.get("/api/auth/me")
    assert res.status_code == 200
    assert res.json().get("authenticated") is True
    print("  >>> PASS: Cookie-based session authentication verified.")

    # 7. Test Protected Route /dashboard without Cookie
    print("\n[TEST 7] Testing Protected Route /dashboard (Unauthenticated)...")
    unauth_client = TestClient(app)
    res = unauth_client.get("/dashboard", follow_redirects=False)
    assert res.status_code in [302, 303, 307], f"Expected redirect, got {res.status_code}"
    assert "/login" in res.headers.get("location", "")
    print(f"  >>> PASS: Unauthenticated access redirected to {res.headers.get('location')}")

    # 8. Test Protected Route /dashboard with Valid Cookie
    print("\n[TEST 8] Testing Protected Route /dashboard (Authenticated)...")
    res = client_cookie.get("/dashboard", follow_redirects=False)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert "TruthLens" in res.text
    print("  >>> PASS: Authenticated user granted access to dashboard UI.")

    # 9. Test Landing Page /
    print("\n[TEST 9] Testing Landing Page /...")
    res = client.get("/")
    assert res.status_code == 200
    assert "Trust every identity" in res.text
    assert "Log In" in res.text
    assert "Sign Up" in res.text
    assert "Muskan Gupta" in res.text
    print("  >>> PASS: Landing page serves integrated login interface.")

    # 10. Test Logout
    print("\n[TEST 10] Testing /api/auth/logout...")
    res = client_cookie.post("/api/auth/logout")
    assert res.status_code == 200
    # Re-check /api/auth/me with the deleted session token
    res_after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert res_after.json().get("authenticated") is False
    print("  >>> PASS: Logout invalidates session immediately.")

    print("\n" + "=" * 70)
    print("ALL 10 AUTHENTICATION & ROUTE TESTS PASSED!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_auth_tests()
    sys.exit(0 if success else 1)
