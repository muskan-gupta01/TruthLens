"""
TruthLens Server Launcher
AI-Based Fake Identity & Document Screening System (SIH26188)
Ministry of Home Affairs - Blockchain & Cybersecurity
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8000))
    print("=" * 70)
    print("TRUTHLENS: AI-BASED FAKE IDENTITY & DOCUMENT SCREENING SYSTEM")
    print("SIH26188 | Ministry of Home Affairs | Blockchain & Cybersecurity")
    print("=" * 70)
    print(f"Server starting at: http://{host}:{port}")
    print(f"API Documentation:  http://{host}:{port}/docs")
    print("=" * 70)
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
