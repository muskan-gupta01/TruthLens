"""
TruthLens Server Launcher
AI-Based Fake Identity & Document Screening System (SIH26188)
Ministry of Home Affairs - Blockchain & Cybersecurity
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    print("=" * 70)
    print("TRUTHLENS: AI-BASED FAKE IDENTITY & DOCUMENT SCREENING SYSTEM")
    print("SIH26188 | Ministry of Home Affairs | Blockchain & Cybersecurity")
    print("=" * 70)
    print("Server starting at: http://127.0.0.1:8000")
    print("API Documentation:  http://127.0.0.1:8000/docs")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
