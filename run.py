"""
Single-command launcher for the AI IPsec VPN Protocol Analyzer & Assessment Framework.
Starts the FastAPI backend service and serves the interactive SOC dashboard on port 8000.
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("   AI-POWERED IPSEC VPN PROTOCOL ANALYZER & ASSESSMENT FRAMEWORK")
    print("   NIST SP 800-77 Auditing • Encrypted ESP Traffic ML • SOC Dashboard")
    print("=" * 70)
    print(">>> Starting Web Dashboard at: http://127.0.0.1:8000")
    print(">>> Interactive API Documentation: http://127.0.0.1:8000/docs")
    print("=" * 70)
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False)
