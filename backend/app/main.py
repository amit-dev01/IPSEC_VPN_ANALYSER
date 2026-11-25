"""
FastAPI Server Entrypoint for AI-Powered IPsec VPN Protocol Analyzer.
Provides RESTful APIs for PCAP upload, reference sample analysis, session history,
Active IKE Gateway Scanning, Docker testbed inspection, and multi-tier report export.
Serves the built React SPA from frontend/dist.
"""

import os
import shutil
import subprocess
import tempfile
from typing import List
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse, HTMLResponse

from backend.app.schemas.models import (
    AnalysisSessionResult, SessionSummary, ActiveScanRequest, ActiveScanResult
)
from backend.app.services.analyzer_service import IPsecAnalyzerService
from backend.app.services.report_generator import ReportGenerator
from backend.app.services.ike_scanner import ActiveIKEGatewayScanner

app = FastAPI(
    title="AI IPsec VPN Protocol Analyzer & Security Assessment Framework",
    version="2.0.0",
    description="Intelligent IPsec protocol parsing, NIST compliance auditing, active IKE scanning, and encrypted ESP traffic classification"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer_service = IPsecAnalyzerService()
report_gen = ReportGenerator()
ike_scanner = ActiveIKEGatewayScanner()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES_DIR = os.path.join(BASE_DIR, "datasets", "samples")
REAL_CAPTURES_DIR = os.path.join(BASE_DIR, "datasets", "real_captures")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
FRONTEND_DIST_DIR = os.path.join(BASE_DIR, "frontend", "dist")
FRONTEND_ASSETS_DIR = os.path.join(FRONTEND_DIST_DIR, "assets")
os.makedirs(REPORTS_DIR, exist_ok=True)

if os.path.isdir(FRONTEND_ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS_DIR), name="assets")


@app.get("/")
def serve_dashboard():
    """Serves the compiled React SOC dashboard."""
    index_file = os.path.join(FRONTEND_DIST_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse(
        "<h2>Frontend build not found</h2><p>Run <code>npm run build</code> inside <code>frontend/</code>.</p>",
        status_code=200
    )


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "IPsec VPN Protocol Analyzer API v2.0",
        "active_sessions": len(analyzer_service.list_sessions())
    }


def _describe_sample(filename: str) -> dict:
    lower = filename.lower()
    if "hardened" in lower and "web" in lower:
        return {"label": "Hardened IKEv2 (Web)", "badge": "LOW RISK", "desc": "AES-256-GCM • Group 19 ECDH • PFS • ESN • Web"}
    if "vulnerable" in lower:
        return {"label": "Vulnerable IKEv1", "badge": "CRITICAL", "desc": "3DES-CBC • MD5 • Group 2 • No PFS • Transport"}
    if "enterprise" in lower:
        return {"label": "Enterprise Standard", "badge": "MODERATE", "desc": "AES-128-CBC • SHA-256 • Group 14 • Video"}
    if "voip" in lower:
        return {"label": "Hardened VoIP", "badge": "LOW RISK", "desc": "AES-256-GCM • Group 19 • VoIP 20ms Audio"}
    if "whatsapp" in lower or "ipv6" in lower:
        return {"label": "IPv6 NAT-T WhatsApp", "badge": "LOW RISK", "desc": "IKEv2 over IPv6 • UDP 4500 NAT-T • WhatsApp Media"}
    if "downgrade" in lower or "email" in lower:
        return {"label": "Downgrade & Email Audit", "badge": "HIGH", "desc": "AES-CBC + 3DES Fallback Proposal • SMTP/IMAP"}
    return {"label": filename, "badge": "CAPTURE", "desc": "IPsec Session Capture"}


@app.get("/api/samples")
def list_sample_pcaps():
    """Lists available pre-generated and real Docker testbed PCAP captures."""
    samples = []
    for folder, source in ((SAMPLES_DIR, "testbed-sample"), (REAL_CAPTURES_DIR, "docker-live")):
        if not os.path.exists(folder):
            continue
        for f in sorted(os.listdir(folder)):
            if f.endswith((".pcap", ".pcapng", ".cap")):
                filepath = os.path.join(folder, f)
                meta = _describe_sample(f)
                samples.append({
                    "filename": f,
                    "source": source,
                    "size_bytes": os.path.getsize(filepath),
                    "label": meta["label"],
                    "badge": meta["badge"],
                    "description": meta["desc"],
                })
    return samples


@app.post("/api/analyze/sample/{sample_name}", response_model=AnalysisSessionResult)
def analyze_sample(sample_name: str):
    """Executes the analysis pipeline on a built-in or real-capture sample PCAP."""
    safe_name = os.path.basename(sample_name)
    for folder in (SAMPLES_DIR, REAL_CAPTURES_DIR):
        target_path = os.path.join(folder, safe_name)
        if os.path.exists(target_path):
            return analyzer_service.analyze_pcap(target_path, filename=safe_name)
    raise HTTPException(status_code=404, detail=f"Sample PCAP '{sample_name}' not found")


@app.post("/api/analyze/upload", response_model=AnalysisSessionResult)
async def analyze_uploaded_pcap(file: UploadFile = File(...)):
    """Uploads and analyzes a custom user PCAP capture with temp cleanup."""
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .pcap, .pcapng, or .cap capture.")

    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, os.path.basename(file.filename))
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return analyzer_service.analyze_pcap(temp_path, filename=file.filename)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/api/sessions", response_model=List[SessionSummary])
def list_sessions():
    """Returns persisted analysis session history sorted newest-first."""
    return analyzer_service.list_sessions()


@app.get("/api/sessions/{session_id}", response_model=AnalysisSessionResult)
def get_session(session_id: str):
    """Retrieves a previously analyzed session for inspection or comparison."""
    result = analyzer_service.get_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session ID not found")
    return result


@app.delete("/api/sessions/{session_id}")
def delete_session(session_id: str):
    if not analyzer_service.delete_session(session_id):
        raise HTTPException(status_code=404, detail="Session ID not found")
    return {"deleted": session_id}


@app.post("/api/scan/target", response_model=ActiveScanResult)
def active_ike_scan(req: ActiveScanRequest):
    """Actively probes an IPsec VPN gateway over UDP to audit accepted cipher/DH suites."""
    return ike_scanner.scan(req)


@app.get("/api/testbed/status")
def testbed_status():
    """Checks Docker Desktop daemon status and StrongSwan container availability."""
    docker_running = False
    containers = []
    try:
        proc = subprocess.run(["docker", "ps", "--format", "{{.Names}}:{{.Status}}"], capture_output=True, text=True, timeout=3)
        if proc.returncode == 0:
            docker_running = True
            for line in proc.stdout.strip().splitlines():
                if ":" in line:
                    name, st = line.split(":", 1)
                    containers.append({"name": name, "status": st})
    except Exception:
        pass

    real_files = os.listdir(REAL_CAPTURES_DIR) if os.path.isdir(REAL_CAPTURES_DIR) else []
    return {
        "docker_running": docker_running,
        "containers": containers,
        "real_captures_count": len([f for f in real_files if f.endswith(".pcap")]),
        "command_hint": "python testbed/run_live_docker_capture.py",
    }


@app.get("/api/report/pdf/{session_id}")
def download_pdf_report(session_id: str):
    """Downloads generated Executive Summary PDF report."""
    result = analyzer_service.get_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session ID not found")

    pdf_path = os.path.join(REPORTS_DIR, f"Executive_Report_{session_id}.pdf")
    report_gen.generate_executive_pdf(result, pdf_path)

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"IPsec_Executive_Report_{result.pcap_filename}_{session_id}.pdf"
    )


@app.get("/api/report/markdown/{session_id}")
def download_markdown_report(session_id: str):
    """Returns technical security audit report formatted in markdown."""
    result = analyzer_service.get_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session ID not found")

    md_content = report_gen.generate_technical_markdown(result)
    return PlainTextResponse(md_content, media_type="text/markdown")


@app.get("/api/report/json/{session_id}")
def download_json_report(session_id: str):
    """Returns full technical assessment model in JSON format."""
    result = analyzer_service.get_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session ID not found")

    return JSONResponse(content=result.model_dump(mode="json"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
