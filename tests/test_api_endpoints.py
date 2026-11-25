"""
Integration tests for FastAPI REST endpoints, Active IKE Scanner,
SQLite session persistence, and compiled React SPA serving.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_samples_and_testbed_endpoints():
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) >= 6
    filenames = [s["filename"] for s in samples]
    assert "hardened_ikev2_tunnel_web.pcap" in filenames
    assert "ipv6_natt_whatsapp_tunnel.pcap" in filenames
    assert "cbc_downgrade_email_audit.pcap" in filenames

    tb_res = client.get("/api/testbed/status")
    assert tb_res.status_code == 200
    assert "docker_running" in tb_res.json()

    ml_res = client.get("/api/ml/metrics")
    assert ml_res.status_code == 200
    assert ml_res.json().get("available") is True
    assert len(ml_res.json()["iscx_vpn2016_benchmark"]["leaderboard"]) == 4


def test_analyze_sample_history_and_export_reports():
    res = client.post("/api/analyze/sample/hardened_ikev2_tunnel_web.pcap")
    assert res.status_code == 200
    data = res.json()
    session_id = data["session_id"]
    assert session_id is not None
    assert data["score_breakdown"]["overall_score"] >= 80
    assert len(data["traffic_predictions"]) > 0

    # Session history persistence
    hist_res = client.get("/api/sessions")
    assert hist_res.status_code == 200
    assert any(s["session_id"] == session_id for s in hist_res.json())

    single_res = client.get(f"/api/sessions/{session_id}")
    assert single_res.status_code == 200
    assert single_res.json()["session_id"] == session_id

    # Report exports
    pdf_res = client.get(f"/api/report/pdf/{session_id}")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    md_res = client.get(f"/api/report/markdown/{session_id}")
    assert md_res.status_code == 200
    assert "Technical Security Assessment Report" in md_res.text

    json_res = client.get(f"/api/report/json/{session_id}")
    assert json_res.status_code == 200
    assert json_res.json()["session_id"] == session_id


def test_active_ike_scanner_endpoints():
    vuln_scan = client.post("/api/scan/target", json={"target_host": "demo-vulnerable-gw", "port": 500})
    assert vuln_scan.status_code == 200
    v_data = vuln_scan.json()
    assert v_data["reachable"] is True
    assert v_data["overall_grade"] == "F"
    assert len(v_data["probes"]) == 5

    hard_scan = client.post("/api/scan/target", json={"target_host": "demo-hardened-gw", "port": 500})
    assert hard_scan.status_code == 200
    h_data = hard_scan.json()
    assert h_data["reachable"] is True
    assert h_data["overall_grade"] in ("A+", "A-")


def test_dashboard_root_serving():
    res = client.get("/")
    assert res.status_code == 200
    assert "IPsec Sentinel AI" in res.text
