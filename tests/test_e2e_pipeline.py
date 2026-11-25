"""
End-to-End Pipeline integration tests.
Tests full analysis, AI 7-class predictions, covert C2 anomaly detection,
dynamic remediation, and PDF/Markdown report generation.
"""

import os
import tempfile
from backend.app.services.analyzer_service import IPsecAnalyzerService
from backend.app.services.report_generator import ReportGenerator
from backend.app.schemas.models import TrafficCategory
from testbed.traffic.pcap_builder import SyntheticIPsecPCAPGenerator


def test_full_analysis_pipeline_hardened():
    service = IPsecAnalyzerService()
    pcap_path = os.path.join("datasets", "samples", "hardened_ikev2_tunnel_web.pcap")
    result = service.analyze_pcap(pcap_path)

    assert result.session_id is not None
    assert result.total_packets_parsed > 0
    assert result.ike_packets_count > 0
    assert result.esp_packets_count > 0
    assert len(result.ike_timeline) > 0
    assert len(result.traffic_predictions) > 0
    assert len(result.traffic_predictions[0].shap_explanations) > 0
    assert result.traffic_predictions[0].iscx_secondary_prediction is not None
    assert 0.0 <= result.traffic_predictions[0].anomaly_score <= 1.0
    assert len(result.esp_flows[0].size_histogram) == 6
    assert result.score_breakdown.overall_score >= 80

    report_gen = ReportGenerator()
    pdf_out = os.path.join("reports", f"test_report_{result.session_id}.pdf")
    generated_pdf = report_gen.generate_executive_pdf(result, pdf_out)
    assert os.path.exists(generated_pdf)
    assert os.path.getsize(generated_pdf) > 1000

    md_out = report_gen.generate_technical_markdown(result)
    assert "Technical Security Assessment Report" in md_out
    assert "IKE Handshake Timeline" in md_out


def test_full_analysis_pipeline_vulnerable_and_context_remediation():
    service = IPsecAnalyzerService()
    pcap_path = os.path.join("datasets", "samples", "vulnerable_ikev1_transport_msg.pcap")
    result = service.analyze_pcap(pcap_path)

    assert result.session_id is not None
    assert result.score_breakdown.overall_score < 50
    assert len(result.threat_matrix) >= 2
    assert len(result.remediation_configs) == 3
    # Context-aware check: remediation includes actual peer IP from trace
    assert "192.168.100.10" in result.remediation_configs[0].config_snippet
    assert len(result.remediation_configs[0].addressed_issues) >= 2


def test_covert_c2_anomaly_detection():
    service = IPsecAnalyzerService()
    gen = SyntheticIPsecPCAPGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        c2_pcap = os.path.join(tmpdir, "c2_beacon_test.pcap")
        gen.generate_full_session_pcap(
            output_path=c2_pcap,
            ike_version=2,
            profile="hardened",
            traffic_type="C2_BEACON",
            mode="TUNNEL",
            packet_count=60,
        )
        result = service.analyze_pcap(c2_pcap)
        assert any("C2_BEACON_SUSPECTED" in f for f in result.esp_flows[0].anomaly_flags)
        assert any(t.threat_id == "THREAT-COVERT-C2" for t in result.threat_matrix)


def test_whatsapp_ipv6_classification():
    service = IPsecAnalyzerService()
    pcap_path = os.path.join("datasets", "samples", "ipv6_natt_whatsapp_tunnel.pcap")
    result = service.analyze_pcap(pcap_path)

    assert result.security_association.ip_version == "IPv6"
    assert result.traffic_predictions[0].predicted_category == TrafficCategory.WHATSAPP
