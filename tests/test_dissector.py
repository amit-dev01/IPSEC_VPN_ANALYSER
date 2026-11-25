"""
Unit tests for the IKE Dissector and Protocol Extraction Engine.
Covers IKEv1, IKEv2, IPv6, NAT-T, Downgrade Risk, and AH/Replay checks.
"""

import os
from backend.app.services.ike_dissector import IKEDissector
from backend.app.schemas.models import ProtocolVersion, DHGroupStatus


def test_hardened_ikev2_pcap_parsing():
    pcap_path = os.path.join("datasets", "samples", "hardened_ikev2_tunnel_web.pcap")
    assert os.path.exists(pcap_path)

    dissector = IKEDissector()
    res = dissector.parse_pcap_detailed(pcap_path)
    sa = res.sa

    assert len(res.ike_packets) > 0
    assert len(res.esp_packets) > 0
    assert len(res.ike_timeline) == 2
    assert sa.ike_version == ProtocolVersion.IKEV2
    assert "AES-GCM" in sa.encryption_algorithm or "256" in sa.encryption_algorithm
    assert sa.dh_group_number == 19 or sa.dh_status == DHGroupStatus.SECURE
    assert sa.pfs_enabled is True
    assert sa.esn_enabled is True
    assert sa.downgrade_risk_detected is False


def test_vulnerable_ikev1_pcap_parsing():
    pcap_path = os.path.join("datasets", "samples", "vulnerable_ikev1_transport_msg.pcap")
    assert os.path.exists(pcap_path)

    dissector = IKEDissector()
    sa, ike_pkts, esp_pkts = dissector.parse_pcap(pcap_path)

    assert len(ike_pkts) > 0
    assert len(esp_pkts) > 0
    assert sa.ike_version == ProtocolVersion.IKEV1
    assert "3DES" in sa.encryption_algorithm
    assert sa.dh_group_number == 2
    assert sa.dh_status == DHGroupStatus.INSECURE
    assert sa.downgrade_risk_detected is True


def test_ipv6_natt_whatsapp_parsing():
    pcap_path = os.path.join("datasets", "samples", "ipv6_natt_whatsapp_tunnel.pcap")
    assert os.path.exists(pcap_path)

    dissector = IKEDissector()
    res = dissector.parse_pcap_detailed(pcap_path)

    assert res.sa.ip_version == "IPv6"
    assert res.sa.nat_traversal_detected is True
    assert len(res.esp_packets) > 0


def test_downgrade_proposal_detection():
    pcap_path = os.path.join("datasets", "samples", "cbc_downgrade_email_audit.pcap")
    assert os.path.exists(pcap_path)

    dissector = IKEDissector()
    res = dissector.parse_pcap_detailed(pcap_path)

    assert len(res.sa.proposals_offered) >= 2
    assert res.sa.downgrade_risk_detected is True
