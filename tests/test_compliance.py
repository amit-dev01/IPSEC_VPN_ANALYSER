"""
Unit tests for the Cryptographic Compliance Engine and Threat Matrix generation.
"""

import pytest
from backend.app.services.compliance_engine import CryptographicComplianceEngine
from backend.app.schemas.models import (
    SecurityAssociation, ProtocolVersion, OperatingMode, DHGroupStatus,
    ComplianceStatus, SeverityLevel
)


def test_hardened_sa_compliance():
    engine = CryptographicComplianceEngine()
    sa = SecurityAssociation(
        initiator_spi="abcdef1234567890",
        responder_spi="fedcba0987654321",
        ike_version=ProtocolVersion.IKEV2,
        mode=OperatingMode.TUNNEL,
        encryption_algorithm="AES-GCM-256",
        key_length=256,
        integrity_algorithm="AUTH_HMAC_SHA2_256_128",
        dh_group="Group 19 (256-bit ECP)",
        dh_group_number=19,
        dh_status=DHGroupStatus.SECURE,
        pfs_enabled=True,
        sa_lifetime_seconds=3600
    )

    findings = engine.evaluate_compliance(sa)
    threats = engine.generate_threat_matrix(findings)
    score = engine.calculate_security_score(sa, findings)

    # Should have no critical failures
    critical_fails = [f for f in findings if f.status == ComplianceStatus.FAIL and f.severity == SeverityLevel.CRITICAL]
    assert len(critical_fails) == 0
    assert len(threats) == 0
    assert score.overall_score >= 80
    assert score.risk_level == SeverityLevel.LOW


def test_vulnerable_sa_compliance():
    engine = CryptographicComplianceEngine()
    sa = SecurityAssociation(
        initiator_spi="1111222233334444",
        ike_version=ProtocolVersion.IKEV1,
        mode=OperatingMode.TRANSPORT,
        encryption_algorithm="3DES-CBC",
        key_length=168,
        integrity_algorithm="HMAC-MD5",
        dh_group="Group 2 (1024-bit MODP)",
        dh_group_number=2,
        dh_status=DHGroupStatus.INSECURE,
        pfs_enabled=False,
        sa_lifetime_seconds=86400
    )

    findings = engine.evaluate_compliance(sa)
    threats = engine.generate_threat_matrix(findings)
    score = engine.calculate_security_score(sa, findings)

    # Should trigger critical failures for 3DES and DH Group 2
    critical_fails = [f for f in findings if f.status == ComplianceStatus.FAIL and f.severity == SeverityLevel.CRITICAL]
    assert len(critical_fails) >= 2
    assert len(threats) >= 2
    assert score.overall_score < 50
    assert score.risk_level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
