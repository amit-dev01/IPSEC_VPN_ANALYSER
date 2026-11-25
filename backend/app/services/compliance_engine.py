"""
Cryptographic Compliance and Security Evaluation Engine for IPsec VPNs.
Evaluates IKE/ESP/AH configurations against NIST SP 800-77 Rev 1, RFC 8221, CNSA 2.0,
assesses Post-Quantum Cryptography (PQC) readiness, downgrade risks, replay protection,
and computes metadata exposure dynamically from flow metrics.
"""

from typing import List, Optional
from backend.app.schemas.models import (
    SecurityAssociation, ComplianceFinding, ComplianceStatus,
    SeverityLevel, ThreatItem, SecurityScoreBreakdown, DHGroupStatus,
    ESPFlowStatistics, TrafficPrediction, OperatingMode
)


class CryptographicComplianceEngine:
    """
    Rigorously verifies cryptographic algorithms, DH groups, forward secrecy,
    downgrade hygiene, replay protection, and metadata exposure.
    """

    def evaluate_compliance(
        self,
        sa: SecurityAssociation,
        esp_flows: Optional[List[ESPFlowStatistics]] = None
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        esp_flows = esp_flows or []

        # 1. NIST SP 800-77 Rev 1 - IKE Version & Aggressive Mode Check
        if sa.ike_version.value == "IKEv1":
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-IPSEC-01",
                title="Deprecated IKEv1 Protocol in Use",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description="IKEv1 is officially deprecated due to lack of DoS resistance, complex multi-mode negotiations, and historical vulnerabilities.",
                current_value="IKEv1" + (" (Aggressive Mode)" if sa.aggressive_mode_detected else ""),
                recommended_value="IKEv2 (RFC 7296)",
                reference_url="https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final"
            ))
            if sa.aggressive_mode_detected:
                findings.append(ComplianceFinding(
                    standard="CIS IPsec Benchmark",
                    rule_id="CIS-IKEV1-AGG",
                    title="IKEv1 Aggressive Mode PSK Hash Exposure",
                    status=ComplianceStatus.FAIL,
                    severity=SeverityLevel.CRITICAL,
                    description="IKEv1 Aggressive Mode transmits identity and PSK hash in cleartext before encryption, enabling offline brute-force attacks (ike-scan).",
                    current_value="IKEv1 Aggressive Mode",
                    recommended_value="IKEv2 or IKEv1 Main Mode with Certificates"
                ))
        else:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-IPSEC-01",
                title="IKE Protocol Modernity Check",
                status=ComplianceStatus.PASS,
                severity=SeverityLevel.INFO,
                description="Deployment utilizes modern IKEv2 protocol with cookie-based anti-spoofing and streamlined SA negotiation.",
                current_value=sa.ike_version.value,
                recommended_value="IKEv2"
            ))

        # 2. Encryption Algorithm Assessment (RFC 8221 / NIST)
        encr = sa.encryption_algorithm.upper()
        if any(weak in encr for weak in ["3DES", "DES", "NULL", "BLOWFISH", "RC5", "CAST"]):
            findings.append(ComplianceFinding(
                standard="RFC 8221",
                rule_id="RFC8221-CIPH-01",
                title="Broken or Deprecated Symmetric Cipher",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.CRITICAL,
                description="3DES, DES, and NULL ciphers are vulnerable to Sweet32 (CVE-2016-2183) 64-bit block collisions or expose plaintext directly.",
                current_value=sa.encryption_algorithm,
                recommended_value="AES-256-GCM or AES-128-GCM (AEAD)",
                reference_url="https://datatracker.ietf.org/doc/html/rfc8221"
            ))
        elif "GCM" in encr or "CHACHA20" in encr or "CCM" in encr:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1 / CNSA 2.0",
                rule_id="NIST-CIPH-02",
                title="Authenticated Encryption with Associated Data (AEAD)",
                status=ComplianceStatus.PASS,
                severity=SeverityLevel.INFO,
                description="Symmetric cipher utilizes AEAD mode, guaranteeing confidentiality and tamper integrity without CBC padding oracle risks.",
                current_value=sa.encryption_algorithm,
                recommended_value="AES-256-GCM / CHACHA20-POLY1305"
            ))
        elif "CBC" in encr:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-CIPH-03",
                title="Legacy CBC Mode Encryption without AEAD",
                status=ComplianceStatus.WARNING,
                severity=SeverityLevel.MEDIUM,
                description="CBC mode requires separate HMAC integrity checks and leaks ciphertext block boundaries / padding patterns unless using Encrypt-then-MAC + TFC.",
                current_value=sa.encryption_algorithm,
                recommended_value="Migrate to AES-256-GCM (AEAD)"
            ))

        # 3. Diffie-Hellman Group Strength
        dh_status = sa.dh_status
        dh_num = sa.dh_group_number or 0
        if dh_status == DHGroupStatus.INSECURE:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 / RFC 8221",
                rule_id="NIST-DH-01",
                title="Critically Weak Diffie-Hellman Group (< 2048-bit)",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.CRITICAL,
                description=f"DH Group {dh_num} provides <112 bits of equivalent security. Discrete logarithm attacks (Logjam) can precompute and compromise session keys.",
                current_value=sa.dh_group or f"Group {dh_num}",
                recommended_value="Group 19 (256-bit ECP), Group 20 (384-bit ECP), or Group 14 minimum"
            ))
        elif dh_status == DHGroupStatus.LEGACY:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-DH-02",
                title="Legacy MODP DH Group (Group 14)",
                status=ComplianceStatus.WARNING,
                severity=SeverityLevel.LOW,
                description="Group 14 (2048-bit MODP) provides 112 bits of security; meets baseline compliance but ECC (Group 19/20) is strongly preferred.",
                current_value=sa.dh_group or "Group 14",
                recommended_value="Group 19 (ECP-256) or Group 21 (ECP-521)"
            ))
        else:
            findings.append(ComplianceFinding(
                standard="CNSA 2.0 / NIST SP 800-77",
                rule_id="NIST-DH-03",
                title="Robust Elliptic Curve Diffie-Hellman Group",
                status=ComplianceStatus.PASS,
                severity=SeverityLevel.INFO,
                description="DH Group provides 128+ bits of modern cryptographic security with low compute overhead.",
                current_value=sa.dh_group or f"Group {dh_num}",
                recommended_value="Group 19/20/21"
            ))

        # 4. Hash & Integrity Algorithm
        integ = (sa.integrity_algorithm or "").upper()
        if "MD5" in integ or "SHA1" in integ or "SHA_1" in integ:
            findings.append(ComplianceFinding(
                standard="RFC 8221",
                rule_id="RFC8221-HASH-01",
                title="Cryptographically Broken Integrity / PRF Algorithm",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description=f"Hash algorithm {sa.integrity_algorithm} is vulnerable to collision attacks (SHAttered / Flame).",
                current_value=sa.integrity_algorithm or "MD5/SHA1",
                recommended_value="HMAC-SHA256, HMAC-SHA384, or Combined-mode AEAD"
            ))

        # 5. Proposal Downgrade Attack Surface
        if sa.downgrade_risk_detected:
            findings.append(ComplianceFinding(
                standard="RFC 8221 / CIS IPsec",
                rule_id="CIS-DOWNGRADE-01",
                title="Weak Fallback Proposal Offered (Downgrade Risk)",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description="At least one offered IKE/ESP proposal contains weak/deprecated cryptographic transforms, allowing an active MITM to force a cipher downgrade.",
                current_value="Mixed / Weak Fallback Transforms Offered",
                recommended_value="Remove all DES/3DES/MD5/SHA1/DH<14 proposals from gateway policy"
            ))

        # 6. Perfect Forward Secrecy (PFS)
        if not sa.pfs_enabled:
            findings.append(ComplianceFinding(
                standard="CIS IPsec Benchmark",
                rule_id="CIS-PFS-01",
                title="Perfect Forward Secrecy (PFS) Disabled",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description="Child SA does not negotiate an independent Diffie-Hellman exchange. Compromising master keys allows decrypting recorded historical sessions.",
                current_value="PFS Disabled",
                recommended_value="Enable PFS (DH Group 19 or 14)"
            ))
        else:
            findings.append(ComplianceFinding(
                standard="CIS IPsec Benchmark",
                rule_id="CIS-PFS-01",
                title="Perfect Forward Secrecy (PFS) Active",
                status=ComplianceStatus.PASS,
                severity=SeverityLevel.INFO,
                description="PFS is active on Child SAs ensuring unique ephemeral keys per session.",
                current_value="PFS Enabled",
                recommended_value="PFS Enabled"
            ))

        # 7. Replay Protection & Extended Sequence Numbers (ESN)
        if not sa.replay_protection_enabled or sa.replay_anomalies_detected > 0:
            findings.append(ComplianceFinding(
                standard="RFC 4303 / NIST SP 800-77",
                rule_id="RFC4303-REPLAY-01",
                title="ESP Anti-Replay Sequence Anomaly Detected",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description=f"Detected {sa.replay_anomalies_detected} non-monotonic or zero ESP sequence numbers, indicating disabled anti-replay protection or an active replay attempt.",
                current_value=f"{sa.replay_anomalies_detected} sequence anomalies",
                recommended_value="Enforce strict ESP anti-replay window (>= 64) and ESN"
            ))
        else:
            findings.append(ComplianceFinding(
                standard="RFC 4303 / NIST SP 800-77",
                rule_id="RFC4303-REPLAY-01",
                title="ESP Sequence Integrity & Anti-Replay Validated",
                status=ComplianceStatus.PASS,
                severity=SeverityLevel.INFO,
                description="ESP sequence numbers increase monotonically without duplicates or zero-sequence resets." + (" 64-bit ESN negotiated." if sa.esn_enabled else ""),
                current_value="Monotonic Sequence" + (" (ESN Active)" if sa.esn_enabled else ""),
                recommended_value="Monotonic Anti-Replay Active"
            ))

        # 8. AH Without Confidentiality Check
        if sa.ah_detected and not esp_flows:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-AH-01",
                title="Authentication Header (AH) Without ESP Encryption",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.HIGH,
                description="AH authenticates packet headers and payloads but provides ZERO confidentiality—all internal data is visible in plaintext on the wire.",
                current_value="AH Only (Unencrypted)",
                recommended_value="Replace AH with ESP AEAD (AES-GCM)"
            ))

        # 9. Transport Mode Metadata Exposure
        if sa.mode == OperatingMode.TRANSPORT:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-MODE-01",
                title="Transport Mode Exposes Original IP Metadata",
                status=ComplianceStatus.WARNING,
                severity=SeverityLevel.LOW,
                description="Transport mode leaves original source/destination IP headers unencrypted, revealing internal topology and endpoint identities to passive observers.",
                current_value="TRANSPORT Mode",
                recommended_value="TUNNEL Mode for site-to-site / remote access gateways"
            ))

        # 10. Low Payload Entropy / Metadata Leakage
        low_entropy_flows = [f for f in esp_flows if f.entropy_score > 0 and f.entropy_score < 7.2]
        if low_entropy_flows:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 / Side-Channel Audit",
                rule_id="META-ENTROPY-01",
                title="Abnormally Low ESP Payload Entropy Detected",
                status=ComplianceStatus.FAIL,
                severity=SeverityLevel.CRITICAL,
                description=f"{len(low_entropy_flows)} ESP flow(s) show Shannon entropy below 7.2 bits/byte, indicating NULL encryption, weak ECB/key reuse, or plaintext leakage.",
                current_value=f"Min entropy: {min(f.entropy_score for f in low_entropy_flows)} bits/byte",
                recommended_value=">= 7.8 bits/byte (Proper randomized AES-GCM / ChaCha20 ciphertext)"
            ))

        # 11. Post-Quantum Cryptography (PQC) Readiness Radar
        if sa.dh_status != DHGroupStatus.POST_QUANTUM:
            findings.append(ComplianceFinding(
                standard="CNSA 2.0 Quantum Advisory",
                rule_id="PQC-RADAR-01",
                title="Quantum Harvest-Now-Decrypt-Later Exposure",
                status=ComplianceStatus.WARNING,
                severity=SeverityLevel.MEDIUM,
                description="Key exchange relies on classical DH/ECC. Adversaries archiving traffic today can decrypt it once cryptanalytically relevant quantum computers (CRQCs) arrive.",
                current_value=sa.dh_group or "Classical DH",
                recommended_value="RFC 9370 Hybrid KEM (ML-KEM-768 / Kyber)"
            ))

        # 12. SA Lifetime Check
        lifetime = sa.sa_lifetime_seconds or 3600
        if lifetime > 28800:
            findings.append(ComplianceFinding(
                standard="NIST SP 800-77 Rev 1",
                rule_id="NIST-LIFE-01",
                title="Excessive Security Association Lifetime",
                status=ComplianceStatus.WARNING,
                severity=SeverityLevel.MEDIUM,
                description=f"SA Lifetime is configured to {lifetime} seconds (> 8 hours). Prolonged key lifetimes increase crypto-material exposure.",
                current_value=f"{lifetime} seconds",
                recommended_value="<= 28800 seconds (8 hours) or rekey by volume (1 GB)"
            ))

        return findings

    def generate_threat_matrix(
        self,
        findings: List[ComplianceFinding],
        predictions: Optional[List[TrafficPrediction]] = None
    ) -> List[ThreatItem]:
        threats: List[ThreatItem] = []
        predictions = predictions or []

        for f in findings:
            if f.status == ComplianceStatus.FAIL:
                if "CIPH-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-SWEET32",
                        title="Sweet32 Ciphertext Collision & Plaintext Recovery",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=8.1,
                        mitre_technique_id="T1040 (Network Sniffing)",
                        description="Eavesdroppers capturing long-lived 64-bit block cipher sessions (3DES/DES) can recover sensitive tokens via birthday collisions.",
                        impact="Confidentiality loss of internal IPsec payload",
                        remediation_advice="Disable 3DES/DES immediately and enforce AES-256-GCM."
                    ))
                elif "DH-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-LOGJAM",
                        title="Diffie-Hellman Discrete Log Precomputation (Logjam)",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=8.6,
                        mitre_technique_id="T1557 (Adversary-in-the-Middle)",
                        description="Well-resourced adversaries can precompute discrete log tables for 768/1024-bit primes to recover session keys.",
                        impact="Full session compromise and MITM injection",
                        remediation_advice="Upgrade DH Group to Group 19 (ECP-256) or Group 14 (MODP-2048) minimum."
                    ))
                elif "AGG" in f.rule_id or "IPSEC-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-IKEV1-EXPLOITS",
                        title="IKEv1 Amplification & Offline PSK Cracking",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.5,
                        mitre_technique_id="T1110 (Brute Force)",
                        description="Legacy IKEv1 lacks DoS cookie defense and exposes pre-shared key hashes in Aggressive Mode.",
                        impact="Credential theft and unauthorized tunnel access",
                        remediation_advice="Migrate tunnel negotiation exclusively to IKEv2."
                    ))
                elif "PFS-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-RETROACTIVE-DECRYPT",
                        title="Retroactive Bulk Session Decryption (No PFS)",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.4,
                        mitre_technique_id="T1552 (Unsecured Credentials)",
                        description="Without ephemeral Child SA Diffie-Hellman exchange, compromising long-term keys unlocks all past archived sessions.",
                        impact="Complete historical confidentiality breach",
                        remediation_advice="Enforce PFS (DH Group 19+) on all Child SA esp_proposals."
                    ))
                elif "DOWNGRADE-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-CIPHER-DOWNGRADE",
                        title="MITM Cryptographic Downgrade Attack",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.2,
                        mitre_technique_id="T1557 (Adversary-in-the-Middle)",
                        description="Offering weak fallback transforms lets an on-path attacker drop strong proposals and force negotiation onto legacy suites.",
                        impact="Silent weakening of session encryption",
                        remediation_advice="Purge all weak fallback suites from gateway policies."
                    ))
                elif "REPLAY-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-PACKET-REPLAY",
                        title="ESP Packet Replay / Sequence Spoofing",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.1,
                        mitre_technique_id="T1557 (Adversary-in-the-Middle)",
                        description="Duplicate or non-monotonic ESP sequence numbers indicate anti-replay enforcement gaps.",
                        impact="Duplicate packet injection and state disruption",
                        remediation_advice="Enable anti-replay window validation and 64-bit ESN."
                    ))
                elif "ENTROPY-01" in f.rule_id:
                    threats.append(ThreatItem(
                        threat_id="THREAT-PLAINTEXT-LEAK",
                        title="Low-Entropy Ciphertext / Null Encryption Leak",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=9.1,
                        mitre_technique_id="T1040 (Network Sniffing)",
                        description="Statistical randomness of ESP payloads falls below encrypted thresholds, exposing structural plaintext patterns.",
                        impact="Direct payload leakage",
                        remediation_advice="Verify active ESP encryption transform is AES-GCM, not ENCR_NULL."
                    ))

        # Covert / Behavioral AI Threat Vectors
        for pred in predictions:
            for flag in pred.anomaly_flags:
                if "C2_BEACON" in flag:
                    threats.append(ThreatItem(
                        threat_id="THREAT-COVERT-C2",
                        title="Suspected Covert C2 Beaconing Inside Encrypted Tunnel",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.8,
                        mitre_technique_id="T1572 (Protocol Tunneling)",
                        description=f"Flow {pred.flow_id} displays highly periodic small-packet heartbeats characteristic of command-and-control beaconing.",
                        impact="Unauthorized persistence / covert channel inside VPN",
                        remediation_advice="Inspect endpoint identity associated with SPI and audit outbound firewall policy."
                    ))
                elif "EXFILTRATION" in flag:
                    threats.append(ThreatItem(
                        threat_id="THREAT-EXFIL-BURST",
                        title="Asymmetric Bulk Outbound Burst (Exfiltration Risk)",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=6.5,
                        mitre_technique_id="T1048 (Exfiltration Over Alternative Protocol)",
                        description=f"Flow {pred.flow_id} exhibits sustained asymmetric MTU-sized bursts consistent with bulk data exfiltration.",
                        impact="Potential undetected egress of sensitive enterprise datasets",
                        remediation_advice="Correlate tunnel byte volume against internal user DLP baselines."
                    ))

        return threats

    def calculate_security_score(
        self,
        sa: SecurityAssociation,
        findings: List[ComplianceFinding],
        esp_flows: Optional[List[ESPFlowStatistics]] = None,
        predictions: Optional[List[TrafficPrediction]] = None
    ) -> SecurityScoreBreakdown:
        """Computes composite security score (0 to 100) dynamically across 5 dimensions."""
        esp_flows = esp_flows or []
        predictions = predictions or []

        crypto_score = 100
        ke_score = 100
        hygiene_score = 100
        quantum_score = 45 if sa.dh_status != DHGroupStatus.POST_QUANTUM else 100

        # Dynamic Traffic & Metadata Exposure Score
        exposure_score = 98
        if sa.mode == OperatingMode.TRANSPORT:
            exposure_score -= 18  # Exposes inner host IP metadata
        if "CBC" in sa.encryption_algorithm.upper():
            exposure_score -= 12  # Padding / block-length metadata leakage
        if sa.ah_detected and not esp_flows:
            exposure_score -= 60  # Unencrypted AH payload
        if esp_flows:
            avg_entropy = sum(f.entropy_score for f in esp_flows) / len(esp_flows)
            if avg_entropy < 7.2:
                exposure_score -= 40
            elif avg_entropy < 7.7:
                exposure_score -= 15
        if any(p.anomaly_flags for p in predictions):
            exposure_score -= 20
        exposure_score = max(10, min(100, exposure_score))

        for f in findings:
            if f.severity == SeverityLevel.CRITICAL and f.status == ComplianceStatus.FAIL:
                if "CIPH" in f.rule_id:
                    crypto_score = max(10, crypto_score - 70)
                if "DH" in f.rule_id:
                    ke_score = max(10, ke_score - 75)
                if "AGG" in f.rule_id:
                    hygiene_score = max(15, hygiene_score - 50)
                if "ENTROPY" in f.rule_id:
                    crypto_score = max(10, crypto_score - 60)
            elif f.severity == SeverityLevel.HIGH and f.status == ComplianceStatus.FAIL:
                if "PFS" in f.rule_id:
                    ke_score = max(25, ke_score - 40)
                if "HASH" in f.rule_id:
                    crypto_score = max(25, crypto_score - 45)
                if "IPSEC-01" in f.rule_id:
                    hygiene_score = max(25, hygiene_score - 35)
                if "DOWNGRADE" in f.rule_id:
                    crypto_score = max(30, crypto_score - 25)
                if "REPLAY" in f.rule_id:
                    hygiene_score = max(25, hygiene_score - 30)
                if "AH-01" in f.rule_id:
                    crypto_score = max(15, crypto_score - 70)
            elif f.severity == SeverityLevel.MEDIUM and f.status == ComplianceStatus.WARNING:
                if "CIPH" in f.rule_id:
                    crypto_score = max(60, crypto_score - 20)
                if "LIFE" in f.rule_id:
                    hygiene_score = max(60, hygiene_score - 25)

        overall = int(
            (crypto_score * 0.35) +
            (ke_score * 0.25) +
            (hygiene_score * 0.15) +
            (exposure_score * 0.15) +
            (quantum_score * 0.10)
        )
        overall = max(0, min(100, overall))

        if overall >= 85:
            risk = SeverityLevel.LOW
        elif overall >= 65:
            risk = SeverityLevel.MEDIUM
        elif overall >= 45:
            risk = SeverityLevel.HIGH
        else:
            risk = SeverityLevel.CRITICAL

        return SecurityScoreBreakdown(
            overall_score=overall,
            risk_level=risk,
            cryptographic_score=crypto_score,
            key_exchange_score=ke_score,
            operational_hygiene_score=hygiene_score,
            quantum_readiness_score=quantum_score,
            traffic_exposure_score=exposure_score
        )
