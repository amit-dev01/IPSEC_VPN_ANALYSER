"""
Core Pydantic data schemas for the IPsec VPN Protocol Analyzer and Security Assessment Framework.
Defines protocol representations, IKE packet timelines, cryptographic compliance models,
ESP flow statistics, active scanner results, AI predictions, and risk reports.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ProtocolVersion(str, Enum):
    IKEV1 = "IKEv1"
    IKEV2 = "IKEv2"
    ESP = "ESP"
    AH = "AH"
    UNKNOWN = "UNKNOWN"


class OperatingMode(str, Enum):
    TUNNEL = "TUNNEL"
    TRANSPORT = "TRANSPORT"
    UNKNOWN = "UNKNOWN"


class TrafficCategory(str, Enum):
    VOIP = "VoIP / Real-Time Audio"
    VIDEO = "Video Streaming"
    WEB = "Web Browsing (HTTPS/HTTP)"
    MESSAGING = "Interactive Messaging / Chat"
    WHATSAPP = "WhatsApp / Encrypted Media & Chat"
    EMAIL = "E-Mail (SMTP/IMAP/TLS)"
    BULK_TRANSFER = "Bulk Data / File Transfer"
    ICMP = "Network Diagnostics (ICMP)"
    UNKNOWN = "Unknown Encrypted Payload"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"


class DHGroupStatus(str, Enum):
    INSECURE = "INSECURE"         # Group 1 (768), Group 2 (1024), Group 5 (1536)
    LEGACY = "LEGACY"             # Group 14 (2048-bit MODP)
    SECURE = "SECURE"             # Group 15/16, Group 19/20/21 ECP, Curve25519
    POST_QUANTUM = "POST_QUANTUM" # Hybrid / ML-KEM / RFC 9370


class TransformInfo(BaseModel):
    transform_type: str  # ENCR, PRF, INTEG, D-H, ESN
    transform_id: int
    transform_name: str
    key_length: Optional[int] = None
    security_rating: str = "UNKNOWN"  # SECURE, LEGACY, INSECURE


class IKEProposal(BaseModel):
    proposal_number: int
    protocol_id: str  # IKE, ESP, AH
    spi: Optional[str] = None
    transforms: List[TransformInfo] = Field(default_factory=list)
    has_weak_transform: bool = False


class IKEPacketSummary(BaseModel):
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ike_version: str
    exchange_type: str
    role: str  # Initiator / Responder
    message_id: int
    length_bytes: int
    initiator_spi: str
    responder_spi: str
    payloads: List[str] = Field(default_factory=list)


class SecurityAssociation(BaseModel):
    ike_version: ProtocolVersion = ProtocolVersion.UNKNOWN
    ip_version: str = "IPv4"
    initiator_spi: str
    responder_spi: Optional[str] = None
    peer_ips: List[str] = Field(default_factory=list)
    mode: OperatingMode = OperatingMode.UNKNOWN
    encryption_algorithm: str = "Unknown"
    key_length: Optional[int] = None
    integrity_algorithm: Optional[str] = None
    prf_algorithm: Optional[str] = None
    dh_group: Optional[str] = None
    dh_group_number: Optional[int] = None
    dh_status: DHGroupStatus = DHGroupStatus.INSECURE
    pfs_enabled: bool = False
    esn_enabled: bool = False
    sa_lifetime_seconds: Optional[int] = None
    sa_lifetime_kilobytes: Optional[int] = None
    nat_traversal_detected: bool = False
    replay_protection_enabled: bool = True
    replay_anomalies_detected: int = 0
    downgrade_risk_detected: bool = False
    aggressive_mode_detected: bool = False
    ah_detected: bool = False
    notify_messages: List[str] = Field(default_factory=list)
    proposals_offered: List[IKEProposal] = Field(default_factory=list)


class ComplianceFinding(BaseModel):
    standard: str  # NIST SP 800-77, RFC 8221, CNSA 2.0
    rule_id: str
    title: str
    status: ComplianceStatus
    severity: SeverityLevel
    description: str
    current_value: str
    recommended_value: str
    reference_url: Optional[str] = None


class ThreatItem(BaseModel):
    threat_id: str
    title: str
    severity: SeverityLevel
    cvss_score: float
    description: str
    mitre_technique_id: Optional[str] = None
    impact: str
    remediation_advice: str


class SizeBin(BaseModel):
    bucket: str
    count: int


class ESPFlowStatistics(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    spi: str
    protocol: str = "ESP"
    ip_version: str = "IPv4"
    packet_count: int
    total_bytes: int
    duration_seconds: float
    packet_rate_pps: float
    byte_rate_bps: float
    mean_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int
    p25_packet_size: float = 0.0
    p50_packet_size: float = 0.0
    p75_packet_size: float = 0.0
    iat_mean_ms: float
    iat_std_ms: float
    iat_p50_ms: float = 0.0
    burst_count: int
    entropy_score: float
    padding_uniformity: float = 0.0
    direction_ratio: float = 0.5
    size_histogram: List[SizeBin] = Field(default_factory=list)
    iscx_features: List[float] = Field(default_factory=list)
    anomaly_flags: List[str] = Field(default_factory=list)


class TrafficPrediction(BaseModel):
    flow_id: str
    predicted_category: TrafficCategory
    confidence_score: float
    inferred_mode: OperatingMode
    mode_confidence: float
    top_contributing_features: Dict[str, float] = Field(default_factory=dict)
    shap_explanations: Dict[str, float] = Field(default_factory=dict)
    class_probabilities: Dict[str, float] = Field(default_factory=dict)
    anomaly_score: float = 0.0
    iscx_secondary_prediction: Optional[str] = None
    anomaly_flags: List[str] = Field(default_factory=list)


class RemediationConfig(BaseModel):
    platform: str  # StrongSwan, Cisco_IOS, VyOS
    config_snippet: str
    description: str
    addressed_issues: List[str] = Field(default_factory=list)


class SecurityScoreBreakdown(BaseModel):
    overall_score: int = Field(ge=0, le=100)
    risk_level: SeverityLevel
    cryptographic_score: int = Field(ge=0, le=100)
    key_exchange_score: int = Field(ge=0, le=100)
    operational_hygiene_score: int = Field(ge=0, le=100)
    quantum_readiness_score: int = Field(ge=0, le=100)
    traffic_exposure_score: int = Field(ge=0, le=100)


class AnalysisSessionResult(BaseModel):
    session_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pcap_filename: str
    file_size_bytes: int
    total_packets_parsed: int
    ike_packets_count: int
    esp_packets_count: int
    ah_packets_count: int = 0
    ike_timeline: List[IKEPacketSummary] = Field(default_factory=list)
    security_association: SecurityAssociation
    compliance_findings: List[ComplianceFinding] = Field(default_factory=list)
    threat_matrix: List[ThreatItem] = Field(default_factory=list)
    esp_flows: List[ESPFlowStatistics] = Field(default_factory=list)
    traffic_predictions: List[TrafficPrediction] = Field(default_factory=list)
    score_breakdown: SecurityScoreBreakdown
    remediation_configs: List[RemediationConfig] = Field(default_factory=list)


class SessionSummary(BaseModel):
    session_id: str
    timestamp: datetime
    pcap_filename: str
    overall_score: int
    risk_level: SeverityLevel
    ike_version: str
    encryption_algorithm: str
    mode: str
    total_packets_parsed: int
    threat_count: int


class ActiveScanRequest(BaseModel):
    target_host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=500, ge=1, le=65535)
    timeout_seconds: float = Field(default=1.5, ge=0.2, le=5.0)


class CipherProbeResult(BaseModel):
    suite_name: str
    ike_version: str
    encryption: str
    integrity: str
    dh_group: str
    accepted: bool
    security_grade: SeverityLevel
    response_time_ms: float
    details: str


class ActiveScanResult(BaseModel):
    scan_id: str
    target_host: str
    port: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reachable: bool
    overall_grade: str
    summary: str
    probes: List[CipherProbeResult] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
