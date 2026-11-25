"""
Comprehensive IPsec VPN Analysis Orchestrator Service.
Coordinates the Detailed IKE/ESP/AH Dissector, ESP Feature Extractor,
AI Classifier, Cryptographic Compliance Engine, Remediation Generator,
and SQLite Session Persistence.
"""

import os
import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone
from backend.app.schemas.models import (
    AnalysisSessionResult, OperatingMode, SessionSummary
)
from backend.app.services.ike_dissector import IKEDissector
from backend.app.services.compliance_engine import CryptographicComplianceEngine
from backend.app.services.esp_feature_extractor import ESPFeatureExtractor
from backend.app.services.classifier import IPsecTrafficClassifier
from backend.app.services.remediation_generator import RemediationGenerator
from backend.app.services.session_store import SessionStore


class IPsecAnalyzerService:
    """Master orchestrator for IPsec packet analysis and security assessment."""

    def __init__(self, db_path: Optional[str] = None):
        self.dissector = IKEDissector()
        self.compliance_engine = CryptographicComplianceEngine()
        self.feature_extractor = ESPFeatureExtractor()
        self.classifier = IPsecTrafficClassifier()
        self.remediation_gen = RemediationGenerator()
        self.store = SessionStore(db_path=db_path)
        self.sessions: Dict[str, AnalysisSessionResult] = {}

    def analyze_pcap(self, pcap_path: str, filename: Optional[str] = None) -> AnalysisSessionResult:
        """Runs the complete analysis pipeline on a PCAP file."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        session_id = str(uuid.uuid4())[:8]
        display_name = filename or os.path.basename(pcap_path)
        file_size = os.path.getsize(pcap_path)

        # 1. Detailed Protocol Dissection (IKEv1/v2, ESP, AH, IPv6, Replay & Notify)
        dissected = self.dissector.parse_pcap_detailed(pcap_path)
        sa = dissected.sa

        # 2. Extract Encrypted ESP/AH Flows
        data_pkts = dissected.esp_packets + dissected.ah_packets
        esp_flows = self.feature_extractor.extract_flows(data_pkts)

        # 3. AI Traffic Classification & Mode Inference
        traffic_predictions = [self.classifier.predict_flow(flow) for flow in esp_flows]

        # Apply AI inferred mode when IKE handshake did not explicitly specify USE_TRANSPORT_MODE
        if sa.mode == OperatingMode.UNKNOWN:
            if traffic_predictions:
                sa.mode = traffic_predictions[0].inferred_mode
            elif data_pkts:
                sa.mode = OperatingMode.TUNNEL

        # 4. Cryptographic Compliance Evaluation (with flow entropy/metadata signals)
        findings = self.compliance_engine.evaluate_compliance(sa, esp_flows=esp_flows)

        # 5. Threat Matrix Generation (including covert AI anomaly vectors)
        threats = self.compliance_engine.generate_threat_matrix(findings, predictions=traffic_predictions)

        # 6. Composite Security Score (dynamic exposure + crypto + KE + PQC + hygiene)
        score_breakdown = self.compliance_engine.calculate_security_score(
            sa, findings, esp_flows=esp_flows, predictions=traffic_predictions
        )

        # 7. Context-Aware Remediation Configurations
        remediations = self.remediation_gen.generate_remediation_configs(sa, findings)

        # 8. Assemble & Persist Full Result
        result = AnalysisSessionResult(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            pcap_filename=display_name,
            file_size_bytes=file_size,
            total_packets_parsed=len(dissected.ike_packets) + len(dissected.esp_packets) + len(dissected.ah_packets),
            ike_packets_count=len(dissected.ike_packets),
            esp_packets_count=len(dissected.esp_packets),
            ah_packets_count=len(dissected.ah_packets),
            ike_timeline=dissected.ike_timeline,
            security_association=sa,
            compliance_findings=findings,
            threat_matrix=threats,
            esp_flows=esp_flows,
            traffic_predictions=traffic_predictions,
            score_breakdown=score_breakdown,
            remediation_configs=remediations,
        )

        self.sessions[session_id] = result
        self.store.save(result)
        return result

    def get_session(self, session_id: str) -> Optional[AnalysisSessionResult]:
        if session_id in self.sessions:
            return self.sessions[session_id]
        persisted = self.store.get(session_id)
        if persisted:
            self.sessions[session_id] = persisted
        return persisted

    def list_sessions(self, limit: int = 30) -> List[SessionSummary]:
        return self.store.list_summaries(limit=limit)

    def delete_session(self, session_id: str) -> bool:
        self.sessions.pop(session_id, None)
        return self.store.delete(session_id)
