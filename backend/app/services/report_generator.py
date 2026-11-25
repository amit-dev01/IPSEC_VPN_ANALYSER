"""
Multi-Tier Security Report Generator for IPsec VPN Framework.
Produces publication-grade Executive PDF reports (via ReportLab) and
exhaustive Technical Audit Reports (Markdown & JSON) with IKE timelines,
threat matrices, AI confidence breakdowns, and context-aware remediation.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.schemas.models import AnalysisSessionResult, ComplianceStatus


class ReportGenerator:
    """Generates Executive and Technical assessment reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()

    def generate_executive_pdf(self, result: AnalysisSessionResult, output_path: str) -> str:
        """Generates an executive-ready PDF report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=40, leftMargin=40,
            topMargin=40, bottomMargin=40
        )
        elements = []

        score = result.score_breakdown.overall_score
        if score >= 85:
            score_color = colors.HexColor("#10b981")
            badge_text = "LOW RISK (HARDENED)"
        elif score >= 65:
            score_color = colors.HexColor("#f59e0b")
            badge_text = "MODERATE RISK"
        elif score >= 45:
            score_color = colors.HexColor("#f97316")
            badge_text = "HIGH RISK"
        else:
            score_color = colors.HexColor("#ef4444")
            badge_text = "CRITICAL RISK"

        title_style = ParagraphStyle(
            'HeaderTitle',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a")
        )
        subtitle_style = ParagraphStyle(
            'HeaderSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b")
        )

        elements.append(Paragraph("IPsec VPN Security Assessment — Executive Report", title_style))
        elements.append(Paragraph(
            f"Generated {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} | Target: {result.pcap_filename} | IP: {result.security_association.ip_version}",
            subtitle_style
        ))
        elements.append(Spacer(1, 12))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#cbd5e1"), spaceAfter=14))

        kpi_data = [
            [
                Paragraph("<b>Overall Security Score</b>", self.styles['Normal']),
                Paragraph("<b>Risk Posture</b>", self.styles['Normal']),
                Paragraph("<b>IKE / IP Version</b>", self.styles['Normal']),
                Paragraph("<b>Operating Mode</b>", self.styles['Normal'])
            ],
            [
                Paragraph(f"<font size=18 color='{score_color.hexval()}'><b>{score} / 100</b></font>", self.styles['Normal']),
                Paragraph(f"<b>{badge_text}</b>", self.styles['Normal']),
                Paragraph(f"<b>{result.security_association.ike_version.value} ({result.security_association.ip_version})</b>", self.styles['Normal']),
                Paragraph(f"<b>{result.security_association.mode.value}</b>", self.styles['Normal'])
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[130, 150, 125, 125])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 18))

        elements.append(Paragraph("<b>1. Executive Summary & Posture Analysis</b>", self.styles['Heading2']))
        sa = result.security_association
        summary_text = (
            f"An automated deep protocol and encrypted flow assessment was conducted on <b>{result.pcap_filename}</b> "
            f"({result.total_packets_parsed} packets: {result.ike_packets_count} IKE, {result.esp_packets_count} ESP, {result.ah_packets_count} AH). "
            f"The session negotiates <b>{sa.encryption_algorithm}</b>, "
            f"<b>{sa.dh_group or 'Unknown DH'}</b>, integrity <b>{sa.integrity_algorithm or 'Combined AEAD'}</b>, "
            f"and PFS <b>{'Enabled' if sa.pfs_enabled else 'Disabled'}</b>. "
            f"Overall compliance against NIST SP 800-77 Rev 1 evaluated to <b>{score}/100</b>. "
        )
        if score < 65:
            summary_text += (
                "<font color='#dc2626'><b>Immediate remediation advised:</b> Critical cryptographic weaknesses, "
                "downgrade proposals, or missing forward secrecy expose session keys to compromise.</font>"
            )
        else:
            summary_text += "The configuration meets modern baseline cryptographic standards."
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 14))

        elements.append(Paragraph("<b>2. Key Compliance Findings (NIST SP 800-77 / RFC 8221 / CNSA 2.0)</b>", self.styles['Heading2']))
        findings_data = [[
            Paragraph("<b>Status</b>", self.styles['Normal']),
            Paragraph("<b>Rule & Title</b>", self.styles['Normal']),
            Paragraph("<b>Severity</b>", self.styles['Normal']),
            Paragraph("<b>Recommendation</b>", self.styles['Normal'])
        ]]
        for f in result.compliance_findings[:8]:
            st_color = "#10b981" if f.status == ComplianceStatus.PASS else "#ef4444" if f.status == ComplianceStatus.FAIL else "#f59e0b"
            findings_data.append([
                Paragraph(f"<font color='{st_color}'><b>{f.status.value}</b></font>", self.styles['Normal']),
                Paragraph(f"<b>{f.rule_id}</b><br/>{f.title}", self.styles['Normal']),
                Paragraph(f"{f.severity.value}", self.styles['Normal']),
                Paragraph(f"{f.recommended_value}", self.styles['Normal'])
            ])

        find_table = Table(findings_data, colWidths=[65, 180, 85, 200])
        find_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(find_table)
        elements.append(Spacer(1, 14))

        if result.traffic_predictions:
            elements.append(Paragraph("<b>3. AI-Powered Encrypted Traffic Intelligence</b>", self.styles['Heading2']))
            ai_data = [[
                Paragraph("<b>Flow SPI</b>", self.styles['Normal']),
                Paragraph("<b>Predicted Application</b>", self.styles['Normal']),
                Paragraph("<b>Confidence</b>", self.styles['Normal']),
                Paragraph("<b>Inferred Mode</b>", self.styles['Normal'])
            ]]
            for p in result.traffic_predictions[:5]:
                ai_data.append([
                    Paragraph(f"<code>{p.flow_id}</code>", self.styles['Normal']),
                    Paragraph(f"<b>{p.predicted_category.value}</b>", self.styles['Normal']),
                    Paragraph(f"{int(p.confidence_score * 100)}%", self.styles['Normal']),
                    Paragraph(f"{p.inferred_mode.value} ({int(p.mode_confidence * 100)}%)", self.styles['Normal'])
                ])
            ai_table = Table(ai_data, colWidths=[160, 160, 80, 130])
            ai_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(ai_table)
            elements.append(Spacer(1, 14))

        elements.append(Paragraph("<b>4. Priority Remediation Actions</b>", self.styles['Heading2']))
        if result.remediation_configs:
            for item in result.remediation_configs[0].addressed_issues[:5]:
                elements.append(Paragraph(f"• {item}", self.styles['Normal']))
                elements.append(Spacer(1, 4))

        doc.build(elements)
        return output_path

    def generate_technical_markdown(self, result: AnalysisSessionResult) -> str:
        """Generates exhaustive markdown technical documentation."""
        sa = result.security_association
        md = [
            f"# Technical Security Assessment Report: {result.pcap_filename}",
            f"**Session ID:** `{result.session_id}` | **Timestamp:** {result.timestamp.isoformat()}",
            "",
            "## 1. Executive Metrics & Cryptographic Parameters",
            f"- **Overall Security Score:** **{result.score_breakdown.overall_score} / 100** ({result.score_breakdown.risk_level.value})",
            f"- **Sub-scores:** Crypto `{result.score_breakdown.cryptographic_score}` | Key Exchange `{result.score_breakdown.key_exchange_score}` | Hygiene `{result.score_breakdown.operational_hygiene_score}` | PQC `{result.score_breakdown.quantum_readiness_score}` | Exposure `{result.score_breakdown.traffic_exposure_score}`",
            f"- **IKE / IP Version:** `{sa.ike_version.value}` over `{sa.ip_version}`",
            f"- **Peer Endpoints:** `{', '.join(sa.peer_ips) or 'N/A'}`",
            f"- **Encryption Algorithm:** `{sa.encryption_algorithm}`",
            f"- **Integrity / PRF:** `{sa.integrity_algorithm or 'Combined AEAD'}` / `{sa.prf_algorithm or 'Standard'}`",
            f"- **Diffie-Hellman Group:** `{sa.dh_group}` (Status: `{sa.dh_status.value}`)",
            f"- **Operating Mode:** `{sa.mode.value}` | **PFS:** `{'ENABLED' if sa.pfs_enabled else 'DISABLED'}` | **ESN:** `{'ENABLED' if sa.esn_enabled else 'DISABLED'}`",
            f"- **NAT-Traversal:** `{'Detected (UDP 4500)' if sa.nat_traversal_detected else 'Direct IP'}` | **Replay Anomalies:** `{sa.replay_anomalies_detected}`",
            "",
            "## 2. IKE Handshake Timeline & Proposals Offered",
        ]
        if result.ike_timeline:
            md.append("| Pkt # | Source -> Destination | Version | Exchange | Role | Payloads |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for pkt in result.ike_timeline:
                md.append(f"| {pkt.packet_index} | `{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}` | {pkt.ike_version} | {pkt.exchange_type} | {pkt.role} | {', '.join(pkt.payloads)} |")
        else:
            md.append("*No cleartext IKE handshake packets captured in trace.*")
        md.append("")

        if sa.proposals_offered:
            md.append("### Offered Proposals & Transform Security")
            for prop in sa.proposals_offered:
                transforms = ", ".join(f"{t.transform_type}:{t.transform_name} [{t.security_rating}]" for t in prop.transforms)
                flag = " **(DOWNGRADE RISK)**" if prop.has_weak_transform else ""
                md.append(f"- **Proposal #{prop.proposal_number} ({prop.protocol_id}):** {transforms}{flag}")
            md.append("")

        md.append("## 3. Threat Matrix (CVSS & MITRE ATT&CK)")
        if result.threat_matrix:
            md.append("| Threat ID | Vulnerability / Attack | Severity | CVSS | MITRE Technique | Impact |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for t in result.threat_matrix:
                md.append(f"| `{t.threat_id}` | **{t.title}** | {t.severity.value} | {t.cvss_score} | `{t.mitre_technique_id or 'N/A'}` | {t.impact} |")
        else:
            md.append("*No critical threats identified for this configuration.*")
        md.append("")

        md.append("## 4. Compliance Findings (NIST SP 800-77 / RFC 8221 / CNSA 2.0)")
        md.append("| Standard | Rule ID | Title | Status | Severity | Current Value | Recommended Value |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in result.compliance_findings:
            md.append(f"| {f.standard} | `{f.rule_id}` | {f.title} | **{f.status.value}** | {f.severity.value} | `{f.current_value}` | `{f.recommended_value}` |")
        md.append("")

        md.append("## 5. AI-Powered Encrypted ESP/AH Flow Inference")
        if result.traffic_predictions:
            md.append("| Flow ID / SPI | Predicted Traffic Class | AI Confidence | Inferred Mode | Anomalies | Key Flow Indicators |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for p in result.traffic_predictions:
                features_str = ", ".join(f"{k}: {v}" for k, v in p.top_contributing_features.items())
                anom = ", ".join(p.anomaly_flags) if p.anomaly_flags else "None"
                md.append(f"| `{p.flow_id}` | **{p.predicted_category.value}** | {int(p.confidence_score * 100)}% | {p.inferred_mode.value} | {anom} | {features_str} |")
        else:
            md.append("*No ESP/AH flows present in capture.*")
        md.append("")

        md.append("## 6. Automated Hardened Configuration Snippets")
        for r in result.remediation_configs:
            md.append(f"### {r.platform}")
            md.append(f"*{r.description}*")
            md.append(f"```text\n{r.config_snippet}\n```\n")

        return "\n".join(md)
