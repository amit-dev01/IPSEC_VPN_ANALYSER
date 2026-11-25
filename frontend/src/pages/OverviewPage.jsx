import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../components/Layout';
import { OverviewTab } from '../components/OverviewTab';

export function OverviewPage({ analysis }) {
  const score = analysis?.score_breakdown?.overall_score ?? '--';
  const risk = analysis?.score_breakdown?.risk_level ?? 'READY';
  const findings = analysis?.compliance_findings || [];
  const failCount = findings.filter((f) => f.status === 'FAIL').length;
  const passCount = findings.filter((f) => f.status === 'PASS').length;
  const quantumStatus = analysis?.security_association?.dh_status === 'POST_QUANTUM' ? 'PQC Ready' : 'Quantum Exposed';

  return (
    <div className="space-y-8 reveal-enter">
      <PageHeader
        eyebrow="Posture & Compliance Workspace"
        title="Cryptographic"
        accent="Posture Overview"
        subtitle="Comprehensive NIST SP 800-77 compliance radar, MITRE ATT&CK threat mapping, and quantum-era key exchange scoring for the active capture."
        rightSlot={
          <>
            <Link
              to="/inspector"
              className="px-4 py-2 rounded-full border border-white/15 hover:border-[#a78b71] text-xs text-gray-200 hover:text-[#e8d5b7] transition"
            >
              IKE Handshake Details
            </Link>
            <Link
              to="/remediation"
              className="px-4 py-2 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition"
            >
              Remediation Patches <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </>
        }
      />

      {analysis && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="glass-panel rounded-[20px] p-5">
            <div className="text-[10px] uppercase tracking-[0.2em] text-gray-400">Overall Posture</div>
            <div className="text-3xl font-bold text-[#e8d5b7] mt-1">{score}/100</div>
            <div className="text-xs text-gray-400 mt-1">Risk Level: {risk}</div>
          </div>
          <div className="glass-panel rounded-[20px] p-5">
            <div className="text-[10px] uppercase tracking-[0.2em] text-gray-400">NIST SP 800-77 Audit</div>
            <div className="text-3xl font-bold text-white mt-1">{passCount}/{findings.length}</div>
            <div className={`text-xs mt-1 ${failCount > 0 ? 'text-[#f5a3ab]' : 'text-[#e8d5b7]'}`}>
              {failCount === 0 ? 'All checks passed' : `${failCount} control failures`}
            </div>
          </div>
          <div className="glass-panel rounded-[20px] p-5">
            <div className="text-[10px] uppercase tracking-[0.2em] text-gray-400">Packet Telemetry</div>
            <div className="text-3xl font-bold text-white mt-1">{analysis.total_packets_parsed}</div>
            <div className="text-xs text-gray-400 mt-1 font-mono">
              {analysis.ike_packets_count} IKE / {analysis.esp_packets_count} ESP
            </div>
          </div>
          <div className="glass-panel rounded-[20px] p-5">
            <div className="text-[10px] uppercase tracking-[0.2em] text-gray-400">Quantum Readiness</div>
            <div className="font-serif italic text-2xl text-[#c9b8a0] mt-1.5">{quantumStatus}</div>
            <div className="text-xs text-gray-400 mt-1">{analysis.security_association?.dh_group || 'No DH Group'}</div>
          </div>
        </div>
      )}

      <OverviewTab analysis={analysis} />
    </div>
  );
}
