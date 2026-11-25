import React from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, Tooltip
} from 'recharts';
import { ShieldAlert, CheckCircle2, AlertTriangle, XCircle, Cpu } from 'lucide-react';

export function OverviewTab({ analysis }) {
  if (!analysis) return null;
  const { score_breakdown, threat_matrix, compliance_findings, security_association } = analysis;

  const radarData = [
    { axis: 'Crypto Strength', score: score_breakdown.cryptographic_score },
    { axis: 'Key Exchange', score: score_breakdown.key_exchange_score },
    { axis: 'Hygiene', score: score_breakdown.operational_hygiene_score },
    { axis: 'PQC Readiness', score: score_breakdown.quantum_readiness_score },
    { axis: 'Exposure Defense', score: score_breakdown.traffic_exposure_score },
  ];

  const radarStroke = score_breakdown.overall_score >= 65 ? '#e8d5b7' : '#e05260';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dimensional Radar Chart */}
        <div className="glass-panel rounded-[28px] p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#a78b71]" />
              5-Axis Security Posture Radar
            </h3>
            <span className="text-[10px] uppercase tracking-[0.2em] font-mono px-2.5 py-1 rounded-full bg-[#a78b71]/15 text-[#e8d5b7] border border-[#a78b71]/30">
              {security_association.ip_version} • {security_association.ike_version}
            </span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="rgba(255,255,255,0.12)" />
                <PolarAngleAxis dataKey="axis" tick={{ fill: '#c9b8a0', fontSize: 11 }} />
                <Radar
                  name="Security Score"
                  dataKey="score"
                  stroke={radarStroke}
                  strokeWidth={2}
                  fill={radarStroke}
                  fillOpacity={0.22}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0a0a0a',
                    borderColor: 'rgba(167,139,113,0.4)',
                    borderRadius: '12px',
                    fontSize: '12px',
                    color: '#fff',
                  }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-5 gap-2 pt-3 border-t border-white/10 text-center">
            {radarData.map((d) => (
              <div key={d.axis} className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
                <div className="text-sm font-bold text-[#e8d5b7]">{d.score}</div>
                <div className="text-[10px] text-gray-400 truncate">{d.axis}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Matrix */}
        <div className="glass-panel rounded-[28px] p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#e05260]" />
              Threat Matrix &amp; MITRE ATT&amp;CK
            </h3>
            <span
              className={`text-[10px] uppercase tracking-[0.18em] font-semibold px-3 py-1 rounded-full border ${
                threat_matrix.length === 0
                  ? 'bg-[#a78b71]/15 text-[#e8d5b7] border-[#a78b71]/40'
                  : 'bg-[#e05260]/15 text-[#f5a3ab] border-[#e05260]/40'
              }`}
            >
              {threat_matrix.length === 0 ? '0 Active Threats' : `${threat_matrix.length} Threat(s) Flagged`}
            </span>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-80 pr-1">
            {threat_matrix.length === 0 ? (
              <div className="p-10 text-center text-gray-400 text-xs">
                <CheckCircle2 className="w-8 h-8 text-[#c9b8a0] mx-auto mb-2" />
                No critical CVEs, weak ciphers, downgrade fallbacks, or covert C2 anomalies detected.
              </div>
            ) : (
              threat_matrix.map((t) => (
                <div
                  key={t.threat_id}
                  className="p-4 rounded-[20px] bg-[#e05260]/[0.06] border border-[#e05260]/30 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-[#f5a3ab]">{t.title}</span>
                    <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-[#e05260]/20 text-white shrink-0">
                      CVSS {t.cvss_score} • {t.severity}
                    </span>
                  </div>
                  <p className="text-xs text-gray-300 leading-relaxed">{t.description}</p>
                  <div className="flex items-center justify-between text-[10px] text-gray-400 pt-1">
                    <span>
                      MITRE: <strong className="text-white">{t.mitre_technique_id || 'N/A'}</strong>
                    </span>
                    <span className="text-[#c9b8a0]">{t.impact}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Compliance Checklist Table */}
      <div className="glass-panel rounded-[28px] p-6">
        <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
          <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#c9b8a0]" />
            NIST SP 800-77 Rev 1, RFC 8221 &amp; CNSA 2.0 Compliance Matrix
          </h3>
          <span className="text-[11px] uppercase tracking-[0.2em] text-gray-400">
            {compliance_findings.length} Controls Audited
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-[#a78b71] uppercase tracking-[0.18em] text-[10px]">
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Standard &amp; Control</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Observed Parameter</th>
                <th className="py-3 px-3">Recommended Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {compliance_findings.map((f, idx) => (
                <tr key={`${f.rule_id}-${idx}`} className="hover:bg-white/[0.03] transition">
                  <td className="py-3 px-3">
                    {f.status === 'PASS' ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-[#a78b71]/15 text-[#e8d5b7] border border-[#a78b71]/40 font-bold text-[10px]">
                        <CheckCircle2 className="w-3 h-3" /> PASS
                      </span>
                    ) : f.status === 'FAIL' ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-[#e05260]/15 text-[#f5a3ab] border border-[#e05260]/40 font-bold text-[10px]">
                        <XCircle className="w-3 h-3" /> FAIL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-[#c9b8a0]/10 text-[#c9b8a0] border border-[#c9b8a0]/30 font-bold text-[10px]">
                        <AlertTriangle className="w-3 h-3" /> WARN
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    <div className="font-semibold text-white">{f.title}</div>
                    <div className="text-[10px] text-gray-400 font-mono">
                      {f.standard} • {f.rule_id}
                    </div>
                  </td>
                  <td className="py-3 px-3 text-gray-300 font-mono text-[11px]">{f.severity}</td>
                  <td className="py-3 px-3 font-mono text-gray-300">{f.current_value}</td>
                  <td className="py-3 px-3 text-[#e8d5b7]">{f.recommended_value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
