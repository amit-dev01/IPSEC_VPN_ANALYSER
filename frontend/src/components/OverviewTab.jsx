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

  const scoreColor =
    score_breakdown.overall_score >= 85
      ? '#10b981'
      : score_breakdown.overall_score >= 65
      ? '#f59e0b'
      : '#ef4444';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dimensional Radar Chart */}
        <div className="glass-panel rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" />
              5-Axis Security Posture Radar
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {security_association.ip_version} • {security_association.ike_version}
            </span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="axis" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Radar
                  name="Security Score"
                  dataKey="score"
                  stroke={scoreColor}
                  fill={scoreColor}
                  fillOpacity={0.25}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '12px' }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-5 gap-2 pt-2 border-t border-slate-800/80 text-center">
            {radarData.map((d) => (
              <div key={d.axis} className="p-1.5 rounded-lg bg-slate-900/60">
                <div className="text-xs font-bold text-white">{d.score}</div>
                <div className="text-[10px] text-slate-400 truncate">{d.axis}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Matrix */}
        <div className="glass-panel rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Threat Matrix & MITRE ATT&CK Vectors
            </h3>
            <span
              className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-full border ${
                threat_matrix.length === 0
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}
            >
              {threat_matrix.length === 0 ? '0 Active Threats' : `${threat_matrix.length} Threat(s) Flagged`}
            </span>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-80 pr-1">
            {threat_matrix.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                No critical CVEs, weak ciphers, downgrade fallbacks, or covert C2 anomalies detected.
              </div>
            ) : (
              threat_matrix.map((t) => (
                <div
                  key={t.threat_id}
                  className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/40 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-rose-400">{t.title}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-900/50 text-rose-200 shrink-0">
                      CVSS {t.cvss_score} • {t.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">{t.description}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                    <span>
                      MITRE: <strong className="text-slate-200">{t.mitre_technique_id || 'N/A'}</strong>
                    </span>
                    <span className="text-amber-400">{t.impact}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Compliance Checklist Table */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            NIST SP 800-77 Rev 1, RFC 8221 & CNSA 2.0 Compliance Matrix
          </h3>
          <span className="text-xs text-slate-400">{compliance_findings.length} rules evaluated</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Standard & Control</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Observed Parameter</th>
                <th className="py-2.5 px-3">Recommended Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {compliance_findings.map((f, idx) => (
                <tr key={`${f.rule_id}-${idx}`} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3">
                    {f.status === 'PASS' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold text-[10px]">
                        <CheckCircle2 className="w-3 h-3" /> PASS
                      </span>
                    ) : f.status === 'FAIL' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold text-[10px]">
                        <XCircle className="w-3 h-3" /> FAIL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold text-[10px]">
                        <AlertTriangle className="w-3 h-3" /> WARN
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="font-semibold text-slate-200">{f.title}</div>
                    <div className="text-[10px] text-slate-500 font-mono">
                      {f.standard} • {f.rule_id}
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px]">{f.severity}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{f.current_value}</td>
                  <td className="py-2.5 px-3 text-emerald-400">{f.recommended_value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
