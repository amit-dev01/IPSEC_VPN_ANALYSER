import React from 'react';
import { Layers, ArrowRightLeft, Lock, AlertCircle, CheckCircle2 } from 'lucide-react';

export function ProtocolInspectorTab({ analysis }) {
  if (!analysis) return null;
  const { security_association: sa, ike_timeline } = analysis;

  return (
    <div className="space-y-6">
      {/* SA Telemetry Grid */}
      <div className="glass-panel rounded-2xl p-6">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
          <Lock className="w-4 h-4 text-cyan-400" />
          Security Association (SA) Deep Parameters
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Initiator SPI</div>
            <div className="font-mono text-cyan-300 mt-1 truncate">{sa.initiator_spi}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Responder SPI</div>
            <div className="font-mono text-cyan-300 mt-1 truncate">{sa.responder_spi || 'Pending / 0x0'}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Peer Endpoints ({sa.ip_version})</div>
            <div className="font-mono text-slate-200 mt-1 truncate">{sa.peer_ips.join(' ↔ ') || 'N/A'}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Replay & ESN Status</div>
            <div className="mt-1 flex items-center gap-1.5">
              {sa.replay_anomalies_detected === 0 ? (
                <span className="text-emerald-400 font-semibold">Protected ({sa.esn_enabled ? '64-bit ESN' : '32-bit Seq'})</span>
              ) : (
                <span className="text-rose-400 font-semibold">{sa.replay_anomalies_detected} Anomalies</span>
              )}
            </div>
          </div>
        </div>
        {sa.notify_messages && sa.notify_messages.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-slate-400">Notify Payloads Observed:</span>
            {sa.notify_messages.map((n) => (
              <span key={n} className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-[10px]">
                {n}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Offered Proposals & Transform Matrix */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-purple-400" />
            Negotiated & Offered IKE Proposals (Downgrade Audit)
          </h3>
          {sa.downgrade_risk_detected ? (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[11px] font-semibold">
              <AlertCircle className="w-3.5 h-3.5" /> Downgrade Risk Detected
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" /> Clean Proposal Suite
            </span>
          )}
        </div>

        {sa.proposals_offered.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No explicit SA proposal payloads observed in trace.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {sa.proposals_offered.map((prop, idx) => (
              <div
                key={`${prop.proposal_number}-${idx}`}
                className={`p-4 rounded-xl border space-y-2.5 ${
                  prop.has_weak_transform
                    ? 'bg-rose-950/15 border-rose-800/50'
                    : 'bg-slate-900/70 border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">
                    Proposal #{prop.proposal_number} ({prop.protocol_id})
                  </span>
                  {prop.has_weak_transform ? (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">WEAK FALLBACK</span>
                  ) : (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">HARDENED</span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {prop.transforms.map((t, tIdx) => (
                    <div key={tIdx} className="flex items-center justify-between text-xs bg-slate-950/60 px-2.5 py-1.5 rounded-lg">
                      <span className="text-slate-400 font-mono">{t.transform_type}</span>
                      <span className="text-slate-200 font-medium">{t.transform_name}</span>
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          t.security_rating === 'SECURE'
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : t.security_rating === 'INSECURE'
                            ? 'bg-rose-500/15 text-rose-400'
                            : 'bg-amber-500/15 text-amber-400'
                        }`}
                      >
                        {t.security_rating}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* IKE Exchange Timeline */}
      <div className="glass-panel rounded-2xl p-6">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
          <ArrowRightLeft className="w-4 h-4 text-emerald-400" />
          IKE Packet Handshake Timeline ({ike_timeline.length} Packets)
        </h3>
        {ike_timeline.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No IKE handshake packets found in trace (ESP-only capture).</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 px-3">Pkt #</th>
                  <th className="py-2 px-3">Direction</th>
                  <th className="py-2 px-3">Role</th>
                  <th className="py-2 px-3">Version</th>
                  <th className="py-2 px-3">Exchange Type</th>
                  <th className="py-2 px-3">Payloads Chained</th>
                  <th className="py-2 px-3">Bytes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {ike_timeline.map((p) => (
                  <tr key={p.packet_index} className="hover:bg-slate-800/40">
                    <td className="py-2 px-3 font-mono text-slate-400">#{p.packet_index}</td>
                    <td className="py-2 px-3 font-mono text-cyan-300">
                      {p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${p.role === 'Initiator' ? 'bg-blue-500/15 text-blue-300' : 'bg-purple-500/15 text-purple-300'}`}>
                        {p.role}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-semibold text-white">{p.ike_version}</td>
                    <td className="py-2 px-3 text-slate-200">{p.exchange_type}</td>
                    <td className="py-2 px-3">
                      <div className="flex flex-wrap gap-1">
                        {p.payloads.map((pl, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300">
                            {pl}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-400">{p.length_bytes} B</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
