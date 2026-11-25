import React from 'react';
import { Layers, ArrowRightLeft, Lock, AlertCircle, CheckCircle2 } from 'lucide-react';

export function ProtocolInspectorTab({ analysis }) {
  if (!analysis) return null;
  const { security_association: sa, ike_timeline } = analysis;

  return (
    <div className="space-y-6">
      {/* SA Telemetry Grid */}
      <div className="glass-panel rounded-[28px] p-6">
        <h3 className="font-serif italic text-lg text-white flex items-center gap-2 border-b border-white/10 pb-3.5 mb-4">
          <Lock className="w-4 h-4 text-[#a78b71]" />
          Security Association (SA) Deep Parameters
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-[20px] bg-white/[0.02] border border-white/10">
            <div className="text-[#a78b71] text-[10px] uppercase tracking-[0.18em]">Initiator SPI</div>
            <div className="font-mono text-[#e8d5b7] mt-1.5 truncate">{sa.initiator_spi}</div>
          </div>
          <div className="p-4 rounded-[20px] bg-white/[0.02] border border-white/10">
            <div className="text-[#a78b71] text-[10px] uppercase tracking-[0.18em]">Responder SPI</div>
            <div className="font-mono text-[#e8d5b7] mt-1.5 truncate">{sa.responder_spi || 'Pending / 0x0'}</div>
          </div>
          <div className="p-4 rounded-[20px] bg-white/[0.02] border border-white/10">
            <div className="text-[#a78b71] text-[10px] uppercase tracking-[0.18em]">Peer Endpoints ({sa.ip_version})</div>
            <div className="font-mono text-white mt-1.5 truncate">{sa.peer_ips.join(' ↔ ') || 'N/A'}</div>
          </div>
          <div className="p-4 rounded-[20px] bg-white/[0.02] border border-white/10">
            <div className="text-[#a78b71] text-[10px] uppercase tracking-[0.18em]">Replay &amp; ESN Status</div>
            <div className="mt-1.5 flex items-center gap-1.5">
              {sa.replay_anomalies_detected === 0 ? (
                <span className="text-[#e8d5b7] font-semibold">Protected ({sa.esn_enabled ? '64-bit ESN' : '32-bit Seq'})</span>
              ) : (
                <span className="text-[#f5a3ab] font-semibold">{sa.replay_anomalies_detected} Anomalies</span>
              )}
            </div>
          </div>
        </div>
        {sa.notify_messages && sa.notify_messages.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-[0.18em] text-gray-400">Notify Payloads:</span>
            {sa.notify_messages.map((n) => (
              <span key={n} className="px-3 py-1 rounded-full bg-[#a78b71]/15 border border-[#a78b71]/35 text-[#e8d5b7] font-mono text-[10px]">
                {n}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Offered Proposals & Transform Matrix */}
      <div className="glass-panel rounded-[28px] p-6">
        <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
          <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#a78b71]" />
            Negotiated &amp; Offered IKE Proposals (Downgrade Audit)
          </h3>
          {sa.downgrade_risk_detected ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#e05260]/15 text-[#f5a3ab] border border-[#e05260]/40 text-[10px] uppercase tracking-[0.15em] font-semibold">
              <AlertCircle className="w-3.5 h-3.5" /> Downgrade Risk Detected
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#a78b71]/15 text-[#e8d5b7] border border-[#a78b71]/40 text-[10px] uppercase tracking-[0.15em] font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" /> Clean Proposal Suite
            </span>
          )}
        </div>

        {sa.proposals_offered.length === 0 ? (
          <p className="text-xs text-gray-500 italic">No explicit SA proposal payloads observed in trace.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {sa.proposals_offered.map((prop, idx) => (
              <div
                key={`${prop.proposal_number}-${idx}`}
                className={`p-5 rounded-[22px] border space-y-3 ${
                  prop.has_weak_transform
                    ? 'bg-[#e05260]/[0.06] border-[#e05260]/40'
                    : 'bg-white/[0.02] border-white/10'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">
                    Proposal #{prop.proposal_number} ({prop.protocol_id})
                  </span>
                  {prop.has_weak_transform ? (
                    <span className="text-[10px] uppercase tracking-[0.14em] font-bold px-2.5 py-0.5 rounded-full bg-[#e05260]/20 text-[#f5a3ab]">
                      WEAK FALLBACK
                    </span>
                  ) : (
                    <span className="text-[10px] uppercase tracking-[0.14em] font-bold px-2.5 py-0.5 rounded-full bg-[#a78b71]/20 text-[#e8d5b7]">
                      HARDENED
                    </span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {prop.transforms.map((t, tIdx) => (
                    <div key={tIdx} className="flex items-center justify-between text-xs bg-black/40 border border-white/5 px-3 py-2 rounded-xl">
                      <span className="text-[#a78b71] font-mono">{t.transform_type}</span>
                      <span className="text-white font-medium">{t.transform_name}</span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          t.security_rating === 'SECURE'
                            ? 'bg-[#a78b71]/20 text-[#e8d5b7]'
                            : t.security_rating === 'INSECURE'
                            ? 'bg-[#e05260]/20 text-[#f5a3ab]'
                            : 'bg-white/10 text-[#c9b8a0]'
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
      <div className="glass-panel rounded-[28px] p-6">
        <h3 className="font-serif italic text-lg text-white flex items-center gap-2 border-b border-white/10 pb-3.5 mb-4">
          <ArrowRightLeft className="w-4 h-4 text-[#a78b71]" />
          IKE Packet Handshake Timeline ({ike_timeline.length} Packets)
        </h3>
        {ike_timeline.length === 0 ? (
          <p className="text-xs text-gray-500 italic">No IKE handshake packets found in trace (ESP-only capture).</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-[#a78b71] uppercase tracking-[0.18em] text-[10px]">
                  <th className="py-2.5 px-3">Pkt #</th>
                  <th className="py-2.5 px-3">Direction</th>
                  <th className="py-2.5 px-3">Role</th>
                  <th className="py-2.5 px-3">Version</th>
                  <th className="py-2.5 px-3">Exchange Type</th>
                  <th className="py-2.5 px-3">Payloads Chained</th>
                  <th className="py-2.5 px-3">Bytes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {ike_timeline.map((p) => (
                  <tr key={p.packet_index} className="hover:bg-white/[0.03] transition">
                    <td className="py-2.5 px-3 font-mono text-gray-400">#{p.packet_index}</td>
                    <td className="py-2.5 px-3 font-mono text-[#e8d5b7]">
                      {p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold ${
                          p.role === 'Initiator'
                            ? 'bg-white/10 text-white'
                            : 'bg-[#a78b71]/20 text-[#e8d5b7]'
                        }`}
                      >
                        {p.role}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-white">{p.ike_version}</td>
                    <td className="py-2.5 px-3 text-gray-200">{p.exchange_type}</td>
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {p.payloads.map((pl, i) => (
                          <span key={i} className="px-2 py-0.5 rounded-full bg-white/[0.05] border border-white/10 text-[10px] font-mono text-[#c9b8a0]">
                            {pl}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-gray-400">{p.length_bytes} B</td>
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
