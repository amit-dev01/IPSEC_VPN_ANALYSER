import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { Brain, Activity, AlertOctagon } from 'lucide-react';

export function TrafficLabTab({ analysis }) {
  if (!analysis) return null;
  const { esp_flows, traffic_predictions } = analysis;
  const primaryFlow = esp_flows?.[0];
  const primaryPred = traffic_predictions?.[0];

  const probData = primaryPred?.class_probabilities
    ? Object.entries(primaryPred.class_probabilities)
        .map(([name, prob]) => ({ name: name.split(' ')[0], confidence: Math.round(prob * 100) }))
        .sort((a, b) => b.confidence - a.confidence)
    : [];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Packet Size Histogram (Visual proof of flow shape) */}
        <div className="glass-panel rounded-2xl p-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              ESP Packet Size Distribution (Bytes)
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              {primaryFlow ? `${primaryFlow.packet_count} packets` : 'No ESP stream'}
            </span>
          </div>
          {primaryFlow?.size_histogram?.length ? (
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={primaryFlow.size_histogram}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="bucket" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#06b6d4" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic py-12 text-center">No ESP flow histogram available.</p>
          )}
        </div>

        {/* AI 7-Class Confidence Distribution */}
        <div className="glass-panel rounded-2xl p-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Brain className="w-4 h-4 text-purple-400" />
              AI 7-Class Encrypted Traffic Probabilities
            </h3>
            <span className="text-[11px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
              Zero-Decryption ML
            </span>
          </div>

          {primaryPred ? (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-[11px] text-slate-400">Top Prediction</div>
                  <div className="text-base font-bold text-purple-300">{primaryPred.predicted_category}</div>
                </div>
                <div className="text-right">
                  <div className="text-lg font-black text-emerald-400">{Math.round(primaryPred.confidence_score * 100)}%</div>
                  <div className="text-[10px] text-slate-400">Mode: {primaryPred.inferred_mode} ({Math.round(primaryPred.mode_confidence * 100)}%)</div>
                </div>
              </div>

              <div className="space-y-2">
                {probData.map((row) => (
                  <div key={row.name} className="space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-300">{row.name}</span>
                      <span className="font-mono text-slate-400">{row.confidence}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-purple-500 to-cyan-400 rounded-full"
                        style={{ width: `${row.confidence}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic py-12 text-center">No ESP flows classified.</p>
          )}
        </div>
      </div>

      {/* Flow Telemetry & Anomaly Table */}
      <div className="glass-panel rounded-2xl p-6">
        <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-3 mb-4">
          Extracted ESP / AH Flow Telemetry & Covert Anomaly Flags
        </h3>
        {esp_flows.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No ESP/AH flows detected in trace.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 px-3">Flow / SPI</th>
                  <th className="py-2 px-3">Proto</th>
                  <th className="py-2 px-3">Pkts / Bytes</th>
                  <th className="py-2 px-3">Rate (pps / kbps)</th>
                  <th className="py-2 px-3">Size (Mean ± Std)</th>
                  <th className="py-2 px-3">IAT Mean</th>
                  <th className="py-2 px-3">Entropy</th>
                  <th className="py-2 px-3">Anomalies</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {esp_flows.map((f) => (
                  <tr key={f.flow_id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 font-mono text-cyan-300">{f.flow_id}</td>
                    <td className="py-2.5 px-3 font-semibold text-slate-200">{f.protocol}</td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {f.packet_count} / {(f.total_bytes / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {f.packet_rate_pps} / {(f.byte_rate_bps / 1000).toFixed(1)}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {f.mean_packet_size} ± {f.std_packet_size} B
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{f.iat_mean_ms} ms</td>
                    <td className="py-2.5 px-3 font-mono">
                      <span className={f.entropy_score >= 7.5 ? 'text-emerald-400' : 'text-rose-400'}>
                        {f.entropy_score}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      {f.anomaly_flags.length === 0 ? (
                        <span className="text-[10px] text-emerald-400">Normal</span>
                      ) : (
                        f.anomaly_flags.map((a) => (
                          <span key={a} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-bold">
                            <AlertOctagon className="w-3 h-3" /> {a}
                          </span>
                        ))
                      )}
                    </td>
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
