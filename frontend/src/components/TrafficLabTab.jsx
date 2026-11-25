import React, { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, ReferenceLine
} from 'recharts';
import { Brain, Activity, AlertOctagon, Award, Sparkles, ShieldAlert } from 'lucide-react';
import { fetchMlMetrics } from '../api';

export function TrafficLabTab({ analysis }) {
  const [mlMetrics, setMlMetrics] = useState(null);

  useEffect(() => {
    fetchMlMetrics().then(setMlMetrics).catch(() => {});
  }, []);

  if (!analysis) return null;
  const { esp_flows, traffic_predictions } = analysis;
  const primaryFlow = esp_flows?.[0];
  const primaryPred = traffic_predictions?.[0];

  const probData = primaryPred?.class_probabilities
    ? Object.entries(primaryPred.class_probabilities)
        .map(([name, prob]) => ({ name: name.split(' ')[0], confidence: Math.round(prob * 100) }))
        .sort((a, b) => b.confidence - a.confidence)
    : [];

  const shapData = primaryPred?.shap_explanations
    ? Object.entries(primaryPred.shap_explanations).map(([feature, val]) => ({
        feature: feature.replace('_packet_size', '_sz').replace('_ms', ''),
        shap: val,
      }))
    : [];

  const iscxBench = mlMetrics?.iscx_vpn2016_benchmark;
  const ipsecBench = mlMetrics?.ipsec_windowed_benchmark;
  const globalShap = (mlMetrics?.global_shap_importance || []).slice(0, 8);

  return (
    <div className="space-y-6">
      {/* Row 1: Packet Histogram + Per-Flow SHAP Waterfall */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-[28px] p-6">
          <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#a78b71]" />
              ESP Packet Size Distribution
            </h3>
            <span className="text-[10px] uppercase tracking-[0.18em] font-mono text-[#c9b8a0]">
              {primaryFlow ? `${primaryFlow.packet_count} packets` : 'No ESP stream'}
            </span>
          </div>
          {primaryFlow?.size_histogram?.length ? (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={primaryFlow.size_histogram}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="bucket" tick={{ fill: '#c9b8a0', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0a0a',
                      borderColor: 'rgba(167,139,113,0.4)',
                      borderRadius: '12px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" fill="#a78b71" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-xs text-gray-500 italic py-12 text-center">No ESP flow histogram available.</p>
          )}
        </div>

        {/* True Per-Flow SHAP Impact Chart */}
        <div className="glass-panel rounded-[28px] p-6">
          <div className="flex items-center justify-between border-b border-white/10 pb-3.5 mb-4">
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#e8d5b7]" />
              Per-Flow SHAP Feature Attribution
            </h3>
            <span className="text-[10px] uppercase tracking-[0.16em] font-mono px-2.5 py-0.5 rounded-full bg-[#a78b71]/15 text-[#e8d5b7] border border-[#a78b71]/30">
              TreeExplainer
            </span>
          </div>
          {shapData.length > 0 ? (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={shapData} layout="vertical" margin={{ left: 20, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                  <YAxis type="category" dataKey="feature" width={95} tick={{ fill: '#e8d5b7', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0a0a',
                      borderColor: 'rgba(167,139,113,0.4)',
                      borderRadius: '12px',
                      fontSize: '12px',
                    }}
                  />
                  <ReferenceLine x={0} stroke="rgba(255,255,255,0.25)" />
                  <Bar dataKey="shap" radius={[4, 4, 4, 4]}>
                    {shapData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.shap >= 0 ? '#c9b8a0' : '#e05260'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-xs text-gray-500 italic py-12 text-center">No SHAP attributions available.</p>
          )}
        </div>
      </div>

      {/* Row 2: LightGBM 7-Class Prediction, IsolationForest Anomaly & ISCX Cross-Check */}
      <div className="glass-panel rounded-[28px] p-6">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5 mb-5">
          <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
            <Brain className="w-4 h-4 text-[#a78b71]" />
            LightGBM 7-Class Prediction &amp; Zero-Day Outlier Scoring
          </h3>
          {primaryPred?.iscx_secondary_prediction && (
            <span className="text-[11px] font-mono px-3 py-1 rounded-full bg-[#a78b71]/15 text-[#e8d5b7] border border-[#a78b71]/35">
              UNB ISCX-VPN2016 Cross-Check: <strong>{primaryPred.iscx_secondary_prediction}</strong>
            </span>
          )}
        </div>

        {primaryPred ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <div className="p-5 rounded-[22px] bg-white/[0.02] border border-white/10 space-y-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-[#a78b71]">Predicted Encapsulated App</div>
                <div className="font-serif italic text-xl text-white">{primaryPred.predicted_category}</div>
                <div className="flex items-center justify-between text-xs pt-2 border-t border-white/10">
                  <span className="text-[#e8d5b7] font-bold">{Math.round(primaryPred.confidence_score * 100)}% Confidence</span>
                  <span className="text-gray-300">Mode: <strong>{primaryPred.inferred_mode}</strong> ({Math.round(primaryPred.mode_confidence * 100)}%)</span>
                </div>
              </div>

              <div className="p-5 rounded-[22px] bg-white/[0.02] border border-white/10 space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-300 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#a78b71]" />
                    IsolationForest Anomaly Score
                  </span>
                  <span className={`font-mono font-bold ${primaryPred.anomaly_score >= 0.7 ? 'text-[#f5a3ab]' : 'text-[#e8d5b7]'}`}>
                    {Math.round((primaryPred.anomaly_score || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${primaryPred.anomaly_score >= 0.7 ? 'bg-[#e05260]' : 'bg-gradient-to-r from-[#a78b71] to-[#e8d5b7]'}`}
                    style={{ width: `${Math.round((primaryPred.anomaly_score || 0) * 100)}%` }}
                  />
                </div>
                <div className="text-[11px] text-gray-400">
                  Unsupervised outlier detector trained on baseline ESP flow geometry.
                </div>
              </div>
            </div>

            <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-3 content-start">
              {probData.map((row) => (
                <div key={row.name} className="p-3.5 rounded-[18px] bg-white/[0.02] border border-white/10 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-white font-medium">{row.name}</span>
                    <span className="font-mono text-[#e8d5b7] font-bold">{row.confidence}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-[#a78b71] to-[#e8d5b7] rounded-full"
                      style={{ width: `${row.confidence}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-xs text-gray-500 italic py-6 text-center">No ESP flows classified.</p>
        )}
      </div>

      {/* Row 3: Real-World UNB ISCX-VPN2016 Benchmark & Confusion Matrix */}
      {mlMetrics?.available && iscxBench?.leaderboard && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="glass-panel rounded-[28px] p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3.5">
              <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
                <Award className="w-4 h-4 text-[#c9b8a0]" />
                5-Fold CV Benchmark: UNB ISCX-VPN2016 ({iscxBench.total_samples.toLocaleString()} Flows)
              </h3>
              <span className="text-[10px] uppercase tracking-[0.16em] font-mono px-2.5 py-0.5 rounded-full bg-[#a78b71]/20 text-[#e8d5b7]">
                Best: {iscxBench.best_model}
              </span>
            </div>

            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={iscxBench.leaderboard}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="model" tick={{ fill: '#e8d5b7', fontSize: 11 }} />
                  <YAxis domain={[50, 100]} tick={{ fill: '#9ca3af', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0a0a',
                      borderColor: 'rgba(167,139,113,0.4)',
                      borderRadius: '12px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="cv_accuracy" name="5-Fold Accuracy %" fill="#e8d5b7" radius={[6, 6, 0, 0]} />
                  <Bar dataKey="macro_f1" name="Macro F1 %" fill="#a78b71" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-[#a78b71] text-[10px] uppercase tracking-[0.16em]">
                    <th className="py-2 px-2">Architecture</th>
                    <th className="py-2 px-2">CV Acc</th>
                    <th className="py-2 px-2">Macro F1</th>
                    <th className="py-2 px-2">IPsec Window Acc</th>
                    <th className="py-2 px-2">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {iscxBench.leaderboard.map((row) => {
                    const ipRow = ipsecBench?.leaderboard?.find((x) => x.model === row.model);
                    return (
                      <tr key={row.model}>
                        <td className="py-2 px-2 font-sans font-semibold text-white">{row.model}</td>
                        <td className="py-2 px-2 text-[#e8d5b7]">{row.cv_accuracy}%</td>
                        <td className="py-2 px-2 text-[#c9b8a0]">{row.macro_f1}%</td>
                        <td className="py-2 px-2 text-white">{ipRow ? `${ipRow.cv_accuracy}%` : '--'}</td>
                        <td className="py-2 px-2 text-gray-400">{row.cv_time_sec}s</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* 7x7 UNB ISCX-VPN2016 Confusion Matrix + Global SHAP */}
          <div className="glass-panel rounded-[28px] p-6 space-y-4">
            <h3 className="font-serif italic text-lg text-white border-b border-white/10 pb-3.5">
              UNB ISCX-VPN2016 Confusion Matrix ({iscxBench.best_model})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-center text-[10px] font-mono">
                <thead>
                  <tr>
                    <th className="p-1 text-left text-[#a78b71]">True \ Pred</th>
                    {iscxBench.class_names.map((c) => (
                      <th key={c} className="p-1 text-gray-300">{c.replace('VPN-', '')}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {iscxBench.confusion_matrix.map((row, rIdx) => {
                    const rowSum = row.reduce((a, b) => a + b, 0) || 1;
                    return (
                      <tr key={rIdx}>
                        <td className="p-1 text-left font-bold text-[#c9b8a0]">
                          {iscxBench.class_names[rIdx]?.replace('VPN-', '')}
                        </td>
                        {row.map((val, cIdx) => {
                          const intensity = val / rowSum;
                          const bg =
                            rIdx === cIdx
                              ? `rgba(167, 139, 113, ${Math.max(0.2, intensity * 0.78)})`
                              : val > 0
                              ? `rgba(224, 82, 96, ${Math.min(0.55, intensity * 2.5)})`
                              : 'rgba(255, 255, 255, 0.02)';
                          return (
                            <td
                              key={cIdx}
                              style={{ backgroundColor: bg }}
                              className="p-1.5 border border-white/10 text-white rounded-sm"
                            >
                              {val}
                            </td>
                          );
                        })}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {globalShap.length > 0 && (
              <div className="pt-3 border-t border-white/10">
                <div className="text-[10px] uppercase tracking-[0.18em] text-[#a78b71] mb-2">
                  Top Global SHAP Features (Mean |SHAP| across {ipsecBench?.total_samples} Flows)
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {globalShap.map((item) => (
                    <span
                      key={item.feature}
                      className="px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/10 text-[10px] font-mono text-gray-300"
                    >
                      {item.feature}: <strong className="text-[#e8d5b7]">{item.mean_abs_shap}</strong>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Row 4: Extracted ESP / AH Flow Telemetry Table */}
      <div className="glass-panel rounded-[28px] p-6">
        <h3 className="font-serif italic text-lg text-white border-b border-white/10 pb-3.5 mb-4">
          Extracted ESP / AH Flow Telemetry &amp; Covert Anomaly Flags
        </h3>
        {esp_flows.length === 0 ? (
          <p className="text-xs text-gray-500 italic">No ESP/AH flows detected in trace.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-[#a78b71] uppercase tracking-[0.16em] text-[10px]">
                  <th className="py-2.5 px-3">Flow / SPI</th>
                  <th className="py-2.5 px-3">Proto</th>
                  <th className="py-2.5 px-3">Pkts / Bytes</th>
                  <th className="py-2.5 px-3">Rate (pps / kbps)</th>
                  <th className="py-2.5 px-3">Size (Mean ± Std)</th>
                  <th className="py-2.5 px-3">IAT Mean</th>
                  <th className="py-2.5 px-3">Entropy</th>
                  <th className="py-2.5 px-3">Anomalies</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {esp_flows.map((f) => (
                  <tr key={f.flow_id} className="hover:bg-white/[0.03] transition">
                    <td className="py-3 px-3 font-mono text-[#e8d5b7]">{f.flow_id}</td>
                    <td className="py-3 px-3 font-semibold text-white">{f.protocol}</td>
                    <td className="py-3 px-3 font-mono text-gray-300">
                      {f.packet_count} / {(f.total_bytes / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-3 px-3 font-mono text-gray-300">
                      {f.packet_rate_pps} / {(f.byte_rate_bps / 1000).toFixed(1)}
                    </td>
                    <td className="py-3 px-3 font-mono text-gray-300">
                      {f.mean_packet_size} ± {f.std_packet_size} B
                    </td>
                    <td className="py-3 px-3 font-mono text-gray-300">{f.iat_mean_ms} ms</td>
                    <td className="py-3 px-3 font-mono">
                      <span className={f.entropy_score >= 7.5 ? 'text-[#e8d5b7]' : 'text-[#f5a3ab]'}>
                        {f.entropy_score}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      {f.anomaly_flags.length === 0 ? (
                        <span className="text-[10px] uppercase tracking-wider text-[#c9b8a0]">Normal</span>
                      ) : (
                        f.anomaly_flags.map((a) => (
                          <span key={a} className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-[#e05260]/20 text-[#f5a3ab] text-[10px] font-bold mr-1">
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
