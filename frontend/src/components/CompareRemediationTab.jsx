import React, { useState } from 'react';
import { GitCompare, Wrench, Copy, Check, FileText, FileCode, FileDown } from 'lucide-react';
import { fetchSessionById } from '../api';

export function CompareRemediationTab({ analysis, sessions, onToast }) {
  const [platformIdx, setPlatformIdx] = useState(0);
  const [copied, setCopied] = useState(false);
  const [compareId, setCompareId] = useState('');
  const [compareData, setCompareData] = useState(null);

  if (!analysis) return null;
  const configs = analysis.remediation_configs || [];
  const activeCfg = configs[platformIdx] || configs[0];

  const handleCopy = () => {
    if (!activeCfg) return;
    navigator.clipboard.writeText(activeCfg.config_snippet);
    setCopied(true);
    onToast(`Copied ${activeCfg.platform} configuration!`, 'success');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCompareChange = async (sid) => {
    setCompareId(sid);
    if (!sid) {
      setCompareData(null);
      return;
    }
    try {
      const data = await fetchSessionById(sid);
      setCompareData(data);
    } catch {
      onToast('Could not load comparison session', 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Side-by-Side Comparison Card */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-cyan-400" />
            Session Comparison (Before vs. After Audit)
          </h3>
          <select
            value={compareId}
            onChange={(e) => handleCompareChange(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">Select historical session to compare...</option>
            {sessions
              .filter((s) => s.session_id !== analysis.session_id)
              .map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.pcap_filename} — Score {s.overall_score}/100 ({s.session_id})
                </option>
              ))}
          </select>
        </div>

        {compareData ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {[
              { title: 'Active Session', item: analysis },
              { title: 'Comparison Baseline', item: compareData },
            ].map(({ title, item }) => (
              <div key={item.session_id} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] uppercase text-slate-400 font-semibold">{title}</span>
                  <span className="font-mono text-slate-500">{item.session_id}</span>
                </div>
                <div className="text-sm font-bold text-white truncate">{item.pcap_filename}</div>
                <div className="grid grid-cols-3 gap-2 pt-2">
                  <div className="p-2 rounded bg-slate-950/80 text-center">
                    <div className="text-[10px] text-slate-400">Score</div>
                    <div className="text-lg font-black text-emerald-400">{item.score_breakdown.overall_score}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950/80 text-center">
                    <div className="text-[10px] text-slate-400">Threats</div>
                    <div className="text-lg font-black text-rose-400">{item.threat_matrix.length}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950/80 text-center">
                    <div className="text-[10px] text-slate-400">IKE / Mode</div>
                    <div className="text-xs font-bold text-cyan-300 mt-1">
                      {item.security_association.ike_version} • {item.security_association.mode}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-400">
            Analyze multiple samples (e.g., Vulnerable IKEv1 and Hardened IKEv2), then pick a baseline above to compare security scores side-by-side.
          </p>
        )}
      </div>

      {/* Context-Aware Remediation & Report Export */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Wrench className="w-4 h-4 text-amber-400" />
              Context-Aware Hardened Remediation Generator
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">{activeCfg?.description}</p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {configs.map((c, idx) => (
              <button
                key={c.platform}
                onClick={() => setPlatformIdx(idx)}
                className={`px-3 py-1.5 text-xs rounded-lg font-medium transition ${
                  platformIdx === idx
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                {c.platform}
              </button>
            ))}
          </div>
        </div>

        {activeCfg?.addressed_issues?.length > 0 && (
          <div className="p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 space-y-1">
            <div className="text-[11px] font-bold text-amber-300">Targeted Issues Patched:</div>
            {activeCfg.addressed_issues.map((issue, i) => (
              <div key={i} className="text-[11px] text-slate-300 font-mono">• {issue}</div>
            ))}
          </div>
        )}

        <div className="relative">
          <button
            onClick={handleCopy}
            className="absolute top-3 right-3 text-xs px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy Config'}
          </button>
          <pre className="p-4 rounded-xl bg-[#04070d] font-mono text-xs text-emerald-300 overflow-x-auto max-h-80 border border-slate-800">
            {activeCfg?.config_snippet}
          </pre>
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-800">
          <button
            onClick={() => window.open(`/api/report/pdf/${analysis.session_id}`, '_blank')}
            className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-2 transition"
          >
            <FileDown className="w-4 h-4" /> Download Executive PDF
          </button>
          <button
            onClick={() => window.open(`/api/report/markdown/${analysis.session_id}`, '_blank')}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-2 transition"
          >
            <FileText className="w-4 h-4" /> Export Technical Markdown
          </button>
          <button
            onClick={() => window.open(`/api/report/json/${analysis.session_id}`, '_blank')}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-2 transition"
          >
            <FileCode className="w-4 h-4" /> Export Raw JSON
          </button>
        </div>
      </div>
    </div>
  );
}
