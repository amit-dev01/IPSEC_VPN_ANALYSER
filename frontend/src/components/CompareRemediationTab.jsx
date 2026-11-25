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
      <div className="glass-panel rounded-[28px] p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3.5">
          <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-[#a78b71]" />
            Session Comparison (Before vs. After Audit)
          </h3>
          <select
            value={compareId}
            onChange={(e) => handleCompareChange(e.target.value)}
            className="px-4 py-2 rounded-full bg-[#0a0a0a] border border-white/15 text-xs text-white focus:outline-none focus:border-[#c9b8a0]"
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
              <div key={item.session_id} className="p-5 rounded-[22px] bg-white/[0.02] border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-[0.2em] text-[#a78b71] font-semibold">{title}</span>
                  <span className="font-mono text-gray-400">{item.session_id}</span>
                </div>
                <div className="font-serif italic text-base text-white truncate">{item.pcap_filename}</div>
                <div className="grid grid-cols-3 gap-2 pt-2">
                  <div className="p-3 rounded-xl bg-black/50 border border-white/5 text-center">
                    <div className="text-[10px] text-gray-400">Score</div>
                    <div className="text-xl font-bold text-[#e8d5b7]">{item.score_breakdown.overall_score}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-black/50 border border-white/5 text-center">
                    <div className="text-[10px] text-gray-400">Threats</div>
                    <div className="text-xl font-bold text-[#f5a3ab]">{item.threat_matrix.length}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-black/50 border border-white/5 text-center">
                    <div className="text-[10px] text-gray-400">IKE / Mode</div>
                    <div className="text-xs font-bold text-[#c9b8a0] mt-1">
                      {item.security_association.ike_version} • {item.security_association.mode}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-400">
            Analyze multiple profiles (e.g., Vulnerable IKEv1 and Hardened IKEv2), then pick a baseline above to compare security posture side-by-side.
          </p>
        )}
      </div>

      {/* Context-Aware Remediation & Report Export */}
      <div className="glass-panel rounded-[28px] p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-white/10 pb-3.5">
          <div>
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <Wrench className="w-4 h-4 text-[#a78b71]" />
              Context-Aware Hardened Remediation
            </h3>
            <p className="text-xs text-gray-400 mt-1">{activeCfg?.description}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {configs.map((c, idx) => (
              <button
                key={c.platform}
                onClick={() => setPlatformIdx(idx)}
                className={`px-4 py-1.5 text-xs rounded-full font-medium transition ${
                  platformIdx === idx
                    ? 'bg-white text-black font-semibold'
                    : 'glass-panel text-gray-300 hover:text-[#e8d5b7]'
                }`}
              >
                {c.platform}
              </button>
            ))}
          </div>
        </div>

        {activeCfg?.addressed_issues?.length > 0 && (
          <div className="p-4 rounded-[20px] bg-[#a78b71]/10 border border-[#a78b71]/30 space-y-1">
            <div className="text-[10px] uppercase tracking-[0.18em] font-bold text-[#e8d5b7]">
              Targeted Issues Patched
            </div>
            {activeCfg.addressed_issues.map((issue, i) => (
              <div key={i} className="text-[11px] text-gray-200 font-mono">• {issue}</div>
            ))}
          </div>
        )}

        <div className="relative">
          <button
            onClick={handleCopy}
            className="absolute top-3 right-3 text-xs px-3.5 py-1.5 rounded-full bg-white/10 hover:bg-white hover:text-black text-white border border-white/15 flex items-center gap-1.5 transition"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy Config'}
          </button>
          <pre className="p-5 rounded-[22px] bg-[#050505] font-mono text-xs text-[#e8d5b7] overflow-x-auto max-h-80 border border-white/10">
            {activeCfg?.config_snippet}
          </pre>
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2.5 pt-3 border-t border-white/10">
          <button
            onClick={() => window.open(`/api/report/pdf/${analysis.session_id}`, '_blank')}
            className="px-5 py-2.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-bold flex items-center gap-2 transition"
          >
            <FileDown className="w-4 h-4" /> Download Executive PDF
          </button>
          <button
            onClick={() => window.open(`/api/report/markdown/${analysis.session_id}`, '_blank')}
            className="px-4 py-2.5 rounded-full glass-panel hover:border-[#a78b71]/50 text-white text-xs font-semibold flex items-center gap-2 transition"
          >
            <FileText className="w-4 h-4 text-[#c9b8a0]" /> Technical Markdown
          </button>
          <button
            onClick={() => window.open(`/api/report/json/${analysis.session_id}`, '_blank')}
            className="px-4 py-2.5 rounded-full glass-panel hover:border-[#a78b71]/50 text-white text-xs font-semibold flex items-center gap-2 transition"
          >
            <FileCode className="w-4 h-4 text-[#c9b8a0]" /> Export Raw JSON
          </button>
        </div>
      </div>
    </div>
  );
}
