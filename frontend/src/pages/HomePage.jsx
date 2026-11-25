import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight, Brain, Cpu, FlaskConical, Loader2,
  Lock, Radar, Terminal, Upload
} from 'lucide-react';

const CORE_PILLARS = [
  {
    icon: Lock,
    title: 'Deterministic IKEv1/v2',
    desc: 'Zero-hallucination RFC 7296 & 2409 byte dissection across ciphers, DH groups, ESN, NAT-T, and replay windows.',
    to: '/inspector',
    cta: 'Open Inspector',
  },
  {
    icon: Brain,
    title: '7-Class Encrypted ML',
    desc: 'LightGBM + TreeExplainer SHAP classifies VoIP, Video, Web, WhatsApp & Email inside opaque ESP tunnels.',
    to: '/traffic-lab',
    cta: 'Open Traffic Lab',
  },
  {
    icon: Radar,
    title: 'Active Gateway Probe',
    desc: 'Non-destructive UDP IKE_SA_INIT probing discovers weak accepted ciphers and downgrade risks on live endpoints.',
    to: '/scanner',
    cta: 'Open Scanner',
  },
  {
    icon: Terminal,
    title: 'Hardened Remediation',
    desc: 'Context-aware StrongSwan, Cisco IOS-XE & VyOS config patches paired with Executive PDF audit reports.',
    to: '/remediation',
    cta: 'Open Remediation',
  },
];

export function HomePage({
  analysis,
  samples,
  loading,
  onSelectSample,
  onUploadFile,
  onTriggerUpload,
}) {
  const [mouseTilt, setMouseTilt] = useState({ x: 0, y: 0 });
  const navigate = useNavigate();

  const handleHeroMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 10;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 10;
    setMouseTilt({ x, y });
  };

  const sa = analysis?.security_association;
  const score = analysis?.score_breakdown?.overall_score ?? '--';
  const risk = analysis?.score_breakdown?.risk_level ?? 'READY';
  const primaryPred = analysis?.traffic_predictions?.[0];
  const failCount = (analysis?.compliance_findings || []).filter((f) => f.status === 'FAIL').length;

  return (
    <div className="space-y-14">
      {/* Interactive Neural Hero Workbench */}
      <section
        onMouseMove={handleHeroMouseMove}
        className="relative reveal-enter space-y-8"
      >
        <div className="text-center max-w-4xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass-panel text-[10px] uppercase tracking-[0.25em] text-[#c9b8a0]">
            <Cpu className="w-3.5 h-3.5 text-[#a78b71]" />
            NIST SP 800-77 • SHAP Explainable AI • Active IKEv2 Probing
          </div>

          <h1
            className="font-serif italic font-semibold leading-[1.06] tracking-tight text-white"
            style={{ fontSize: 'clamp(2.35rem, 5.2vw, 4.3rem)' }}
          >
            Autonomous <span className="text-[#a78b71]">IPsec</span> Intelligence &amp;{' '}
            <span className="text-[#a78b71]">Cryptographic</span> Posture
          </h1>

          <p className="text-sm text-gray-400 max-w-2xl mx-auto leading-relaxed">
            Dissect IKEv1/IKEv2 handshakes deterministically, classify encrypted ESP payloads across 7 traffic classes without decryption, and auto-remediate weak tunnel configurations.
          </p>

          {/* Dual CTA Group */}
          <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
            <button
              onClick={onTriggerUpload}
              className="px-6 py-2.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold uppercase tracking-[0.12em] flex items-center gap-2 transition-all duration-300"
            >
              <Upload className="w-3.5 h-3.5" /> Upload .PCAP Trace
            </button>
            <button
              onClick={() => navigate('/scanner')}
              className="px-6 py-2.5 rounded-full border border-[#a78b71]/50 hover:border-[#e8d5b7] hover:bg-[#a78b71]/10 text-[#e8d5b7] text-xs font-semibold uppercase tracking-[0.12em] flex items-center gap-2 transition-all duration-300"
            >
              <Radar className="w-3.5 h-3.5" /> Probe Live Gateway
            </button>
          </div>
        </div>

        {/* Central 16:9 Neural Node + Satellite Media Cards + Bezier SVG Connections */}
        <div className="relative py-4">
          {/* Dynamic SVG Neural Connection Lines (Desktop) */}
          <svg
            className="hidden lg:block absolute inset-0 w-full h-full pointer-events-none z-0"
            viewBox="0 0 1200 420"
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id="goldBranchGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="10%" stopColor="#c9b8a0" stopOpacity="0.9" />
                <stop offset="90%" stopColor="#a78b71" stopOpacity="0.1" />
              </linearGradient>
              <linearGradient id="goldBranchRev" x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="10%" stopColor="#c9b8a0" stopOpacity="0.9" />
                <stop offset="90%" stopColor="#a78b71" stopOpacity="0.1" />
              </linearGradient>
            </defs>

            <path d="M 270 95 C 370 95, 360 205, 430 205" className="node-line" stroke="url(#goldBranchGrad)" />
            <path d="M 270 95 C 370 95, 360 205, 430 205" className="node-line-flow" stroke="#e8d5b7" />

            <path d="M 270 325 C 370 325, 360 215, 430 215" className="node-line" stroke="url(#goldBranchGrad)" />
            <path d="M 270 325 C 370 325, 360 215, 430 215" className="node-line-flow" stroke="#e8d5b7" />

            <path d="M 930 95 C 830 95, 840 205, 770 205" className="node-line" stroke="url(#goldBranchRev)" />
            <path d="M 930 95 C 830 95, 840 205, 770 205" className="node-line-flow" stroke="#e8d5b7" />

            <path d="M 930 325 C 830 325, 840 215, 770 215" className="node-line" stroke="url(#goldBranchRev)" />
            <path d="M 930 325 C 830 325, 840 215, 770 215" className="node-line-flow" stroke="#e8d5b7" />
          </svg>

          <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
            {/* Left Satellites */}
            <div
              className="lg:col-span-3 space-y-5 flex flex-col items-center lg:items-start"
              style={{ transform: `translate3d(${mouseTilt.x * 0.4}px, ${mouseTilt.y * 0.4}px, 0)` }}
            >
              <Link
                to="/inspector"
                className="satellite-card w-full max-w-[290px] p-5 block"
              >
                <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">
                  Node 01 • Handshake
                </div>
                <div className="font-serif italic text-lg text-white mt-1">
                  {sa ? `${sa.ike_version} / ${sa.ip_version}` : 'IKEv2 / IPv4'}
                </div>
                <div className="text-xs text-gray-400 mt-1 truncate">
                  {sa?.encryption_algorithm || 'AES-GCM-16-256'}
                </div>
                <div className="mt-3 pt-2.5 border-t border-white/10 flex justify-between text-[11px] text-[#c9b8a0]">
                  <span>{sa?.dh_group || 'Group 19'}</span>
                  <span>{sa?.nat_traversal_detected ? 'NAT-T 4500' : 'UDP 500'}</span>
                </div>
              </Link>

              <Link
                to="/traffic-lab"
                className="satellite-card w-full max-w-[290px] p-5 block"
              >
                <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">
                  Node 02 • Encrypted ML
                </div>
                <div className="font-serif italic text-lg text-white mt-1 truncate">
                  {primaryPred ? primaryPred.predicted_category.split('/')[0] : 'LightGBM + SHAP'}
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  {primaryPred
                    ? `${Math.round(primaryPred.confidence_score * 100)}% Confidence • Anomaly ${Math.round((primaryPred.anomaly_score || 0) * 100)}%`
                    : '7-Class Zero-Decryption'}
                </div>
                <div className="mt-3 pt-2.5 border-t border-white/10 flex justify-between text-[11px] text-[#c9b8a0]">
                  <span>Mode: {sa?.mode || 'TUNNEL'}</span>
                  <span>ISCX Verified</span>
                </div>
              </Link>
            </div>

            {/* Central 16:9 Interactive Telemetry & Drop Node */}
            <div className="lg:col-span-6">
              <div
                onClick={onTriggerUpload}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files?.[0]) onUploadFile(e.dataTransfer.files[0]);
                }}
                className="glass-panel central-glow rounded-[32px] aspect-video p-6 sm:p-8 flex flex-col justify-between cursor-pointer hover:border-[#a78b71]/50 relative overflow-hidden"
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <span className="text-[10px] uppercase tracking-[0.25em] text-[#c9b8a0]">
                      Active Telemetry Node
                    </span>
                    <div className="font-serif italic text-xl sm:text-2xl text-white mt-1 truncate max-w-[280px] sm:max-w-[360px]">
                      {analysis?.pcap_filename || 'Drop Packet Capture (.pcap)'}
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] uppercase tracking-[0.22em] text-gray-400">Posture Index</span>
                    <div className="flex items-baseline justify-end gap-1.5">
                      <span
                        className={`text-4xl sm:text-5xl font-bold tracking-tight ${
                          score >= 85
                            ? 'text-[#e8d5b7]'
                            : score >= 65
                            ? 'text-[#c9b8a0]'
                            : 'text-[#e05260]'
                        }`}
                      >
                        {score}
                      </span>
                      <span className="text-xs text-gray-400">/100</span>
                    </div>
                  </div>
                </div>

                <div className="my-auto py-3 flex flex-col items-center justify-center text-center border border-dashed border-white/15 rounded-[20px] bg-black/30 hover:border-[#a78b71]/60 transition-colors">
                  {loading ? (
                    <Loader2 className="w-7 h-7 text-[#c9b8a0] animate-spin mb-1.5" />
                  ) : (
                    <Upload className="w-6 h-6 text-[#a78b71] mb-1.5" />
                  )}
                  <div className="text-xs font-medium text-white">
                    {loading ? 'Dissecting Packets & Computing SHAP Values...' : 'Click or Drag & Drop .pcap / .pcapng'}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-0.5">
                    Wireshark • tcpdump • StrongSwan • Cisco IOS traces
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-white/10 text-[11px]">
                  <span className="text-gray-300">
                    Risk:{' '}
                    <strong className={risk === 'CRITICAL' || risk === 'HIGH' ? 'text-[#e05260]' : 'text-[#e8d5b7]'}>
                      {risk}
                    </strong>
                  </span>
                  <span className="text-gray-400 font-mono">
                    {analysis ? `${analysis.total_packets_parsed} pkts (${analysis.ike_packets_count} IKE / ${analysis.esp_packets_count} ESP)` : 'Awaiting capture'}
                  </span>
                </div>
              </div>
            </div>

            {/* Right Satellites */}
            <div
              className="lg:col-span-3 space-y-5 flex flex-col items-center lg:items-end"
              style={{ transform: `translate3d(${mouseTilt.x * -0.4}px, ${mouseTilt.y * -0.4}px, 0)` }}
            >
              <Link
                to="/overview"
                className="satellite-card w-full max-w-[290px] p-5 block"
              >
                <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">
                  Node 03 • Quantum &amp; PFS
                </div>
                <div className="font-serif italic text-lg text-white mt-1">
                  {sa?.pfs_enabled ? 'Forward Secrecy Active' : 'PFS Disabled'}
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  {sa?.dh_status === 'POST_QUANTUM' ? 'ML-KEM Hybrid Secure' : 'Classical DH — Q-Day Radar'}
                </div>
                <div className="mt-3 pt-2.5 border-t border-white/10 flex justify-between text-[11px] text-[#c9b8a0]">
                  <span>ESN: {sa?.esn_enabled ? '64-bit' : '32-bit'}</span>
                  <span>Anomalies: {sa?.replay_anomalies_detected ?? 0}</span>
                </div>
              </Link>

              <Link
                to="/remediation"
                className="satellite-card w-full max-w-[290px] p-5 block"
              >
                <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">
                  Node 04 • Compliance
                </div>
                <div className="font-serif italic text-lg text-white mt-1">
                  {failCount === 0 ? 'NIST SP 800-77 Clean' : `${failCount} Control Failures`}
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  StrongSwan • Cisco IOS-XE • VyOS Patches
                </div>
                <div className="mt-3 pt-2.5 border-t border-white/10 flex justify-between text-[11px] text-[#c9b8a0]">
                  <span>Downgrade: {sa?.downgrade_risk_detected ? 'FLAGGED' : 'Clean'}</span>
                  <span>Auto-Fix Ready</span>
                </div>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* 4-Column Core Architecture Features Grid */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {CORE_PILLARS.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.title}
              to={item.to}
              className="glass-panel glass-panel-hover rounded-[24px] p-6 group flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-2xl bg-[#a78b71]/10 border border-[#a78b71]/25 flex items-center justify-center mb-4 transition-transform duration-300 group-hover:scale-110">
                  <Icon className="w-5 h-5 text-[#c9b8a0]" />
                </div>
                <h3 className="font-bold text-[20px] text-white tracking-tight mb-2">{item.title}</h3>
                <p className="text-[14px] text-gray-400 leading-relaxed">{item.desc}</p>
              </div>
              <div className="mt-5 pt-3 border-t border-white/10 flex items-center justify-between text-[11px] uppercase tracking-[0.18em] text-[#c9b8a0] group-hover:text-[#e8d5b7]">
                <span>{item.cta}</span>
                <ArrowRight className="w-3.5 h-3.5 transition-transform duration-300 group-hover:translate-x-1" />
              </div>
            </Link>
          );
        })}
      </section>

      {/* Lab Testbed Permutations Strip */}
      <section className="glass-panel rounded-[28px] p-6 sm:p-7 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-serif italic text-xl text-white flex items-center gap-2">
              <FlaskConical className="w-5 h-5 text-[#a78b71]" />
              Laboratory Testbed Captures
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Select a scenario below to analyze its capture, then launch any dedicated inspection workspace page.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] uppercase tracking-[0.2em] text-[#c9b8a0] mr-2">
              {samples.length} Scenarios Loaded
            </span>
            {analysis && (
              <Link
                to="/overview"
                className="px-4 py-1.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-[11px] font-semibold uppercase tracking-[0.14em] flex items-center gap-1.5 transition"
              >
                Open Overview <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {samples.map((s) => {
            const isActive = analysis?.pcap_filename === s.filename;
            const isBad = s.badge === 'CRITICAL' || s.badge === 'HIGH';
            return (
              <button
                key={s.filename}
                onClick={() => onSelectSample(s.filename)}
                className={`text-left p-4 rounded-[20px] border transition-all duration-300 ${
                  isActive
                    ? 'bg-[#a78b71]/15 border-[#c9b8a0]/60 shadow-[0_0_40px_rgba(167,139,113,0.18)]'
                    : 'bg-white/[0.02] border-white/10 hover:border-[#a78b71]/40 hover:bg-white/[0.04]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-white truncate">{s.label}</span>
                  <span
                    className={`text-[9px] uppercase tracking-[0.16em] font-bold px-2 py-0.5 rounded-full border shrink-0 ${
                      isBad
                        ? 'bg-[#e05260]/15 text-[#f5a3ab] border-[#e05260]/40'
                        : 'bg-[#a78b71]/15 text-[#e8d5b7] border-[#a78b71]/40'
                    }`}
                  >
                    {s.badge}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1.5 truncate">{s.description}</p>
              </button>
            );
          })}
        </div>

        {analysis && (
          <div className="pt-2 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-gray-400">
              Active Capture: <strong className="font-mono text-white">{analysis.pcap_filename}</strong>
            </span>
            <div className="flex flex-wrap gap-2">
              <Link to="/overview" className="px-3.5 py-1.5 rounded-full glass-panel border border-white/15 hover:border-[#c9b8a0] text-[#e8d5b7] transition">
                Posture Overview
              </Link>
              <Link to="/inspector" className="px-3.5 py-1.5 rounded-full glass-panel border border-white/15 hover:border-[#c9b8a0] text-[#e8d5b7] transition">
                IKE Inspector
              </Link>
              <Link to="/traffic-lab" className="px-3.5 py-1.5 rounded-full glass-panel border border-white/15 hover:border-[#c9b8a0] text-[#e8d5b7] transition">
                AI Traffic Lab
              </Link>
              <Link to="/remediation" className="px-3.5 py-1.5 rounded-full glass-panel border border-white/15 hover:border-[#c9b8a0] text-[#e8d5b7] transition">
                Compare &amp; Fix
              </Link>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
