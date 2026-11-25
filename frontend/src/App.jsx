import React, { useEffect, useState, useRef } from 'react';
import {
  Shield, Upload, FlaskConical, Activity, Radar, GitCompare,
  Layers, LayoutDashboard, FileDown, Loader2, ArrowRight,
  Lock, Brain, Cpu, Terminal, Github, BookOpen
} from 'lucide-react';
import {
  fetchHealth, fetchSamples, fetchTestbedStatus, analyzeSample,
  uploadPcap, fetchSessions
} from './api';
import { OverviewTab } from './components/OverviewTab';
import { ProtocolInspectorTab } from './components/ProtocolInspectorTab';
import { TrafficLabTab } from './components/TrafficLabTab';
import { ActiveScannerTab } from './components/ActiveScannerTab';
import { CompareRemediationTab } from './components/CompareRemediationTab';

const TABS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'protocol', label: 'IKE Inspector', icon: Layers },
  { id: 'traffic', label: 'AI Traffic Lab', icon: Activity },
  { id: 'scanner', label: 'Active Scanner', icon: Radar },
  { id: 'remediation', label: 'Remediation', icon: GitCompare },
];

const CORE_PILLARS = [
  {
    icon: Lock,
    title: 'Deterministic IKEv1/v2',
    desc: 'Zero-hallucination RFC 7296 & 2409 byte dissection across ciphers, DH groups, ESN, NAT-T, and replay windows.',
  },
  {
    icon: Brain,
    title: '7-Class Encrypted ML',
    desc: 'LightGBM + TreeExplainer SHAP classifies VoIP, Video, Web, WhatsApp & Email inside opaque ESP tunnels.',
  },
  {
    icon: Radar,
    title: 'Active Gateway Probe',
    desc: 'Non-destructive UDP IKE_SA_INIT probing discovers weak accepted ciphers and downgrade risks on live endpoints.',
  },
  {
    icon: Terminal,
    title: 'Hardened Remediation',
    desc: 'Context-aware StrongSwan, Cisco IOS-XE & VyOS config patches paired with Executive PDF audit reports.',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [samples, setSamples] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [testbedStatus, setTestbedStatus] = useState({ docker_running: false, containers: [] });
  const [health, setHealth] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [quickHost, setQuickHost] = useState('demo-vulnerable-gw');
  const [mouseTilt, setMouseTilt] = useState({ x: 0, y: 0 });
  const fileInputRef = useRef(null);
  const workspaceRef = useRef(null);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const refreshMetadata = async () => {
    try {
      const [h, s, tb, sess] = await Promise.all([
        fetchHealth(),
        fetchSamples(),
        fetchTestbedStatus(),
        fetchSessions(),
      ]);
      setHealth(h);
      setSamples(s);
      setTestbedStatus(tb);
      setSessions(sess);
      return s;
    } catch {
      showToast('Backend connection error', 'error');
      return [];
    }
  };

  useEffect(() => {
    refreshMetadata().then((loadedSamples) => {
      if (loadedSamples.length > 0) {
        const defaultSample =
          loadedSamples.find((x) => x.filename.includes('hardened_ikev2_tunnel_web')) || loadedSamples[0];
        handleSampleClick(defaultSample.filename);
      }
    });
  }, []);

  const handleSampleClick = async (filename) => {
    setLoading(true);
    try {
      const res = await analyzeSample(filename);
      setAnalysis(res);
      setSessions(await fetchSessions());
      showToast(`Analyzed ${filename}`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setLoading(true);
    try {
      const res = await uploadPcap(file);
      setAnalysis(res);
      setSessions(await fetchSessions());
      showToast(`Uploaded & analyzed ${file.name}`, 'success');
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleHeroMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 10;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 10;
    setMouseTilt({ x, y });
  };

  const jumpToTab = (tabId) => {
    setActiveTab(tabId);
    workspaceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const sa = analysis?.security_association;
  const score = analysis?.score_breakdown?.overall_score ?? '--';
  const risk = analysis?.score_breakdown?.risk_level ?? 'READY';
  const primaryPred = analysis?.traffic_predictions?.[0];
  const failCount = (analysis?.compliance_findings || []).filter((f) => f.status === 'FAIL').length;

  return (
    <div className="min-h-screen flex flex-col bg-dots text-white font-sans">
      {/* Toast Notification */}
      {toast && (
        <div
          className={`fixed bottom-6 right-6 z-50 px-5 py-3 rounded-full text-xs font-medium glass-panel shadow-2xl transition-all duration-300 ${
            toast.type === 'error'
              ? 'border-[#e05260]/60 text-[#f5a3ab]'
              : 'border-[#a78b71]/60 text-[#e8d5b7]'
          }`}
        >
          {toast.msg}
        </div>
      )}

      {/* Fixed Top Navigation */}
      <header className="fixed top-0 inset-x-0 z-40 h-16 px-6 lg:px-12 glass-panel border-x-0 border-t-0 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="font-serif italic font-bold text-xl tracking-tight text-white">
            IPsec <span className="text-[#a78b71]">Sentinel</span>
          </span>
          <span className="hidden sm:inline-block text-[10px] uppercase tracking-[0.22em] text-[#c9b8a0]/80 border-l border-white/15 pl-3">
            Neural Security Suite
          </span>
        </div>

        {/* Center-Aligned 11px Wide-Tracked Nav Links */}
        <nav className="hidden md:flex items-center gap-6">
          {TABS.map((t) => {
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => jumpToTab(t.id)}
                className={`text-[11px] uppercase tracking-[0.18em] font-medium transition-colors duration-300 ${
                  active ? 'text-[#e8d5b7]' : 'text-gray-400 hover:text-white'
                }`}
              >
                {t.label}
              </button>
            );
          })}
        </nav>

        {/* Live Notification Pill + White Pill CTA */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 rounded-full glass-panel border border-white/10">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[8px] font-bold text-green-400 tracking-widest">LIVE</span>
            <span className="text-[12px] text-white font-medium">
              {health ? (testbedStatus.docker_running ? 'Docker XFRM Active' : 'ISCX LightGBM Online') : 'Connecting'}
            </span>
          </div>

          {analysis ? (
            <button
              onClick={() => window.open(`/api/report/pdf/${analysis.session_id}`, '_blank')}
              className="px-4 py-1.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition-all duration-300"
            >
              <FileDown className="w-3.5 h-3.5" /> Executive PDF
            </button>
          ) : (
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-4 py-1.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold transition-all duration-300"
            >
              Analyze Trace
            </button>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 pt-24 pb-16 px-6 lg:px-12 max-w-[1380px] w-full mx-auto space-y-14">
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
                onClick={() => fileInputRef.current?.click()}
                className="px-6 py-2.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold uppercase tracking-[0.12em] flex items-center gap-2 transition-all duration-300"
              >
                <Upload className="w-3.5 h-3.5" /> Upload .PCAP Trace
              </button>
              <button
                onClick={() => jumpToTab('scanner')}
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

              {/* Left Top -> Center */}
              <path d="M 270 95 C 370 95, 360 205, 430 205" className="node-line" stroke="url(#goldBranchGrad)" />
              <path d="M 270 95 C 370 95, 360 205, 430 205" className="node-line-flow" stroke="#e8d5b7" />

              {/* Left Bottom -> Center */}
              <path d="M 270 325 C 370 325, 360 215, 430 215" className="node-line" stroke="url(#goldBranchGrad)" />
              <path d="M 270 325 C 370 325, 360 215, 430 215" className="node-line-flow" stroke="#e8d5b7" />

              {/* Right Top -> Center */}
              <path d="M 930 95 C 830 95, 840 205, 770 205" className="node-line" stroke="url(#goldBranchRev)" />
              <path d="M 930 95 C 830 95, 840 205, 770 205" className="node-line-flow" stroke="#e8d5b7" />

              {/* Right Bottom -> Center */}
              <path d="M 930 325 C 830 325, 840 215, 770 215" className="node-line" stroke="url(#goldBranchRev)" />
              <path d="M 930 325 C 830 325, 840 215, 770 215" className="node-line-flow" stroke="#e8d5b7" />
            </svg>

            <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
              {/* Left Satellites */}
              <div
                className="lg:col-span-3 space-y-5 flex flex-col items-center lg:items-start"
                style={{ transform: `translate3d(${mouseTilt.x * 0.4}px, ${mouseTilt.y * 0.4}px, 0)` }}
              >
                <div
                  onClick={() => jumpToTab('protocol')}
                  className="satellite-card w-full max-w-[290px] p-5 cursor-pointer"
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
                </div>

                <div
                  onClick={() => jumpToTab('traffic')}
                  className="satellite-card w-full max-w-[290px] p-5 cursor-pointer"
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
                </div>
              </div>

              {/* Central 16:9 Interactive Telemetry & Drop Node */}
              <div className="lg:col-span-6">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
                  }}
                  className="glass-panel central-glow rounded-[32px] aspect-video p-6 sm:p-8 flex flex-col justify-between cursor-pointer hover:border-[#a78b71]/50 relative overflow-hidden"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pcap,.pcapng,.cap"
                    className="hidden"
                    onChange={(e) => handleFileUpload(e.target.files?.[0])}
                  />

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
                      Risk: <strong className={risk === 'CRITICAL' || risk === 'HIGH' ? 'text-[#e05260]' : 'text-[#e8d5b7]'}>{risk}</strong>
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
                <div
                  onClick={() => jumpToTab('overview')}
                  className="satellite-card w-full max-w-[290px] p-5 cursor-pointer"
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
                </div>

                <div
                  onClick={() => jumpToTab('remediation')}
                  className="satellite-card w-full max-w-[290px] p-5 cursor-pointer"
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
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4-Column Core Architecture Features Grid */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {CORE_PILLARS.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.title}
                className="glass-panel glass-panel-hover rounded-[24px] p-6 group"
              >
                <div className="w-12 h-12 rounded-2xl bg-[#a78b71]/10 border border-[#a78b71]/25 flex items-center justify-center mb-4 transition-transform duration-300 group-hover:scale-110">
                  <Icon className="w-5 h-5 text-[#c9b8a0]" />
                </div>
                <h3 className="font-bold text-[20px] text-white tracking-tight mb-2">{item.title}</h3>
                <p className="text-[14px] text-gray-400 leading-relaxed">{item.desc}</p>
              </div>
            );
          })}
        </section>

        {/* Lab Testbed Permutations Strip */}
        <section className="glass-panel rounded-[28px] p-6 sm:p-7 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-serif italic text-xl text-white flex items-center gap-2">
                <FlaskConical className="w-5 h-5 text-[#a78b71]" />
                Laboratory Testbed Captures
              </h2>
              <p className="text-xs text-gray-400 mt-0.5">
                Select any reference profile or live StrongSwan capture to inspect posture, SHAP attributions, and remediation patches.
              </p>
            </div>
            <span className="text-[11px] uppercase tracking-[0.2em] text-[#c9b8a0]">
              {samples.length} Scenarios Loaded
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {samples.map((s) => {
              const isActive = analysis?.pcap_filename === s.filename;
              const isBad = s.badge === 'CRITICAL' || s.badge === 'HIGH';
              return (
                <button
                  key={s.filename}
                  onClick={() => handleSampleClick(s.filename)}
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
        </section>

        {/* Deep Inspection Tabs Workspace */}
        <section ref={workspaceRef} className="space-y-6 pt-2">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-4">
            <div className="flex flex-wrap gap-2">
              {TABS.map((t) => {
                const Icon = t.icon;
                const active = activeTab === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setActiveTab(t.id)}
                    className={`px-4 py-2 rounded-full text-[11px] uppercase tracking-[0.16em] font-semibold flex items-center gap-2 transition-all duration-300 ${
                      active
                        ? 'bg-white text-black shadow-[0_0_30px_rgba(232,213,183,0.2)]'
                        : 'glass-panel text-gray-300 hover:text-[#e8d5b7] hover:border-[#a78b71]/40'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {t.label}
                  </button>
                );
              })}
            </div>

            {analysis && (
              <div className="text-[11px] uppercase tracking-[0.18em] text-[#c9b8a0]">
                Session <span className="font-mono text-white">{analysis.session_id}</span>
              </div>
            )}
          </div>

          <div className="reveal-enter">
            {activeTab === 'overview' && <OverviewTab analysis={analysis} />}
            {activeTab === 'protocol' && <ProtocolInspectorTab analysis={analysis} />}
            {activeTab === 'traffic' && <TrafficLabTab analysis={analysis} />}
            {activeTab === 'scanner' && (
              <ActiveScannerTab initialHost={quickHost} onToast={showToast} />
            )}
            {activeTab === 'remediation' && (
              <CompareRemediationTab analysis={analysis} sessions={sessions} onToast={showToast} />
            )}
          </div>
        </section>
      </main>

      {/* Luxury 5-Column Editorial Footer */}
      <footer className="border-t border-white/10 bg-[#0a0a0a]/90 backdrop-blur px-6 lg:px-12 py-12 mt-auto">
        <div className="max-w-[1380px] mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8">
          <div className="space-y-4">
            <div className="font-serif italic font-bold text-2xl text-white">
              IPsec <span className="text-[#a78b71]">Sentinel</span>
            </div>
            <p className="text-xs text-gray-400 leading-relaxed">
              AI-powered IPsec VPN protocol inspection, cryptographic compliance auditing, and encrypted flow intelligence.
            </p>
            <div className="flex items-center gap-2.5">
              <a
                href="https://github.com/amit-dev01/IPSEC_VPN_ANALYSER"
                target="_blank"
                rel="noreferrer"
                className="w-9 h-9 rounded-full border border-white/15 hover:border-[#e8d5b7] flex items-center justify-center text-gray-300 hover:text-[#e8d5b7] transition"
                title="GitHub Repository"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                className="w-9 h-9 rounded-full border border-white/15 hover:border-[#e8d5b7] flex items-center justify-center text-gray-300 hover:text-[#e8d5b7] transition"
                title="OpenAPI Swagger Docs"
              >
                <BookOpen className="w-4 h-4" />
              </a>
            </div>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">Modules</div>
            <button onClick={() => jumpToTab('overview')} className="block text-gray-400 hover:text-white transition">Posture Radar</button>
            <button onClick={() => jumpToTab('protocol')} className="block text-gray-400 hover:text-white transition">IKEv1/v2 Dissector</button>
            <button onClick={() => jumpToTab('traffic')} className="block text-gray-400 hover:text-white transition">SHAP Traffic Lab</button>
            <button onClick={() => jumpToTab('scanner')} className="block text-gray-400 hover:text-white transition">Active IKE Prober</button>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">Standards</div>
            <div className="text-gray-400">NIST SP 800-77 Rev 1</div>
            <div className="text-gray-400">RFC 8221 / RFC 7296</div>
            <div className="text-gray-400">CNSA 2.0 Quantum Advisory</div>
            <div className="text-gray-400">MITRE ATT&amp;CK Mapping</div>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">ML Engine</div>
            <div className="text-gray-400">LightGBM 7-Class Classifier</div>
            <div className="text-gray-400">UNB ISCX-VPN2016 (9,793 flows)</div>
            <div className="text-gray-400">SHAP TreeExplainer XAI</div>
            <div className="text-gray-400">IsolationForest Anomaly</div>
          </div>

          {/* Quick Gateway Probe Input (Circular Arrow Submit) */}
          <div className="space-y-3">
            <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">
              Quick Gateway Probe
            </div>
            <p className="text-xs text-gray-400">
              Jump straight to live IKE probing on any target IP or demo host.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                jumpToTab('scanner');
              }}
              className="flex items-center rounded-full bg-white/[0.04] border border-white/15 p-1 pl-4 focus-within:border-[#c9b8a0]"
            >
              <input
                type="text"
                value={quickHost}
                onChange={(e) => setQuickHost(e.target.value)}
                placeholder="Host or demo-vulnerable-gw"
                className="bg-transparent text-xs text-white placeholder-gray-500 focus:outline-none flex-1 min-w-0 font-mono"
              />
              <button
                type="submit"
                className="w-8 h-8 rounded-full bg-white hover:bg-[#e8d5b7] text-black flex items-center justify-center shrink-0 transition"
                title="Open Active Scanner"
              >
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      </footer>
    </div>
  );
}
