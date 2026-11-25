import React, { useEffect, useState, useRef } from 'react';
import {
  Shield, Upload, FlaskConical, Activity, Radar, GitCompare,
  Layers, LayoutDashboard, FileDown, Loader2, Server
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
  { id: 'overview', label: 'Overview & Risk', icon: LayoutDashboard },
  { id: 'protocol', label: 'IKE Inspector', icon: Layers },
  { id: 'traffic', label: 'AI Traffic Lab', icon: Activity },
  { id: 'scanner', label: 'Active IKE Scanner', icon: Radar },
  { id: 'remediation', label: 'Compare & Remediation', icon: GitCompare },
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
  const fileInputRef = useRef(null);

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
      showToast(`Uploaded and analyzed ${file.name}`, 'success');
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const sa = analysis?.security_association;
  const score = analysis?.score_breakdown?.overall_score ?? '--';
  const risk = analysis?.score_breakdown?.risk_level ?? 'READY';

  return (
    <div className="min-h-screen flex flex-col bg-[#070b14] text-slate-100">
      {/* Toast Notification */}
      {toast && (
        <div
          className={`fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-xl text-xs font-semibold shadow-2xl border transition ${
            toast.type === 'error'
              ? 'bg-rose-950/95 text-rose-200 border-rose-600/50'
              : 'bg-emerald-950/95 text-emerald-200 border-emerald-600/50'
          }`}
        >
          {toast.msg}
        </div>
      )}

      {/* Top Header */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#0a0f1c]/90 backdrop-blur px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-wide">IPsec Sentinel AI</h1>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  v2.0 React SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Deep IPsec Protocol Dissector • 7-Class Encrypted Flow ML • Active Gateway Scanner
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${health ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-slate-300">{health ? 'API Online' : 'Connecting'}</span>
            </div>
            <div
              title={testbedStatus.command_hint}
              className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2"
            >
              <Server className={`w-3.5 h-3.5 ${testbedStatus.docker_running ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span className="text-slate-300">
                Docker Lab: {testbedStatus.docker_running ? `${testbedStatus.containers.length} Live` : 'Standby'}
              </span>
            </div>
            {analysis && (
              <button
                onClick={() => window.open(`/api/report/pdf/${analysis.session_id}`, '_blank')}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5 transition"
              >
                <FileDown className="w-3.5 h-3.5" /> Executive PDF
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Ingest & Lab Matrix Strip */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
            }}
            className="glass-panel rounded-2xl p-5 flex flex-col justify-center items-center text-center border-2 border-dashed border-slate-700/80 hover:border-cyan-500 cursor-pointer transition bg-slate-900/30 hover:bg-slate-900/60"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              className="hidden"
              onChange={(e) => handleFileUpload(e.target.files?.[0])}
            />
            {loading ? (
              <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mb-2" />
            ) : (
              <Upload className="w-8 h-8 text-cyan-400 mb-2" />
            )}
            <div className="text-sm font-semibold text-white">
              {loading ? 'Analyzing Packets & Extracting Flow ML...' : 'Drop .pcap / .pcapng Trace Here'}
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Supports Wireshark, tcpdump, StrongSwan, Cisco, IPv4 & IPv6 captures
            </p>
          </div>

          <div className="lg:col-span-2 glass-panel rounded-2xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <FlaskConical className="w-4 h-4 text-emerald-400" />
                Dynamic Lab Testbed Permutations ({samples.length} Captures)
              </h2>
              <span className="text-[11px] text-slate-500">Click any scenario to run full audit</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
              {samples.map((s) => {
                const isActive = analysis?.pcap_filename === s.filename;
                const badgeStyle =
                  s.badge === 'CRITICAL'
                    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                    : s.badge === 'HIGH'
                    ? 'bg-orange-500/15 text-orange-400 border-orange-500/30'
                    : s.badge === 'MODERATE'
                    ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
                    : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
                return (
                  <button
                    key={s.filename}
                    onClick={() => handleSampleClick(s.filename)}
                    className={`text-left p-2.5 rounded-xl border transition ${
                      isActive
                        ? 'bg-slate-800/90 border-cyan-500/60 shadow-lg shadow-cyan-500/10'
                        : 'bg-slate-900/60 border-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-semibold text-white truncate">{s.label}</span>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border shrink-0 ${badgeStyle}`}>
                        {s.badge}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 truncate">{s.description}</p>
                  </button>
                );
              })}
            </div>
          </div>
        </section>

        {/* KPI Bar */}
        {analysis && (
          <section className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="glass-panel p-4 rounded-xl text-center">
              <div className="text-[10px] uppercase text-slate-400 font-semibold">Security Score</div>
              <div
                className={`text-3xl font-black mt-0.5 ${
                  score >= 85 ? 'text-emerald-400' : score >= 65 ? 'text-amber-400' : 'text-rose-500'
                }`}
              >
                {score}
              </div>
              <span className="text-[10px] font-bold text-slate-300">{risk}</span>
            </div>

            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[10px] uppercase text-slate-400 font-semibold">Protocol</div>
              <div className="text-lg font-bold text-white mt-0.5">{sa?.ike_version}</div>
              <div className="text-[10px] text-cyan-400">{sa?.ip_version} • {sa?.nat_traversal_detected ? 'NAT-T 4500' : 'Direct IP'}</div>
            </div>

            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[10px] uppercase text-slate-400 font-semibold">Operating Mode</div>
              <div className="text-lg font-bold text-white mt-0.5">{sa?.mode}</div>
              <div className="text-[10px] text-slate-400">
                PFS: <strong className={sa?.pfs_enabled ? 'text-emerald-400' : 'text-rose-400'}>{sa?.pfs_enabled ? 'ON' : 'OFF'}</strong>
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl col-span-2">
              <div className="text-[10px] uppercase text-slate-400 font-semibold">Negotiated Cipher Suite</div>
              <div className="text-sm font-bold text-white mt-1 truncate">{sa?.encryption_algorithm}</div>
              <div className="text-[11px] text-slate-400 truncate">
                {sa?.integrity_algorithm || 'Combined AEAD'} • {sa?.dh_group || 'No DH'}
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[10px] uppercase text-slate-400 font-semibold">Trace Volume</div>
              <div className="text-lg font-bold text-white mt-0.5">{analysis.total_packets_parsed} pkts</div>
              <div className="text-[10px] text-slate-400">
                {analysis.ike_packets_count} IKE • {analysis.esp_packets_count} ESP
              </div>
            </div>
          </section>
        )}

        {/* Navigation Tabs */}
        <nav className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition ${
                  active
                    ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/20'
                    : 'bg-slate-900/70 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <Icon className="w-4 h-4" />
                {t.label}
              </button>
            );
          })}
        </nav>

        {/* Active Tab View */}
        <section>
          {activeTab === 'overview' && <OverviewTab analysis={analysis} />}
          {activeTab === 'protocol' && <ProtocolInspectorTab analysis={analysis} />}
          {activeTab === 'traffic' && <TrafficLabTab analysis={analysis} />}
          {activeTab === 'scanner' && <ActiveScannerTab onToast={showToast} />}
          {activeTab === 'remediation' && (
            <CompareRemediationTab analysis={analysis} sessions={sessions} onToast={showToast} />
          )}
        </section>
      </main>
    </div>
  );
}
