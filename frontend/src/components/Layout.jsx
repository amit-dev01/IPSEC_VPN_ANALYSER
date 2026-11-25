import React, { useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity, ArrowRight, BookOpen, FileDown, FlaskConical,
  GitCompare, Github, Home, Layers, LayoutDashboard,
  Loader2, Radar, Upload
} from 'lucide-react';

export const NAV_ROUTES = [
  { path: '/', label: 'Command Center', shortLabel: 'Home', icon: Home, end: true },
  { path: '/overview', label: 'Overview', shortLabel: 'Overview', icon: LayoutDashboard },
  { path: '/inspector', label: 'IKE Inspector', shortLabel: 'IKE Inspector', icon: Layers },
  { path: '/traffic-lab', label: 'AI Traffic Lab', shortLabel: 'Traffic Lab', icon: Activity },
  { path: '/scanner', label: 'Active Scanner', shortLabel: 'Scanner', icon: Radar },
  { path: '/remediation', label: 'Remediation', shortLabel: 'Remediation', icon: GitCompare },
];

/**
 * Shared subpage editorial header matching the obsidian & gold aesthetic.
 */
export function PageHeader({ eyebrow, title, accent, subtitle, rightSlot }) {
  return (
    <section className="glass-panel rounded-[28px] p-6 sm:p-8 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5 reveal-enter">
      <div className="space-y-2 max-w-3xl">
        <div className="text-[10px] uppercase tracking-[0.25em] text-[#a78b71] font-semibold">
          {eyebrow}
        </div>
        <h1 className="font-serif italic font-semibold text-2xl sm:text-3xl lg:text-4xl text-white tracking-tight">
          {title} {accent && <span className="text-[#a78b71]">{accent}</span>}
        </h1>
        {subtitle && (
          <p className="text-xs sm:text-sm text-gray-400 leading-relaxed">{subtitle}</p>
        )}
      </div>
      {rightSlot && <div className="flex flex-wrap items-center gap-3 shrink-0">{rightSlot}</div>}
    </section>
  );
}

/**
 * Persistent shell containing the fixed top navbar, mobile route rail,
 * subpage capture context switcher, toast notifications, and 5-column footer.
 */
export function Layout({
  children,
  analysis,
  samples,
  health,
  testbedStatus,
  loading,
  toast,
  onSelectSample,
  onTriggerUpload,
}) {
  const [quickHost, setQuickHost] = useState('demo-vulnerable-gw');
  const location = useLocation();
  const navigate = useNavigate();

  const isHome = location.pathname === '/';
  const isScanner = location.pathname === '/scanner';
  const score = analysis?.score_breakdown?.overall_score ?? '--';
  const risk = analysis?.score_breakdown?.risk_level ?? 'READY';

  const triggerUpload = onTriggerUpload;

  const handleQuickProbeSubmit = (e) => {
    e.preventDefault();
    const cleaned = (quickHost || 'demo-vulnerable-gw').trim();
    navigate(`/scanner?host=${encodeURIComponent(cleaned)}`);
  };

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
      <header className="fixed top-0 inset-x-0 z-40 h-16 px-6 lg:px-12 glass-panel border-x-0 border-t-0 border-b border-white/10 flex items-center justify-between gap-4">
        <Link to="/" className="flex items-center gap-3 shrink-0 group">
          <span className="font-serif italic font-bold text-xl tracking-tight text-white">
            IPsec <span className="text-[#a78b71] group-hover:text-[#e8d5b7] transition-colors">Sentinel</span>
          </span>
          <span className="hidden xl:inline-block text-[10px] uppercase tracking-[0.22em] text-[#c9b8a0]/80 border-l border-white/15 pl-3">
            Neural Security Suite
          </span>
        </Link>

        {/* Center-Aligned 11px Wide-Tracked Nav Links */}
        <nav className="hidden md:flex items-center gap-5 lg:gap-7">
          {NAV_ROUTES.map((r) => (
            <NavLink
              key={r.path}
              to={r.path}
              end={r.end}
              className={({ isActive }) =>
                `relative py-1 text-[11px] uppercase tracking-[0.18em] font-medium transition-colors duration-300 ${
                  isActive
                    ? 'text-[#e8d5b7] after:absolute after:inset-x-0 after:-bottom-1 after:h-[1.5px] after:bg-[#c9b8a0]'
                    : 'text-gray-400 hover:text-white'
                }`
              }
            >
              {r.shortLabel}
            </NavLink>
          ))}
        </nav>

        {/* Live Notification Pill + Upload + White Pill CTA */}
        <div className="flex items-center gap-2.5 shrink-0">
          <div className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 rounded-full glass-panel border border-white/10">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[8px] font-bold text-green-400 tracking-widest">LIVE</span>
            <span className="text-[12px] text-white font-medium">
              {health ? (testbedStatus.docker_running ? 'Docker XFRM Active' : 'ISCX LightGBM Online') : 'Connecting'}
            </span>
          </div>

          <button
            onClick={triggerUpload}
            title="Upload .pcap or .pcapng trace"
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-white/15 hover:border-[#a78b71]/60 text-[11px] text-gray-300 hover:text-[#e8d5b7] transition-colors"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin text-[#c9b8a0]" /> : <Upload className="w-3.5 h-3.5 text-[#a78b71]" />}
            <span className="hidden lg:inline">Upload PCAP</span>
          </button>

          {analysis ? (
            <button
              onClick={() => window.open(`/api/report/pdf/${analysis.session_id}`, '_blank')}
              className="px-4 py-1.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition-all duration-300"
            >
              <FileDown className="w-3.5 h-3.5" /> Executive PDF
            </button>
          ) : (
            <button
              onClick={triggerUpload}
              className="px-4 py-1.5 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold transition-all duration-300"
            >
              Analyze Trace
            </button>
          )}
        </div>
      </header>

      {/* Mobile Route Strip */}
      <div className="md:hidden fixed top-16 inset-x-0 z-30 glass-panel border-x-0 border-t-0 border-b border-white/10 px-4 py-2 overflow-x-auto">
        <div className="flex items-center gap-2 min-w-max">
          {NAV_ROUTES.map((r) => {
            const Icon = r.icon;
            return (
              <NavLink
                key={r.path}
                to={r.path}
                end={r.end}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-full text-[10px] uppercase tracking-[0.15em] font-semibold flex items-center gap-1.5 transition-colors ${
                    isActive
                      ? 'bg-white text-black'
                      : 'bg-white/[0.04] text-gray-300 border border-white/10'
                  }`
                }
              >
                <Icon className="w-3 h-3" />
                {r.shortLabel}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 pt-28 md:pt-24 pb-16 px-6 lg:px-12 max-w-[1380px] w-full mx-auto space-y-8">
        {/* Subpage Active Capture Context Bar (shown on analysis subpages) */}
        {!isHome && !isScanner && (
          <div className="glass-panel rounded-[22px] px-5 py-3.5 flex flex-wrap items-center justify-between gap-3 border border-white/10">
            <div className="flex flex-wrap items-center gap-3">
              <FlaskConical className="w-4 h-4 text-[#a78b71] shrink-0" />
              <div className="text-xs">
                <span className="text-gray-400">Active Capture: </span>
                <span className="font-mono text-white font-medium">
                  {analysis?.pcap_filename || 'Loading sample...'}
                </span>
              </div>
              {analysis && (
                <>
                  <span className="text-white/15">|</span>
                  <span className="text-xs text-gray-400">
                    Posture:{' '}
                    <strong className={risk === 'CRITICAL' || risk === 'HIGH' ? 'text-[#e05260]' : 'text-[#e8d5b7]'}>
                      {score}/100 ({risk})
                    </strong>
                  </span>
                  <span className="hidden sm:inline text-white/15">|</span>
                  <span className="hidden sm:inline text-[11px] font-mono text-[#c9b8a0]">
                    Session {analysis.session_id}
                  </span>
                </>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              {samples.length > 0 && (
                <select
                  aria-label="Switch testbed sample"
                  value={analysis?.pcap_filename || ''}
                  onChange={(e) => {
                    if (e.target.value) onSelectSample(e.target.value);
                  }}
                  disabled={loading}
                  className="bg-[#0e0e0e] border border-white/15 hover:border-[#a78b71]/60 rounded-full px-3.5 py-1.5 text-xs text-[#e8d5b7] focus:outline-none focus:border-[#c9b8a0]"
                >
                  {samples.map((s) => (
                    <option key={s.filename} value={s.filename}>
                      {s.label} ({s.badge})
                    </option>
                  ))}
                  {analysis && !samples.some((s) => s.filename === analysis.pcap_filename) && (
                    <option value={analysis.pcap_filename}>{analysis.pcap_filename} (Uploaded)</option>
                  )}
                </select>
              )}

              <button
                onClick={triggerUpload}
                disabled={loading}
                className="px-3.5 py-1.5 rounded-full bg-white/[0.06] hover:bg-[#a78b71]/20 border border-white/15 text-xs text-white flex items-center gap-1.5 transition"
              >
                {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin text-[#c9b8a0]" /> : <Upload className="w-3.5 h-3.5 text-[#a78b71]" />}
                Upload .PCAP
              </button>
            </div>
          </div>
        )}

        {/* Routed Page Outlet */}
        {children}
      </main>

      {/* Luxury 5-Column Editorial Footer */}
      <footer className="border-t border-white/10 bg-[#0a0a0a]/90 backdrop-blur px-6 lg:px-12 py-12 mt-auto">
        <div className="max-w-[1380px] mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8">
          <div className="space-y-4">
            <Link to="/" className="block font-serif italic font-bold text-2xl text-white">
              IPsec <span className="text-[#a78b71]">Sentinel</span>
            </Link>
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
            <div className="text-[10px] uppercase tracking-[0.22em] text-[#a78b71] font-semibold">Workspace Pages</div>
            <Link to="/" className="block text-gray-400 hover:text-white transition">Command Center</Link>
            <Link to="/overview" className="block text-gray-400 hover:text-white transition">Posture Radar</Link>
            <Link to="/inspector" className="block text-gray-400 hover:text-white transition">IKEv1/v2 Dissector</Link>
            <Link to="/traffic-lab" className="block text-gray-400 hover:text-white transition">SHAP Traffic Lab</Link>
            <Link to="/scanner" className="block text-gray-400 hover:text-white transition">Active IKE Prober</Link>
            <Link to="/remediation" className="block text-gray-400 hover:text-white transition">Compare &amp; Remediation</Link>
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
              onSubmit={handleQuickProbeSubmit}
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
