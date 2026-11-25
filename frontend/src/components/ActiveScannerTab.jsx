import React, { useState, useEffect } from 'react';
import { Radar, Play, CheckCircle2, XCircle, Loader2, Server } from 'lucide-react';
import { runActiveScan } from '../api';

export function ActiveScannerTab({ initialHost, onToast }) {
  const [targetHost, setTargetHost] = useState(initialHost || 'demo-vulnerable-gw');
  const [port, setPort] = useState(500);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  useEffect(() => {
    if (initialHost) setTargetHost(initialHost);
  }, [initialHost]);

  const handleScan = async (hostOverride) => {
    const host = hostOverride || targetHost;
    if (hostOverride) setTargetHost(hostOverride);
    setScanning(true);
    try {
      const res = await runActiveScan({ target_host: host, port: Number(port), timeout_seconds: 1.5 });
      setScanResult(res);
      onToast(`Scan finished for ${host} (Grade: ${res.overall_grade})`, 'success');
    } catch (err) {
      onToast(`Scan error: ${err.message}`, 'error');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass-panel rounded-[28px] p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <h3 className="font-serif italic text-lg text-white flex items-center gap-2">
              <Radar className="w-4 h-4 text-[#a78b71]" />
              Active IKE Gateway Scanner
            </h3>
            <p className="text-xs text-gray-400 mt-1">
              Sends non-destructive UDP IKE_SA_INIT &amp; IKEv1 cipher probes to audit accepted proposals on live VPN endpoints.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleScan('demo-vulnerable-gw')}
              className="text-[11px] uppercase tracking-[0.14em] px-3.5 py-1.5 rounded-full bg-[#e05260]/15 hover:bg-[#e05260]/25 text-[#f5a3ab] border border-[#e05260]/35 transition"
            >
              Demo Vulnerable GW
            </button>
            <button
              onClick={() => handleScan('demo-hardened-gw')}
              className="text-[11px] uppercase tracking-[0.14em] px-3.5 py-1.5 rounded-full bg-[#a78b71]/15 hover:bg-[#a78b71]/25 text-[#e8d5b7] border border-[#a78b71]/40 transition"
            >
              Demo Hardened GW
            </button>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <label className="block text-[10px] uppercase tracking-[0.2em] text-[#a78b71] mb-1.5">Target Gateway Host / IP</label>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              placeholder="e.g., 192.168.100.20 or demo-vulnerable-gw"
              className="w-full px-4 py-2.5 rounded-full bg-white/[0.04] border border-white/15 text-xs text-white focus:outline-none focus:border-[#c9b8a0] font-mono"
            />
          </div>
          <div className="w-32">
            <label className="block text-[10px] uppercase tracking-[0.2em] text-[#a78b71] mb-1.5">UDP Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full px-4 py-2.5 rounded-full bg-white/[0.04] border border-white/15 text-xs text-white focus:outline-none focus:border-[#c9b8a0] font-mono"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={() => handleScan()}
              disabled={scanning}
              className="px-6 py-2.5 rounded-full bg-white hover:bg-[#e8d5b7] disabled:opacity-50 text-black text-xs font-bold uppercase tracking-[0.14em] flex items-center gap-2 transition"
            >
              {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {scanning ? 'Probing...' : 'Run Probe'}
            </button>
          </div>
        </div>
      </div>

      {scanResult && (
        <div className="glass-panel rounded-[28px] p-6 space-y-5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-4">
            <div className="flex items-center gap-4">
              <div
                className={`w-16 h-16 rounded-[20px] flex items-center justify-center text-2xl font-serif italic font-bold border ${
                  scanResult.overall_grade.startsWith('A')
                    ? 'bg-[#a78b71]/20 text-[#e8d5b7] border-[#a78b71]/50'
                    : scanResult.overall_grade === 'F'
                    ? 'bg-[#e05260]/20 text-[#f5a3ab] border-[#e05260]/50'
                    : 'bg-white/10 text-[#c9b8a0] border-white/20'
                }`}
              >
                {scanResult.overall_grade}
              </div>
              <div>
                <div className="text-sm font-bold text-white flex items-center gap-2">
                  <Server className="w-4 h-4 text-[#a78b71]" />
                  {scanResult.target_host}:{scanResult.port}/UDP
                </div>
                <p className="text-xs text-gray-300 mt-1">{scanResult.summary}</p>
              </div>
            </div>
            <span className="text-xs font-mono text-gray-400">Scan ID: {scanResult.scan_id}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-[#a78b71] uppercase tracking-[0.16em] text-[10px]">
                  <th className="py-2.5 px-3">Result</th>
                  <th className="py-2.5 px-3">Probe Suite</th>
                  <th className="py-2.5 px-3">DH Group</th>
                  <th className="py-2.5 px-3">Security Risk</th>
                  <th className="py-2.5 px-3">RTT</th>
                  <th className="py-2.5 px-3">Gateway Response</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {scanResult.probes.map((p, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.03] transition">
                    <td className="py-3 px-3">
                      {p.accepted ? (
                        <span className="inline-flex items-center gap-1 text-xs font-bold text-[#e8d5b7]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> ACCEPTED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                          <XCircle className="w-3.5 h-3.5" /> REJECTED
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 font-medium text-white">{p.suite_name}</td>
                    <td className="py-3 px-3 font-mono text-gray-300">{p.dh_group}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                          p.security_grade === 'CRITICAL' || p.security_grade === 'HIGH'
                            ? 'bg-[#e05260]/20 text-[#f5a3ab]'
                            : 'bg-[#a78b71]/20 text-[#e8d5b7]'
                        }`}
                      >
                        {p.security_grade}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-gray-400">{p.response_time_ms} ms</td>
                    <td className="py-3 px-3 text-gray-300">{p.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-4 rounded-[20px] bg-white/[0.03] border border-[#a78b71]/30 space-y-1.5">
            <div className="text-[11px] uppercase tracking-[0.18em] font-bold text-[#e8d5b7]">
              Gateway Hardening Recommendations
            </div>
            {scanResult.recommendations.map((r, i) => (
              <div key={i} className="text-xs text-gray-300">• {r}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
