import React, { useState } from 'react';
import { Radar, Play, CheckCircle2, XCircle, Loader2, Server } from 'lucide-react';
import { runActiveScan } from '../api';

export function ActiveScannerTab({ onToast }) {
  const [targetHost, setTargetHost] = useState('demo-vulnerable-gw');
  const [port, setPort] = useState(500);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

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
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Radar className="w-4 h-4 text-emerald-400" />
              Active IKE Gateway Scanner ("SSL Labs for IPsec")
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Sends non-destructive UDP IKE_SA_INIT & IKEv1 cipher probes to audit supported proposals on live VPN endpoints.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleScan('demo-vulnerable-gw')}
              className="text-xs px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 transition"
            >
              Demo Vulnerable GW
            </button>
            <button
              onClick={() => handleScan('demo-hardened-gw')}
              className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 transition"
            >
              Demo Hardened GW
            </button>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Target Gateway Host / IP</label>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              placeholder="e.g., 192.168.100.20 or demo-vulnerable-gw"
              className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <div className="w-32">
            <label className="block text-[10px] uppercase text-slate-400 mb-1">UDP Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={() => handleScan()}
              disabled={scanning}
              className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold flex items-center gap-2 transition"
            >
              {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {scanning ? 'Probing...' : 'Run Probe'}
            </button>
          </div>
        </div>
      </div>

      {scanResult && (
        <div className="glass-panel rounded-2xl p-6 space-y-5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-4">
              <div
                className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl font-black border ${
                  scanResult.overall_grade.startsWith('A')
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40'
                    : scanResult.overall_grade === 'F'
                    ? 'bg-rose-500/15 text-rose-400 border-rose-500/40'
                    : 'bg-amber-500/15 text-amber-400 border-amber-500/40'
                }`}
              >
                {scanResult.overall_grade}
              </div>
              <div>
                <div className="text-sm font-bold text-white flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  {scanResult.target_host}:{scanResult.port}/UDP
                </div>
                <p className="text-xs text-slate-300 mt-0.5">{scanResult.summary}</p>
              </div>
            </div>
            <span className="text-xs font-mono text-slate-400">Scan ID: {scanResult.scan_id}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 px-3">Result</th>
                  <th className="py-2 px-3">Probe Suite</th>
                  <th className="py-2 px-3">DH Group</th>
                  <th className="py-2 px-3">Security Risk</th>
                  <th className="py-2 px-3">RTT</th>
                  <th className="py-2 px-3">Gateway Response</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scanResult.probes.map((p, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3">
                      {p.accepted ? (
                        <span className="inline-flex items-center gap-1 text-xs font-bold text-cyan-300">
                          <CheckCircle2 className="w-3.5 h-3.5" /> ACCEPTED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-slate-400">
                          <XCircle className="w-3.5 h-3.5" /> REJECTED
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-white">{p.suite_name}</td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{p.dh_group}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          p.security_grade === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300'
                            : p.security_grade === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {p.security_grade}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400">{p.response_time_ms} ms</td>
                    <td className="py-2.5 px-3 text-slate-300">{p.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
            <div className="text-xs font-bold text-amber-300">Gateway Hardening Recommendations</div>
            {scanResult.recommendations.map((r, i) => (
              <div key={i} className="text-xs text-slate-300">• {r}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
