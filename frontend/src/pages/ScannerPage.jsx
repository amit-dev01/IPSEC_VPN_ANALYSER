import React from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../components/Layout';
import { ActiveScannerTab } from '../components/ActiveScannerTab';

export function ScannerPage({ onToast }) {
  const [searchParams] = useSearchParams();
  const initialHost = searchParams.get('host') || 'demo-vulnerable-gw';

  return (
    <div className="space-y-8 reveal-enter">
      <PageHeader
        eyebrow="Live Network Reconnaissance"
        title="Active IKE"
        accent="Gateway Prober"
        subtitle="Probe live UDP port 500/4500 VPN endpoints or built-in simulated gateways with non-destructive IKE_SA_INIT & IKEv1 proposals to score accepted cipher suites."
        rightSlot={
          <Link
            to="/remediation"
            className="px-4 py-2 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition"
          >
            Hardening Templates <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        }
      />

      <ActiveScannerTab key={initialHost} initialHost={initialHost} onToast={onToast} />
    </div>
  );
}
