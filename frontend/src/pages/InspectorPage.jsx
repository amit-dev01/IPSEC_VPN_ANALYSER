import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../components/Layout';
import { ProtocolInspectorTab } from '../components/ProtocolInspectorTab';

export function InspectorPage({ analysis }) {
  return (
    <div className="space-y-8 reveal-enter">
      <PageHeader
        eyebrow="Deterministic RFC 7296 / 2409 Engine"
        title="IKEv1 & IKEv2"
        accent="Protocol Inspector"
        subtitle="Deep packet inspection of Security Association transform parameters, offered proposal downgrade surfaces, Notify flags, and multi-stage handshake exchanges."
        rightSlot={
          <>
            <Link
              to="/traffic-lab"
              className="px-4 py-2 rounded-full border border-white/15 hover:border-[#a78b71] text-xs text-gray-200 hover:text-[#e8d5b7] transition"
            >
              Inspect ESP Traffic AI
            </Link>
            <Link
              to="/remediation"
              className="px-4 py-2 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition"
            >
              Fix Weak Ciphers <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </>
        }
      />

      <ProtocolInspectorTab analysis={analysis} />
    </div>
  );
}
