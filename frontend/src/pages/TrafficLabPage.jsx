import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../components/Layout';
import { TrafficLabTab } from '../components/TrafficLabTab';

export function TrafficLabPage({ analysis }) {
  return (
    <div className="space-y-8 reveal-enter">
      <PageHeader
        eyebrow="Explainable Encrypted Flow Telemetry"
        title="AI Encrypted"
        accent="Traffic Lab"
        subtitle="Zero-decryption LightGBM 7-class inference over ESP packet lengths & inter-arrival timing, TreeExplainer SHAP attributions, IsolationForest anomaly detection, and UNB ISCX-VPN2016 validation."
        rightSlot={
          <>
            <Link
              to="/inspector"
              className="px-4 py-2 rounded-full border border-white/15 hover:border-[#a78b71] text-xs text-gray-200 hover:text-[#e8d5b7] transition"
            >
              View Handshake SA
            </Link>
            <Link
              to="/overview"
              className="px-4 py-2 rounded-full bg-white hover:bg-[#e8d5b7] text-black text-xs font-semibold flex items-center gap-1.5 transition"
            >
              Posture Radar <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </>
        }
      />

      <TrafficLabTab analysis={analysis} />
    </div>
  );
}
