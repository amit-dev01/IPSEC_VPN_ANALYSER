import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../components/Layout';
import { CompareRemediationTab } from '../components/CompareRemediationTab';

export function RemediationPage({ analysis, sessions, onToast }) {
  return (
    <div className="space-y-8 reveal-enter">
      <PageHeader
        eyebrow="Vendor Hardening & Executive Reporting"
        title="Compare &"
        accent="Remediation Engine"
        subtitle="Benchmark any two persisted sessions side-by-side, deploy context-aware StrongSwan/Cisco IOS-XE/VyOS configuration patches, and download Executive PDF, Markdown, or JSON audit artifacts."
        rightSlot={
          <Link
            to="/overview"
            className="px-4 py-2 rounded-full border border-white/15 hover:border-[#a78b71] text-xs text-gray-200 hover:text-[#e8d5b7] flex items-center gap-1.5 transition"
          >
            Back to Overview <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        }
      />

      <CompareRemediationTab analysis={analysis} sessions={sessions} onToast={onToast} />
    </div>
  );
}
