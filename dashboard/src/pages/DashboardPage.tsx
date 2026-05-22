import React, { useState } from 'react';
import { useWalletStore } from '../store/useWalletStore';
import { useAuditStore } from '../store/useAuditStore';
import { truncateAddress, chainName } from '../lib/wallet';
import {
  Shield, LogOut, ExternalLink, Copy, CheckCheck,
  Activity, AlertTriangle, CheckCircle2, Radio,
} from 'lucide-react';
import { LiveAuditSimulator } from '../components/LiveAuditSimulator';
import { SIEMPanel } from '../components/SIEMPanel';


const CopyableAddress = ({ address }: { address: string }) => {
  const [copied, setCopied] = React.useState(false);
  const copy = () => {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} className="flex items-center gap-1.5 text-[10px] font-fira text-gray-400 hover:text-gray-200 transition-colors">
      {truncateAddress(address)}
      {copied ? <CheckCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

export const DashboardPage: React.FC = () => {
  const { wallet, disconnect } = useWalletStore();
  const { simStatus, report } = useAuditStore();
  const [activeTab, setActiveTab] = useState<'audit' | 'siem'>('audit');

  if (!wallet) return null;

  const riskColor =
    report?.analyticsSummary.riskClassification === 'critical' ? 'text-rose-400' :
    report?.analyticsSummary.riskClassification === 'high' ? 'text-orange-400' :
    report?.analyticsSummary.riskClassification === 'medium' ? 'text-amber-400' :
    'text-emerald-400';

  return (
    <div className="min-h-screen bg-[#07090F] text-gray-100">

      {/* ── TOP NAV ── */}
      <header className="sticky top-0 z-50 border-b border-white/5 bg-[#07090F]/90 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <a href="/" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg overflow-hidden border border-indigo-500/20 shadow-lg shadow-indigo-500/25 group-hover:scale-105 transition-transform duration-300">
              <img src="/icon.png" alt="AuditX Logo" className="w-full h-full object-cover" />
            </div>
            <div>
              <span className="text-base font-extrabold tracking-tight text-white">AuditX</span>
              <span className="text-[9px] text-indigo-400 font-fira font-bold block -mt-0.5 uppercase tracking-widest">Protocol v2</span>
            </div>
          </a>

          {/* Status chips */}
          <div className="hidden md:flex items-center gap-3">
            {simStatus === 'RUNNING' && (
              <div className="flex items-center gap-1.5 bg-amber-500/10 border border-amber-400/20 text-amber-400 text-[10px] font-fira font-bold px-3 py-1.5 rounded-full">
                <Activity className="w-3 h-3 animate-pulse" /> Analyzing…
              </div>
            )}
            {simStatus === 'COMPLETED' && report && (
              <div className={`flex items-center gap-1.5 bg-white/5 border border-white/10 text-[10px] font-fira font-bold px-3 py-1.5 rounded-full ${riskColor}`}>
                {report.analyticsSummary.certificationStatus === 'DENIED_RISK_TOO_HIGH'
                  ? <><AlertTriangle className="w-3 h-3" /> RISK DENIED</>
                  : <><CheckCircle2 className="w-3 h-3" /> CERTIFIED</>
                }
              </div>
            )}
          </div>

          {/* Wallet info */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-white/[0.04] border border-white/8 rounded-xl px-4 py-2">
              <div className="w-6 h-6 rounded-full bg-gradient-to-br from-indigo-400 to-purple-500" />
              <div className="hidden sm:block">
                <CopyableAddress address={wallet.address} />
                <span className="text-[9px] text-gray-600 font-fira block">
                  {chainName(wallet.chainId)} · {wallet.balance} ETH
                </span>
              </div>
              <a
                href={`https://etherscan.io/address/${wallet.address}`}
                target="_blank" rel="noreferrer"
                className="text-gray-600 hover:text-gray-300 transition-colors ml-1"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <button
              onClick={disconnect}
              title="Disconnect wallet"
              className="w-9 h-9 flex items-center justify-center rounded-xl border border-white/5 bg-white/[0.03] text-gray-500 hover:text-rose-400 hover:border-rose-500/30 hover:bg-rose-500/5 transition-all duration-300"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* ── MAIN CONTENT ── */}
      <main className="max-w-7xl mx-auto px-6 py-10">

        {/* Page header */}
        <div className="flex items-start justify-between mb-8 pb-6 border-b border-white/5">
          <div>
            <h1 className="text-2xl font-extrabold text-white font-outfit tracking-tight">Security Audit</h1>
            <p className="text-sm text-gray-500 font-outfit mt-1">
              Upload a Solidity contract for decentralized multi-tool analysis
            </p>
          </div>
          <div className="hidden md:flex flex-col items-end gap-1">
            <div className="flex items-center gap-2 text-[10px] font-fira text-gray-500">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Zero-Server Mode
            </div>
            <div className="flex items-center gap-2 text-[10px] font-fira text-gray-500">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" /> Gemini Flash Latest
            </div>
            <div className="flex items-center gap-2 text-[10px] font-fira text-gray-500">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400" /> EIP-1193 Wallet
            </div>
          </div>
        </div>

        {/* ── TAB NAVIGATION ── */}
        <div className="flex items-center gap-1 mb-8 border-b border-white/5 pb-0">
          <button
            id="tab-audit"
            onClick={() => setActiveTab('audit')}
            className={`flex items-center gap-2 px-5 py-3 text-xs font-fira font-bold border-b-2 -mb-px transition-colors ${
              activeTab === 'audit'
                ? 'border-indigo-500 text-indigo-300'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Audit
          </button>
          <button
            id="tab-siem"
            onClick={() => setActiveTab('siem')}
            className={`flex items-center gap-2 px-5 py-3 text-xs font-fira font-bold border-b-2 -mb-px transition-colors ${
              activeTab === 'siem'
                ? 'border-rose-500 text-rose-300'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            SIEM Monitor
            <span className="text-[9px] bg-rose-500/20 border border-rose-500/30 text-rose-400 px-1.5 py-0.5 rounded-full font-bold">LIVE</span>
          </button>
        </div>

        {/* ── TAB CONTENT ── */}
        {activeTab === 'audit' && <LiveAuditSimulator />}
        {activeTab === 'siem'  && <SIEMPanel />}
      </main>

      <footer className="border-t border-white/5 py-6 text-center text-[10px] text-gray-700 font-fira mt-16">
        AUDITX PROTOCOL v2 · WALLET: {truncateAddress(wallet.address)} · DECENTRALIZED
      </footer>
    </div>
  );
};
