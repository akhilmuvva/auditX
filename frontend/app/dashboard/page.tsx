'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, ShieldAlert, FileText, ArrowRight, Activity, Plus, CheckCircle2, Lock } from 'lucide-react';

export default function Dashboard() {
  const [audits] = useState([
    {
      id: 'clean',
      name: 'Clean Token Vault',
      date: '2026-07-01',
      cvss: 1.8,
      web3: 1.8,
      web2: 0.0,
      chains: 0,
      badge: 'Emerald Guard',
      badgeId: 42
    },
    {
      id: 'reentrancy',
      name: 'Vulnerable Staking Pool',
      date: '2026-06-28',
      cvss: 8.5,
      web3: 8.5,
      web2: 0.0,
      chains: 0,
      badge: 'Locked',
      badgeId: null
    },
    {
      id: 'fullstack',
      name: 'Full Stack De-Fi Portal',
      date: '2026-06-20',
      cvss: 9.8,
      web3: 8.0,
      web2: 9.8,
      chains: 1,
      badge: 'Locked',
      badgeId: null
    }
  ]);

  const getBadgeColor = (cvss: number) => {
    if (cvss >= 7.0) return 'text-rose-700 bg-rose-50 border border-rose-200';
    return 'text-emerald-700 bg-emerald-50 border border-emerald-200';
  };

  return (
    <div className="min-h-screen bg-[#F6F9FC] text-slate-900 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Header */}
      <header className="border-b border-slate-200/80 bg-white/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center font-bold text-white text-lg shadow-sm shadow-blue-500/20">
              A
            </div>
            <span className="font-extrabold text-xl tracking-tight text-slate-900">
              Audit<span className="text-blue-600">X</span>
            </span>
          </Link>
          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
            <Link href="/dashboard" className="text-blue-700 font-bold bg-blue-50/80 border border-blue-200/80 px-3 py-1.5 rounded-xl flex items-center gap-1.5 shadow-sm">
              Dashboard
            </Link>
            <Link href="/audit" className="hover:text-blue-600 transition-colors">New Audit</Link>
            <Link href="/siem" className="hover:text-blue-600 transition-colors">SIEM Toolkit</Link>
          </nav>
          <Link 
            href="/audit" 
            className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-4 py-2.5 rounded-xl transition-all shadow-md shadow-blue-500/20 flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" /> New Audit
          </Link>
        </div>
      </header>

      {/* Content */}
      <main className="max-w-7xl w-full mx-auto px-6 py-10 flex flex-col gap-8 flex-1">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200/80 pb-6">
          <div>
            <h1 className="text-2xl sm:text-3xl font-black text-slate-900">Security Audits Registry</h1>
            <p className="text-slate-600 text-xs sm:text-sm mt-1">
              Verifiable on-chain audit reports, CVSS vulnerability scoring, and minted Soulbound Security Badges.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> ICP Canister State Synced
            </span>
          </div>
        </div>

        {/* Audits Table */}
        <div className="grid grid-cols-1 gap-4">
          {audits.map((item) => (
            <div 
              key={item.id}
              className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm hover:border-blue-300 hover:shadow-md transition-all flex flex-col md:flex-row md:items-center justify-between gap-6"
            >
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shrink-0">
                  <FileText className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-bold text-base text-slate-900">{item.name}</h3>
                    <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                      {item.date}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 font-mono">
                    <span>Web3 Score: <strong className="text-slate-800">{item.web3}</strong></span>
                    <span>Web2 Score: <strong className="text-slate-800">{item.web2}</strong></span>
                    <span>Cross-Chains: <strong className="text-slate-800">{item.chains}</strong></span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4 self-end md:self-auto">
                <div className="flex flex-col items-end gap-1">
                  <span className={`text-xs font-bold px-3 py-1 rounded-full ${getBadgeColor(item.cvss)}`}>
                    CVSS: {item.cvss}
                  </span>
                  <span className="text-[11px] text-slate-500 font-medium">
                    {item.badge === 'Emerald Guard' ? (
                      <span className="text-emerald-600 font-semibold flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5" /> Badge #{item.badgeId} Minted
                      </span>
                    ) : (
                      <span className="text-slate-400 flex items-center gap-1">
                        <Lock className="w-3.5 h-3.5" /> Badge Locked
                      </span>
                    )}
                  </span>
                </div>

                <Link
                  href={`/report/${item.id}`}
                  className="bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold px-4 py-2.5 rounded-xl transition-all flex items-center gap-1.5 shadow-sm"
                >
                  View Report <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
