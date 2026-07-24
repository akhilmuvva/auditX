'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, ShieldAlert, FileText, ArrowRight, Activity, Plus } from 'lucide-react';

export default function Dashboard() {
  // Mock historical audit records representing the ICP canister storage
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
    if (cvss >= 7.0) return 'text-rose-400 bg-rose-500/10 border border-rose-500/20';
    return 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20';
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white flex flex-col font-sans relative selection:bg-indigo-500 selection:text-white">
      <div className="absolute top-0 left-0 w-[40%] h-[40%] rounded-full bg-emerald-500/5 blur-[120px] pointer-events-none" />

      {/* Header */}
      <header className="border-b border-white/[0.06] bg-black/30 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-emerald-500 flex items-center justify-center font-bold text-black text-lg">
              A
            </div>
            <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent">
              Audit<span className="text-indigo-400">X</span>
            </span>
          </Link>
          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-white/60">
            <Link href="/audit" className="hover:text-white transition-colors">New Audit</Link>
            <Link href="/siem" className="hover:text-white transition-colors">SIEM Toolkit</Link>
          </nav>
          <Link 
            href="/audit" 
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-all flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" /> New Audit
          </Link>
        </div>
      </header>

      {/* Content */}
      <main className="max-w-7xl w-full mx-auto px-6 py-12 flex flex-col gap-8 flex-1">
        
        {/* Welcome Section */}
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-black">Security Audit Registry</h1>
          <p className="text-white/60 text-sm">
            Read records stored on the Internet Computer Canister and manage your deployed certificates.
          </p>
        </div>

        {/* Audit Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {audits.map((a, idx) => (
            <div key={idx} className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col justify-between min-h-[220px] relative overflow-hidden group hover:border-white/10 transition-all">
              {/* Highlight bar based on CVSS */}
              <div className={`absolute top-0 left-0 right-0 h-1 ${a.cvss >= 7.0 ? 'bg-rose-500' : 'bg-emerald-500'}`} />

              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">{a.date}</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-lg ${getBadgeColor(a.cvss)}`}>
                    CVSS {a.cvss.toFixed(1)}
                  </span>
                </div>
                
                <h3 className="font-extrabold text-base tracking-tight">{a.name}</h3>
              </div>

              <div className="flex items-center justify-between border-t border-white/[0.04] pt-4 mt-6">
                <span className="text-[10px] font-bold text-white/40 uppercase">
                  {a.badgeId ? `Badge Token #${a.badgeId}` : 'No Badge Minted'}
                </span>
                
                <Link 
                  href={`/report/${a.id}`}
                  className="text-xs text-indigo-400 font-semibold group-hover:text-indigo-300 transition-colors flex items-center gap-1"
                >
                  View Report <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
