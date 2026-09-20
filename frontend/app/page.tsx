import Link from 'next/link';
import { ShieldCheck, ShieldAlert, Activity, ArrowRight, Zap, Lock, Cpu, Terminal, CheckCircle2, Layers } from 'lucide-react';

export default function Home() {
  return (
    <div className="min-h-screen bg-[#F6F9FC] text-slate-900 flex flex-col selection:bg-blue-600 selection:text-white font-sans">
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
            <Link href="/dashboard" className="hover:text-blue-600 transition-colors">Dashboard</Link>
            <Link href="/audit" className="hover:text-blue-600 transition-colors">New Audit</Link>
            <Link href="/siem" className="hover:text-blue-600 transition-colors flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-emerald-600" /> SIEM Toolkit
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <Link 
              href="/audit" 
              className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-4 py-2.5 rounded-xl transition-all shadow-md shadow-blue-500/20 flex items-center gap-1.5"
            >
              Start Free Audit <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="flex-1 flex flex-col justify-center items-center text-center px-6 py-20 max-w-5xl mx-auto w-full">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200/80 text-xs text-blue-700 font-semibold mb-8 shadow-sm">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          AuditX Engine v2.0 Live on Polygon & ICP
        </div>

        <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-slate-950 leading-tight mb-6">
          Continuous Smart Contract Security. <br />
          <span className="bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 bg-clip-text text-transparent">
            Audited & Monitored in Real-Time.
          </span>
        </h1>

        <p className="text-slate-600 text-base sm:text-lg max-w-2xl leading-relaxed mb-10">
          Slither + Mythril symbolic analysis combined with AI triage. Seal verifiable audit reports with on-chain EAS attestations, mint Soulbound Security Badges, and stream live EVM threat telemetry.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 mb-16 w-full justify-center max-w-md">
          <Link 
            href="/audit" 
            className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-semibold h-12 flex items-center justify-center rounded-xl transition-all shadow-md shadow-blue-500/25"
          >
            Audit Your Contract Free
          </Link>
          <Link 
            href="/siem" 
            className="flex-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-semibold h-12 flex items-center justify-center rounded-xl transition-all shadow-sm"
          >
            Launch Web3 SIEM
          </Link>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-4xl w-full border-t border-slate-200/80 pt-12 text-left">
          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm">
            <div className="text-xs text-slate-500 font-bold uppercase tracking-wider mb-2">Contracts Audited</div>
            <div className="text-3xl font-black text-slate-900">14,204</div>
            <span className="text-xs text-emerald-600 font-medium mt-1 inline-flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> 100% Automated Static Pipeline
            </span>
          </div>
          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm">
            <div className="text-xs text-slate-500 font-bold uppercase tracking-wider mb-2">Critical Threats Prevented</div>
            <div className="text-3xl font-black text-rose-600">1,894</div>
            <span className="text-xs text-slate-500 font-medium mt-1 inline-block">
              Reentrancy, Flash Loan & Permissions
            </span>
          </div>
          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm">
            <div className="text-xs text-slate-500 font-bold uppercase tracking-wider mb-2">On-chain Badges Minted</div>
            <div className="text-3xl font-black text-blue-600">9,842</div>
            <span className="text-xs text-slate-500 font-medium mt-1 inline-block">
              Polygon ERC-721 + EAS Attestations
            </span>
          </div>
        </div>
      </section>

      {/* Feature Cards Grid */}
      <section className="max-w-7xl mx-auto px-6 py-12 w-full">
        <div className="text-center mb-12">
          <span className="text-xs font-bold uppercase tracking-wider text-blue-600 bg-blue-50 px-3 py-1 rounded-full border border-blue-200">
            6-Layer Defense Grid
          </span>
          <h2 className="text-3xl font-black text-slate-900 mt-3">Full-Spectrum Web3 Security Suite</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm hover:border-blue-300 hover:shadow-md transition-all flex flex-col gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Terminal className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-slate-900">Multi-Engine Code Audit</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              Automated Slither and Mythril execution with AST extraction, control flow graph generation, and cross-contract dependency inspection.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm hover:border-blue-300 hover:shadow-md transition-all flex flex-col gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-600">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-slate-900">Real-Time Web3 SIEM</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              EVM transaction streaming with Welford anomaly detection, Tornado Cash threat matching, and automated HMAC-signed webhook delivery.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm hover:border-blue-300 hover:shadow-md transition-all flex flex-col gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-slate-900">SIWE Dynamic Trust Scoring</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              High-speed Rust authentication engine with velocity tracking, impossible travel calculation, and cold-start baselines under 300ms SLA.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-200/80 bg-white py-8 text-center text-xs text-slate-500 mt-auto">
        <p>© 2026 AuditX. Enterprise Security on Polygon & Internet Computer.</p>
      </footer>
    </div>
  );
}
