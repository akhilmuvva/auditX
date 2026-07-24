import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-[#030303] text-white flex flex-col selection:bg-indigo-500 selection:text-white overflow-hidden relative font-sans">
      {/* Background glow effects */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-emerald-500/10 blur-[120px] pointer-events-none" />

      {/* Header */}
      <header className="border-b border-white/[0.06] bg-black/30 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-emerald-500 flex items-center justify-center font-bold text-black text-lg">
              A
            </div>
            <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent">
              Audit<span className="text-indigo-400">X</span>
            </span>
          </div>
          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-white/60">
            <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
            <Link href="/audit" className="hover:text-white transition-colors">New Audit</Link>
            <Link href="/siem" className="hover:text-white transition-colors">SIEM Toolkit</Link>
          </nav>
          <div className="flex items-center gap-4">
            <Link 
              href="/audit" 
              className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-all shadow-[0_0_15px_rgba(79,70,229,0.3)] hover:shadow-[0_0_20px_rgba(79,70,229,0.5)]"
            >
              Start Free Audit
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="flex-1 flex flex-col justify-center items-center text-center px-6 py-20 relative z-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.03] border border-white/[0.08] text-xs text-indigo-300 font-medium mb-8">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          AuditX Engine v2.0 is Live
        </div>

        <h1 className="text-4xl sm:text-6xl font-black tracking-tight max-w-4xl leading-tight mb-6">
          Your Smart Contract. <br />
          <span className="bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400 bg-clip-text text-transparent">
            Audited in 60 Seconds.
          </span>
        </h1>

        <p className="text-white/60 text-lg sm:text-xl max-w-2xl leading-relaxed mb-12">
          Slither + Mythril + Claude AI triage combined into a single continuous security pipeline. 
          Generate on-chain EAS attestations and mint SVG Security Badges.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 mb-20 w-full justify-center max-w-md">
          <Link 
            href="/audit" 
            className="flex-1 bg-white hover:bg-white/90 text-black font-semibold h-12 flex items-center justify-center rounded-xl transition-all shadow-[0_0_20px_rgba(255,255,255,0.15)]"
          >
            Audit Your Contract Free
          </Link>
          <Link 
            href="/dashboard" 
            className="flex-1 bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-white font-semibold h-12 flex items-center justify-center rounded-xl transition-all"
          >
            View Demo Dashboard
          </Link>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-8 max-w-4xl w-full border-t border-white/[0.06] pt-12 text-left">
          <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03]">
            <div className="text-xs text-white/40 font-bold uppercase tracking-wider mb-2">Contracts Audited</div>
            <div className="text-3xl font-black bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent">14,204</div>
          </div>
          <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03]">
            <div className="text-xs text-white/40 font-bold uppercase tracking-wider mb-2">Critical Bugs Found</div>
            <div className="text-3xl font-black text-indigo-400">1,894</div>
          </div>
          <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03]">
            <div className="text-xs text-white/40 font-bold uppercase tracking-wider mb-2">On-chain Badges Minted</div>
            <div className="text-3xl font-black text-emerald-400">9,842</div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/[0.06] bg-black/40 py-8 text-center text-xs text-white/40">
        <p>© 2026 AuditX. Built on Polygon & Internet Computer.</p>
      </footer>
    </div>
  );
}
