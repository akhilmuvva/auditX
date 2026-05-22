import React, { useEffect, useRef } from 'react';
import { useWalletStore } from '../store/useWalletStore';
import { isMetaMaskInstalled, truncateAddress, chainName } from '../lib/wallet';
import { Shield, Loader2, Zap, ChevronRight, Code2 } from 'lucide-react';

/* ── Animated counter ── */
const StatCard = ({ value, label, accent }: { value: string; label: string; accent: string }) => (
  <div className="flex flex-col items-center">
    <span className={`text-3xl font-extrabold font-fira ${accent}`}>{value}</span>
    <span className="text-xs text-gray-500 font-outfit uppercase tracking-widest mt-1">{label}</span>
  </div>
);



/* ── Main Landing Page ── */
export const LandingPage: React.FC = () => {
  const { connect, connecting, error, wallet } = useWalletStore();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  /* Particle mesh background */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf: number;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener('resize', resize);

    const pts = Array.from({ length: 80 }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
    }));

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(99,102,241,0.35)';
        ctx.fill();
      });
      // Draw connecting lines
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 130) {
            ctx.beginPath();
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[j].x, pts[j].y);
            ctx.strokeStyle = `rgba(99,102,241,${0.12 * (1 - dist / 130)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, []);

  const hasMetaMask = isMetaMaskInstalled();

  return (
    <div className="min-h-screen bg-[#07090F] text-gray-100 relative overflow-hidden">
      {/* Background */}
      <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none" />
      <div className="fixed inset-0 bg-gradient-to-br from-indigo-950/30 via-transparent to-purple-950/20 pointer-events-none" />
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-indigo-600/5 blur-[120px] rounded-full pointer-events-none" />

      {/* ── NAVBAR ── */}
      <nav className="relative z-50 border-b border-white/5 bg-[#07090F]/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg overflow-hidden border border-indigo-500/20 shadow-lg shadow-indigo-500/25">
              <img src="/icon.png" alt="AuditX Logo" className="w-full h-full object-cover" />
            </div>
            <div>
              <span className="text-base font-extrabold tracking-tight text-white">AuditX</span>
              <span className="text-[9px] text-indigo-400 font-fira font-bold block -mt-0.5 uppercase tracking-widest">Protocol v2</span>
            </div>
          </div>

          <div className="hidden md:flex items-center gap-8 text-xs text-gray-400 font-outfit">

            <a href="#how-it-works" className="hover:text-white transition-colors">How It Works</a>
            <a href="https://github.com/akhilmuvva/auditX" target="_blank" rel="noreferrer"
              className="flex items-center gap-1.5 hover:text-white transition-colors">
              <Code2 className="w-3.5 h-3.5" /> GitHub
            </a>
          </div>

          {wallet ? (
            <div className="flex items-center gap-3 bg-white/5 border border-white/10 rounded-xl px-4 py-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-fira text-gray-200">{truncateAddress(wallet.address)}</span>
              <span className="text-[9px] font-fira text-indigo-400 border border-indigo-400/30 bg-indigo-400/10 px-2 py-0.5 rounded-full">
                {chainName(wallet.chainId)}
              </span>
            </div>
          ) : (
            <button
              onClick={connect}
              disabled={connecting}
              className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-outfit px-5 py-2.5 rounded-xl border border-indigo-400/25 shadow-lg shadow-indigo-500/20 transition-all duration-300 hover:-translate-y-0.5 disabled:opacity-60"
            >
              {connecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
              Connect Wallet
            </button>
          )}
        </div>
      </nav>

      <main className="relative z-10">
        {/* ── HERO ── */}
        <section className="max-w-7xl mx-auto px-6 pt-28 pb-24 text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 bg-indigo-500/10 border border-indigo-400/20 text-indigo-300 text-[10px] font-fira font-bold uppercase tracking-widest px-4 py-2 rounded-full mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
            Decentralized · Zero-Server · On-Chain Attestation
          </div>

          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight leading-none mb-6 font-outfit">
            <span className="text-white">Autonomous</span>
            <br />
            <span className="bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              Smart Contract
            </span>
            <br />
            <span className="text-white">Security Protocol</span>
          </h1>

          <p className="text-gray-400 text-lg max-w-2xl mx-auto font-outfit leading-relaxed mb-12">
            Upload any Solidity contract. Gemini AI performs multi-tool security analysis.
            Results sealed on-chain via EAS attestation with SVG NFT badges.
          </p>

          {/* CTA */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-20">
            {wallet ? (
              <a
                href="/audit"
                className="flex items-center gap-3 bg-gradient-to-r from-indigo-600 to-purple-700 hover:from-indigo-500 hover:to-purple-600 text-white font-bold font-outfit px-8 py-4 rounded-2xl border border-indigo-400/25 shadow-2xl shadow-indigo-500/30 transition-all duration-300 hover:-translate-y-1 text-sm"
              >
                <Shield className="w-5 h-5" />
                Launch Dashboard
                <ChevronRight className="w-4 h-4" />
              </a>
            ) : (
              <button
                onClick={connect}
                disabled={connecting}
                className="flex items-center gap-3 bg-gradient-to-r from-indigo-600 to-purple-700 hover:from-indigo-500 hover:to-purple-600 text-white font-bold font-outfit px-8 py-4 rounded-2xl border border-indigo-400/25 shadow-2xl shadow-indigo-500/30 transition-all duration-300 hover:-translate-y-1 disabled:opacity-60 text-sm"
              >
                {connecting
                  ? <><Loader2 className="w-5 h-5 animate-spin" /> Connecting…</>
                  : <><Zap className="w-5 h-5" /> Connect Wallet to Start</>
                }
              </button>
            )}
            <a
              href="https://github.com/akhilmuvva/auditX"
              target="_blank" rel="noreferrer"
              className="flex items-center gap-2 bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 hover:text-white font-outfit font-bold px-8 py-4 rounded-2xl text-sm transition-all duration-300"
            >
              <Code2 className="w-4 h-4" /> View on GitHub
            </a>
          </div>

          {/* Error */}
          {error && (
            <div className="inline-flex items-center gap-2 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-fira px-4 py-2 rounded-xl mb-8">
              ⚠ {error}{!hasMetaMask && ' — Install MetaMask first.'}
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-3 gap-8 max-w-lg mx-auto border-t border-white/5 pt-12">
            <StatCard value="8" label="Pipeline Stages" accent="text-indigo-400" />
            <StatCard value="3+" label="Analysis Tools" accent="text-purple-400" />
            <StatCard value="100%" label="Decentralized" accent="text-emerald-400" />
          </div>
        </section>

        {/* ── PIPELINE VISUAL ── */}
        <section id="how-it-works" className="max-w-7xl mx-auto px-6 py-20 border-t border-white/5">
          <div className="text-center mb-14">
            <p className="text-[10px] text-indigo-400 font-fira font-bold uppercase tracking-widest mb-3">Audit Pipeline</p>
            <h2 className="text-3xl font-extrabold text-white font-outfit">How It Works</h2>
          </div>
          <div className="flex items-center justify-between gap-2 overflow-x-auto pb-4">
            {[
              { step: '01', label: 'Upload', sub: '.sol file', color: 'text-indigo-400', bg: 'bg-indigo-500/10 border-indigo-400/20' },
              { step: '02', label: 'Slither', sub: 'Static AST', color: 'text-cyan-400', bg: 'bg-cyan-500/10 border-cyan-400/20' },
              { step: '03', label: 'Mythril', sub: 'Symbolic Exec', color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-400/20' },
              { step: '04', label: 'Surya', sub: 'Call Graph', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-400/20' },
              { step: '05', label: 'Gemini AI', sub: 'Triage', color: 'text-pink-400', bg: 'bg-pink-500/10 border-pink-400/20' },
              { step: '06', label: 'IPFS', sub: 'Report Pin', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-400/20' },
              { step: '07', label: 'EAS', sub: 'Attest', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-400/20' },
              { step: '08', label: 'NFT Badge', sub: 'Mint SVG', color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-400/20' },
            ].map((s, i, arr) => (
              <React.Fragment key={s.step}>
                <div className={`flex-shrink-0 flex flex-col items-center gap-2 border rounded-2xl px-5 py-4 min-w-[90px] ${s.bg}`}>
                  <span className={`text-[9px] font-fira font-bold ${s.color} uppercase tracking-wider`}>{s.step}</span>
                  <span className={`text-sm font-bold font-outfit ${s.color}`}>{s.label}</span>
                  <span className="text-[9px] text-gray-500 font-fira">{s.sub}</span>
                </div>
                {i < arr.length - 1 && <ChevronRight className="w-4 h-4 text-gray-700 flex-shrink-0" />}
              </React.Fragment>
            ))}
          </div>
        </section>



        {/* ── BOTTOM CTA ── */}
        <section className="max-w-7xl mx-auto px-6 py-24 text-center border-t border-white/5">
          <h2 className="text-4xl font-extrabold text-white font-outfit mb-4">Ready to audit?</h2>
          <p className="text-gray-400 font-outfit mb-10">Connect your wallet and upload any Solidity contract.</p>
          <button
            onClick={connect}
            disabled={connecting || !!wallet}
            className="inline-flex items-center gap-3 bg-gradient-to-r from-indigo-600 to-purple-700 hover:from-indigo-500 hover:to-purple-600 text-white font-bold font-outfit px-10 py-5 rounded-2xl border border-indigo-400/25 shadow-2xl shadow-indigo-500/30 transition-all duration-300 hover:-translate-y-1 disabled:opacity-60 text-base"
          >
            {wallet
              ? <><Shield className="w-5 h-5" /><a href="/audit">Go to Dashboard</a></>
              : connecting
              ? <><Loader2 className="w-5 h-5 animate-spin" /> Connecting…</>
              : <><Zap className="w-5 h-5" /> Connect Wallet</>
            }
          </button>
        </section>

        {/* ── FOOTER ── */}
        <footer className="border-t border-white/5 py-8 text-center text-[10px] text-gray-600 font-fira">
          AUDITX PROTOCOL v2 · DECENTRALIZED SMART CONTRACT SECURITY ·{' '}
          <a href="https://github.com/akhilmuvva/auditX" target="_blank" rel="noreferrer"
            className="text-indigo-500 hover:text-indigo-300 transition-colors">
            OPEN SOURCE
          </a>
        </footer>
      </main>
    </div>
  );
};
