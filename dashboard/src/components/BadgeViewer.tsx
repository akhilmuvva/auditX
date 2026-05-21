import React, { useEffect, useRef, useState } from 'react';
import type { SimulatorReport } from '../store/constants';
import { ShieldCheck, AlertTriangle, AlertCircle, ChevronRight, Share2 } from 'lucide-react';
import { useSkyper } from '../hooks/useSkyper';
import { useAnime } from '../hooks/useAnime';

interface BadgeViewerProps {
  report: SimulatorReport | null;
  templateName: string;
}

export const BadgeViewer: React.FC<BadgeViewerProps> = ({ report, templateName }) => {
  const cardRef = useRef<HTMLDivElement | null>(null);
  const [tilt, setTilt] = useState({ rx: 0, ry: 0, mx: '50%', my: '50%' });

  const easSkyper = useSkyper(report?.easTx || '', { duration: 1500, delay: 600 });
  const ipfsSkyper = useSkyper(report?.ipfs || '', { duration: 1500, delay: 800 });

  useEffect(() => {
    if (report) {
      easSkyper.startDecoding();
      ipfsSkyper.startDecoding();
    }
  }, [report]);

  useAnime({
    targets: cardRef.current,
    translateY: [50, 0],
    opacity: [0, 1],
    scale: [0.9, 1.03],
    easing: 'easeOutExpo',
    duration: 1200,
    delay: 200
  }, [report]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center bg-cyber-card border border-white/5 rounded-2xl backdrop-blur-md">
        <ShieldCheck className="w-12 h-12 text-gray-600 mb-4 animate-pulse opacity-40" />
        <h3 className="text-sm font-bold text-gray-400 font-outfit">Waiting for Telemetry Seal</h3>
        <p className="text-xs text-gray-500 mt-1 max-w-[240px] leading-relaxed font-outfit">
          Sealed proof badges are dynamically minted when compiler processes and scanner constraints successfully complete.
        </p>
      </div>
    );
  }

  // Calculate 3D Hover Tilt Coordinates
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const card = cardRef.current;
    if (!card) return;

    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const tiltX = (centerY - y) / 10;
    const tiltY = (x - centerX) / 10;

    setTilt({
      rx: tiltX,
      ry: tiltY,
      mx: `${(x / rect.width) * 100}%`,
      my: `${(y / rect.height) * 100}%`,
    });
  };

  const handleMouseLeave = () => {
    setTilt({ rx: 0, ry: 0, mx: '50%', my: '50%' });
  };

  const getStatusIcon = () => {
    switch (report.status) {
      case 'safe': return <ShieldCheck className="w-8 h-8 text-emerald-400" />;
      case 'warning': return <AlertTriangle className="w-8 h-8 text-amber-400" />;
      case 'danger': return <AlertCircle className="w-8 h-8 text-rose-500 animate-pulse" />;
    }
  };

  const getStatusColorClass = () => {
    switch (report.status) {
      case 'safe': return 'text-emerald-400 border-emerald-400/30 bg-emerald-500/10 shadow-glow-emerald';
      case 'warning': return 'text-amber-400 border-amber-400/30 bg-amber-500/10 shadow-glow-amber';
      case 'danger': return 'text-rose-400 border-rose-500/30 bg-rose-500/10 shadow-glow-rose';
    }
  };

  const getBadgeTag = () => {
    switch (report.status) {
      case 'safe': return 'SECURED';
      case 'warning': return 'WARNING';
      case 'danger': return 'DANGER';
    }
  };

  const fileName =
    templateName === 'vault'
      ? 'VulnerableVault.sol'
      : templateName === 'borrower'
      ? 'FlashLoanReceiver.sol'
      : 'SecureStaking.sol';

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 w-full mt-4 p-1 animate-[fadeIn_0.4s_ease-out]">
      {/* Left Column: 3D Holographic Card Panel */}
      <div className="flex flex-col items-center justify-center py-4 perspective-[1000px]">
        <div
          ref={cardRef}
          className={`relative w-[280px] h-[390px] rounded-3xl p-6 flex flex-col justify-between overflow-hidden cursor-grab active:cursor-grabbing select-none transition-all duration-150 border backdrop-blur-xl shadow-2xl ${
            report.status === 'safe'
              ? 'border-emerald-400/40 shadow-[0_30px_60px_rgba(0,0,0,0.6),0_0_30px_rgba(16,185,129,0.15)]'
              : report.status === 'warning'
              ? 'border-amber-400/40 shadow-[0_30px_60px_rgba(0,0,0,0.6),0_0_30px_rgba(245,158,11,0.15)]'
              : 'border-rose-400/40 shadow-[0_30px_60px_rgba(0,0,0,0.6),0_0_30px_rgba(244,63,94,0.15)]'
          }`}
          style={{
            transform: `rotateX(${tilt.rx}deg) rotateY(${tilt.ry}deg) scale(1.03)`,
            transformStyle: 'preserve-3d',
            background: 'linear-gradient(135deg, rgba(20, 24, 45, 0.9) 0%, rgba(10, 11, 20, 0.95) 100%)',
          }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          {/* Reflective dynamic glare */}
          <div
            className="absolute inset-0 pointer-events-none z-20 transition-opacity duration-300 rounded-3xl"
            style={{
              background: `radial-gradient(circle at ${tilt.mx} ${tilt.my}, rgba(255, 255, 255, 0.14) 0%, transparent 60%)`,
            }}
          />

          {/* Runic Circuit background pattern */}
          <div className="absolute inset-0 opacity-[0.06] bg-cover z-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-indigo-500 via-purple-500 to-transparent" />

          {/* Glowing particle stars */}
          <div
            className="absolute inset-0 opacity-[0.25] pointer-events-none z-1"
            style={{
              background: `
                radial-gradient(1px 1px at 20px 40px, #fff, transparent),
                radial-gradient(1.5px 1.5px at 90px 170px, #fff, transparent),
                radial-gradient(1px 1px at 210px 90px, #fff, transparent),
                radial-gradient(2px 2px at 240px 310px, #fff, transparent)
              `,
            }}
          />

          {/* Colored blur spotlight */}
          <div
            className={`absolute w-36 h-36 rounded-full top-[100px] left-[70px] filter blur-[45px] opacity-[0.2] z-0 pointer-events-none ${
              report.status === 'safe'
                ? 'bg-emerald-400'
                : report.status === 'warning'
                ? 'bg-amber-400'
                : 'bg-rose-500'
            }`}
          />

          {/* Card Header */}
          <div className="z-10 flex justify-between items-center" style={{ transform: 'translateZ(30px)' }}>
            <span className="text-[10px] text-gray-400 font-bold tracking-widest font-fira">AUDITX BADGE</span>
            <span
              className={`text-[8px] font-black px-2 py-0.5 rounded border font-fira tracking-widest ${
                report.status === 'safe'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : report.status === 'warning'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
              }`}
            >
              {getBadgeTag()}
            </span>
          </div>

          {/* Card Body Medallion */}
          <div className="z-10 flex flex-col items-center gap-4 my-2" style={{ transform: 'translateZ(50px)' }}>
            <div className="relative w-32 h-32 flex items-center justify-center select-none pointer-events-none">
              {/* Outer rotating ring */}
              <svg className="absolute w-[124px] h-[124px] animate-[spin_12s_linear_infinite]" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="45"
                  stroke={
                    report.status === 'safe'
                      ? 'rgba(16, 185, 129, 0.35)'
                      : report.status === 'warning'
                      ? 'rgba(245, 158, 11, 0.35)'
                      : 'rgba(244, 63, 94, 0.35)'
                  }
                  strokeWidth="1"
                  fill="none"
                  strokeDasharray="4 8 16 8"
                />
              </svg>

              {/* Middle rotating runic border */}
              <svg className="absolute w-24 h-24 animate-[spin_8s_linear_infinite_reverse]" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  stroke={
                    report.status === 'safe'
                      ? 'rgba(16, 185, 129, 0.2)'
                      : report.status === 'warning'
                      ? 'rgba(245, 158, 11, 0.2)'
                      : 'rgba(244, 63, 94, 0.2)'
                  }
                  strokeWidth="1.5"
                  fill="none"
                  strokeDasharray="1 14 6 14"
                />
              </svg>

              {/* Main SVG Shield */}
              <svg
                className={`w-20 h-20 fill-none filter drop-shadow-[0_4px_12px_rgba(0,0,0,0.5)] ${
                  report.status === 'safe'
                    ? 'stroke-emerald-400'
                    : report.status === 'warning'
                    ? 'stroke-amber-400'
                    : 'stroke-rose-500'
                }`}
                viewBox="0 0 24 24"
                strokeWidth="1.5"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>

              {/* Dynamic Center Icon overlay */}
              <div className="absolute flex items-center justify-center">
                {getStatusIcon()}
              </div>
            </div>

            <div className="text-center">
              <h4 className="text-sm font-bold text-gray-100 font-outfit select-none">{report.badgeTitle}</h4>
              <p className="text-[9px] text-gray-400 font-bold uppercase tracking-widest font-fira mt-0.5">
                {report.badgeRisk}
              </p>
            </div>
          </div>

          {/* Card Footer Ledger */}
          <div className="z-10 border-t border-white/5 pt-3 grid grid-cols-2 gap-4" style={{ transform: 'translateZ(30px)' }}>
            <div>
              <span className="text-[8px] text-gray-500 font-bold block uppercase font-fira">SECURE TARGET</span>
              <strong className="text-[10px] text-gray-300 font-medium font-fira truncate block">{fileName}</strong>
            </div>
            <div>
              <span className="text-[8px] text-gray-500 font-bold block uppercase font-fira">STORAGE CID</span>
              <strong className="text-[10px] text-gray-300 font-medium font-fira truncate block">
                {report.ipfs.substring(0, 10)}...
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* Right Column: Ledger Proofs & Telemetry Accordions */}
      <div className="flex flex-col justify-between py-2">
        <div className="space-y-5">
          <div className="flex justify-between items-start">
            <div>
              <h3 className="text-lg font-bold text-gray-200 font-outfit">On-Chain Evidence Ledger</h3>
              <p className="text-xs text-gray-400 mt-0.5 font-outfit">
                Attestations and cryptographic proofs minted during this session.
              </p>
            </div>

            <div className={`flex flex-col items-center justify-center w-16 h-16 rounded-2xl border ${getStatusColorClass()}`}>
              <span className="text-xl font-bold font-fira leading-none">{report.score}</span>
              <span className="text-[7px] font-bold text-gray-300 font-fira uppercase tracking-widest mt-1">CVSS</span>
            </div>
          </div>

          {/* Sealed Signatures block */}
          <div className="bg-black/40 border border-white/5 rounded-2xl p-5 space-y-4 font-fira">
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500 font-bold">EAS SEAL UID:</span>
              <code className="text-purple-400 font-bold">{easSkyper.displayedText.length > 20 ? easSkyper.displayedText.substring(0, 12) + '...' + easSkyper.displayedText.substring(easSkyper.displayedText.length - 12) : easSkyper.displayedText}</code>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500 font-bold">IPFS METADATA:</span>
              <code className="text-cyan-400 font-bold">{ipfsSkyper.displayedText.length > 20 ? ipfsSkyper.displayedText.substring(0, 12) + '...' + ipfsSkyper.displayedText.substring(ipfsSkyper.displayedText.length - 12) : ipfsSkyper.displayedText}</code>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500 font-bold">NETWORK ANCHOR:</span>
              <span className="text-gray-300">{report.network}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-500 font-bold">ERC-721 REGISTRY:</span>
              <span className="text-emerald-400 font-bold">#2847 MINTED</span>
            </div>
          </div>

          {/* Gas & P2P consensus telemetries */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-white/5 border border-white/5 rounded-2xl p-4 flex flex-col justify-between">
              <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider font-fira">
                GAS CONSUMPTION
              </span>
              <div className="flex items-baseline gap-1.5 mt-2">
                <span className="text-xl font-black text-gray-200 font-fira">48,290</span>
                <span className="text-[9px] text-gray-400 font-bold uppercase font-fira">GWEI</span>
              </div>
            </div>

            <div className="bg-white/5 border border-white/5 rounded-2xl p-4 flex flex-col justify-between">
              <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider font-fira">
                P2P CONSENSUS
              </span>
              <div className="flex items-baseline gap-1.5 mt-2">
                <span className="text-xl font-black text-emerald-400 font-fira">100%</span>
                <span className="text-[9px] text-gray-400 font-bold uppercase font-fira">PROOF</span>
              </div>
            </div>
          </div>
        </div>

        {/* Dynamic Action Buttons */}
        <div className="flex gap-4 mt-6">
          <button className="flex-1 bg-cyber-indigo text-white font-bold py-3 px-6 rounded-xl hover:-translate-y-0.5 hover:shadow-glow-indigo transition-all duration-300 flex items-center justify-center gap-2 border border-indigo-400/25 bg-gradient-to-r from-indigo-600 to-indigo-700">
            <Share2 className="w-4 h-4" />
            <span className="text-sm font-outfit">Export NFT Metadata</span>
          </button>

          <a
            href={`https://ipfs.io/ipfs/${report.ipfs}`}
            target="_blank"
            rel="noreferrer"
            className="flex-1 bg-white/5 hover:bg-white/10 text-gray-200 font-bold py-3 px-6 rounded-xl border border-white/5 transition-all duration-300 flex items-center justify-center gap-2 text-center"
          >
            <span className="text-sm font-outfit">View JSON Report</span>
            <ChevronRight className="w-4 h-4" />
          </a>
        </div>
      </div>
    </div>
  );
};
