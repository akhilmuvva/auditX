import React, { useRef, useState, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';
import { useAnime } from '../hooks/useAnime';

interface Finding {
  severity: string;
  title: string;
  tool: string;
  desc: string;
  loc: string;
  vulnCode: string;
  fixCode: string;
}

export const FindingsList: React.FC<{ findings: Finding[] }> = ({ findings }) => {
  const [openFindingIdx, setOpenFindingIdx] = useState<number | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useAnime({
    targets: '.finding-stagger-item',
    translateY: [20, 0],
    opacity: [0, 1],
    easing: 'easeOutExpo',
    duration: 800,
    delay: (el: any, i: number) => i * 150
  }, [findings]);

  return (
    <div className="flex flex-col gap-4" ref={containerRef}>
      {findings.map((finding, idx) => (
        <div key={idx} className="finding-stagger-item border border-white/5 rounded-2xl overflow-hidden bg-white/[0.01] opacity-0">
          <div
            className="px-6 py-4 flex justify-between items-center cursor-pointer select-none hover:bg-white/[0.02] transition-colors duration-200"
            onClick={() => setOpenFindingIdx(openFindingIdx === idx ? null : idx)}
          >
            <div className="flex items-center gap-4">
              <span
                className={`text-[9px] font-black px-2.5 py-0.5 rounded border font-fira tracking-widest uppercase ${
                  finding.severity === 'critical'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                    : finding.severity === 'high'
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                    : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/25'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-bold text-gray-200 font-outfit leading-none">{finding.title}</span>
            </div>

            <div className="flex items-center gap-4">
              <span className="text-[10px] text-gray-500 font-bold font-fira uppercase">{finding.tool}</span>
              <ChevronDown
                className={`w-4 h-4 text-gray-500 transition-transform duration-300 ${
                  openFindingIdx === idx ? 'rotate-180 text-gray-200' : ''
                }`}
              />
            </div>
          </div>

          {/* Accordion Body Comparative Diffs */}
          {openFindingIdx === idx && (
            <div className="px-6 pb-6 pt-2 border-t border-white/5 bg-black/25 flex flex-col gap-4 animate-[fadeIn_0.3s_ease-out]">
              <div className="text-xs text-gray-400 leading-relaxed font-outfit mt-2">{finding.desc}</div>
              <div className="text-[10px] text-indigo-400 font-bold font-fira bg-indigo-500/5 border border-indigo-500/10 rounded-lg px-3 py-1.5 w-fit">
                📍 Location: {finding.loc}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-2">
                {/* Vulnerable block */}
                <div className="bg-[#0b0406] border border-rose-950/40 rounded-xl overflow-hidden font-fira">
                  <div className="bg-rose-500/5 px-4 py-2 border-b border-rose-950/40 text-[9px] font-bold text-rose-400 uppercase tracking-widest">
                    VULNERABLE CODE BLOCK
                  </div>
                  <pre className="p-4 text-xs text-rose-300 overflow-x-auto whitespace-pre leading-normal">
                    <code>{finding.vulnCode}</code>
                  </pre>
                </div>

                {/* Remediated Block */}
                <div className="bg-[#040806] border border-emerald-950/40 rounded-xl overflow-hidden font-fira">
                  <div className="bg-emerald-500/5 px-4 py-2 border-b border-emerald-950/40 text-[9px] font-bold text-emerald-400 uppercase tracking-widest">
                    REMEDIATION PATCH
                  </div>
                  <pre className="p-4 text-xs text-emerald-300 overflow-x-auto whitespace-pre leading-normal">
                    <code>{finding.fixCode}</code>
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};
