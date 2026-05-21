import React, { useEffect, useRef } from 'react';
import { Cpu, FileCode, AlertTriangle, Shield, CheckCircle, Search, Server, Key } from 'lucide-react';
import { useAnime } from '../hooks/useAnime';

interface PipelineTrackerProps {
  simStatus: string;
  currentStep: number;
  connectorWidth: number;
}

export const PipelineTracker: React.FC<PipelineTrackerProps> = ({ simStatus, currentStep, connectorWidth }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  const steps = [
    { label: 'AST Build', icon: FileCode, details: 'solc pipeline' },
    { label: 'Static Scan', icon: Search, details: 'slither engine' },
    { label: 'Symbolic', icon: Cpu, details: 'mythril solver' },
    { label: 'Heuristics', icon: AlertTriangle, details: 'threat mapping' },
    { label: 'AI Triage', icon: Server, details: 'claude sonnet' },
    { label: 'IPFS Pin', icon: Shield, details: 'storage layer' },
    { label: 'EAS Attest', icon: Key, details: 'on-chain proof' },
    { label: 'NFT Mint', icon: CheckCircle, details: 'badge sealed' },
  ];

  useAnime({
    targets: '.pipeline-node',
    scale: [0, 1],
    opacity: [0, 1],
    delay: (el: any, i: number) => i * 100,
    easing: 'spring(1, 80, 10, 0)',
  }, []);

  const getStepNodeClass = (idx: number) => {
    if (currentStep > idx) return 'border-emerald-400 bg-cyber-card text-emerald-400 shadow-glow-emerald';
    if (currentStep === idx) return 'border-cyan-400 bg-cyber-cardHover text-cyan-400 shadow-glow-cyan animate-pulse';
    return 'border-white/5 bg-cyber-dark text-gray-500';
  };

  return (
    <div ref={containerRef} className="bg-cyber-card border border-white/5 rounded-2xl p-6 backdrop-blur-md flex flex-col gap-5">
      <div className="flex justify-between items-center">
        <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-cyan-400">
          8-Step Execution Pipeline
        </h3>
        <span
          className={`text-[9px] font-bold px-2 py-0.5 rounded-md border font-fira tracking-widest ${
            simStatus === 'RUNNING'
              ? 'text-amber-400 border-amber-400/20 bg-amber-500/5 animate-pulse'
              : simStatus === 'COMPLETED'
              ? 'text-emerald-400 border-emerald-400/20 bg-emerald-500/5'
              : 'text-gray-500 border-white/5 bg-cyber-dark'
          }`}
        >
          {simStatus}
        </span>
      </div>

      <div className="relative grid grid-cols-4 lg:grid-cols-8 gap-2 select-none mt-2">
        <div className="absolute top-[21px] left-[6%] right-[6%] h-0.5 bg-white/5 z-0">
          <div
            className="h-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-emerald-400 shadow-[0_0_8px_rgba(99,102,241,0.5)] transition-all duration-500"
            style={{ width: \`\${connectorWidth}%\` }}
          />
        </div>

        {steps.map((node, idx) => {
          const Icon = node.icon;
          return (
            <div key={idx} className="pipeline-node relative z-10 flex flex-col items-center gap-2 opacity-0">
              <div
                className={\`w-10 h-10 rounded-full border flex items-center justify-center transition-all duration-500 \${getStepNodeClass(idx)}\`}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div className="text-center">
                <span className="text-[9px] text-gray-200 font-bold block font-outfit whitespace-nowrap">{node.label}</span>
                <span className="text-[7px] text-gray-500 block uppercase font-fira tracking-tighter whitespace-nowrap">{node.details}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
