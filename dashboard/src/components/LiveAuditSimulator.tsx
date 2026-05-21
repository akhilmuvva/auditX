import React, { useEffect, useRef, useState } from 'react';
import { useAuditStore } from '../store/useAuditStore';
import { useCyberSynth } from '../hooks/useCyberSynth';
import { CallGraph } from './CallGraph';
import { BadgeViewer } from './BadgeViewer';
import { FindingsList } from './FindingsList';
import { PipelineTracker } from './PipelineTracker';
import { Play, RotateCcw, AlertTriangle, Cpu, Shield, FileCode, ChevronDown } from 'lucide-react';
import { useSkyper } from '../hooks/useSkyper';
import { useAnime } from '../hooks/useAnime';

const TerminalLine = ({ log }: { log: { type: string, text: string } }) => {
  const { displayedText, startDecoding } = useSkyper(log.text, { duration: 600, fps: 60 });
  
  useEffect(() => {
    startDecoding();
  }, []);

  const colorClass =
    log.type === 'system'
      ? 'text-indigo-400'
      : log.type === 'success'
      ? 'text-emerald-400'
      : log.type === 'warning'
      ? 'text-amber-400'
      : 'text-rose-500';

  return (
    <div className="flex gap-1.5 leading-relaxed align-top">
      <span className="text-gray-600 select-none">»</span>
      <span className={`${colorClass} whitespace-pre-wrap`}>{displayedText}</span>
    </div>
  );
};

export const LiveAuditSimulator: React.FC = () => {
  const {
    selectedTemplate,
    code,
    simStatus,
    currentStep,
    connectorWidth,
    terminalLogs,
    report,
    setTemplate,
    setCode,
    startSimulation,
    resetSimulator,
  } = useAuditStore();

  const { playHover, playClick, startScanHum, stopScanHum, playAlertChime } = useCyberSynth();
  const terminalEndRef = useRef<HTMLDivElement | null>(null);
  const [openFindingIdx, setOpenFindingIdx] = useState<number | null>(null);

  // Auto scroll logs
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs]);

  // Manage Scan Sound Hum
  useEffect(() => {
    if (simStatus === 'RUNNING') {
      startScanHum();
    } else {
      stopScanHum();
    }
    return () => stopScanHum();
  }, [simStatus, startScanHum, stopScanHum]);

  const handleStartAudit = () => {
    playClick();
    startSimulation(
      (_type, _text) => {
        // Option to trigger click on log tick for extra texture
      },
      (completedReport) => {
        // Audit completed successfully
        playAlertChime(completedReport.status);
      }
    );
  };

  const handleReset = () => {
    playClick();
    resetSimulator();
    setOpenFindingIdx(null);
  };

  const handleTemplateChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    playClick();
    setTemplate(e.target.value as 'vault' | 'borrower' | 'staking');
    setOpenFindingIdx(null);
  };

  const getStepNodeClass = (idx: number) => {
    if (currentStep > idx) return 'border-emerald-400 bg-cyber-card text-emerald-400 shadow-glow-emerald';
    if (currentStep === idx) return 'border-cyan-400 bg-cyber-cardHover text-cyan-400 shadow-glow-cyan animate-pulse';
    return 'border-white/5 bg-cyber-dark text-gray-500';
  };

  const getStepIcon = (idx: number) => {
    const props = { className: "w-4 h-4" };
    switch (idx) {
      case 0: return <FileCode {...props} />;
      case 1: return <Cpu {...props} />;
      case 2: return <AlertTriangle {...props} />;
      case 3: return <Shield {...props} />;
      default: return <FileCode {...props} />;
    }
  };

  const lineCount = code.split('\n').length;
  const lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mt-4 animate-[fadeIn_0.4s_ease-out]">
      {/* ── LEFT PANEL: Code Editor & Selector (5 Columns) ── */}
      <div className="lg:col-span-5 flex flex-col gap-6">
        <div className="bg-cyber-card border border-white/5 rounded-2xl overflow-hidden flex flex-col h-[520px] backdrop-blur-md relative group">
          
          {/* Holographic Laser Scanline when Scanning */}
          {simStatus === 'RUNNING' && (
            <div className="absolute top-0 left-0 w-full h-[6px] editor-scanline z-20 pointer-events-none animate-[scanning_2.2s_linear_infinite]" />
          )}

          {/* Editor Header */}
          <div className="bg-cyber-dark/60 border-b border-white/5 px-5 py-3 flex justify-between items-center z-10">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            </div>

            <select
              value={selectedTemplate}
              onChange={handleTemplateChange}
              disabled={simStatus === 'RUNNING'}
              className="bg-white/5 border border-white/5 text-gray-200 text-xs font-semibold px-3 py-1.5 rounded-lg outline-none cursor-pointer hover:bg-white/10 transition-colors duration-200"
            >
              <option value="vault" className="bg-cyber-bg text-gray-300">VulnerableVault.sol (Reentrancy)</option>
              <option value="borrower" className="bg-cyber-bg text-gray-300">FlashLoanReceiver.sol (Callback Bypass)</option>
              <option value="staking" className="bg-cyber-bg text-gray-300">SecureStaking.sol (Audit Cleaned)</option>
            </select>
          </div>

          {/* Editor Body */}
          <div className="flex-1 flex overflow-hidden font-fira text-xs relative">
            {/* Line Gutter */}
            <div className="w-12 bg-black/20 border-r border-white/5 text-right pr-3 select-none text-gray-600 leading-normal py-5 flex flex-col">
              {lineNumbers.map((num) => (
                <div key={num}>{num}</div>
              ))}
            </div>

            {/* Code Content Input Area */}
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              disabled={simStatus === 'RUNNING'}
              className="flex-1 bg-transparent text-gray-300 p-5 outline-none resize-none leading-normal overflow-y-auto whitespace-pre font-fira tracking-wide focus:text-white"
            />
          </div>

          {/* Editor Footer controls */}
          <div className="bg-cyber-dark/60 border-t border-white/5 px-5 py-3.5 flex justify-between items-center z-10">
            <span className="text-[10px] text-gray-500 font-bold uppercase font-fira">
              Lines: {lineCount} · Solidity 0.8.20
            </span>

            <div className="flex gap-3">
              {simStatus !== 'IDLE' && (
                <button
                  onClick={handleReset}
                  className="bg-white/5 hover:bg-white/10 text-gray-300 p-2.5 rounded-xl border border-white/5 transition-all duration-300 flex items-center justify-center gap-2"
                  onMouseEnter={playHover}
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              )}

              <button
                onClick={handleStartAudit}
                disabled={simStatus === 'RUNNING'}
                className="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:to-indigo-600 border border-indigo-400/25 text-white font-bold py-2.5 px-6 rounded-xl hover:-translate-y-0.5 hover:shadow-glow-indigo transition-all duration-300 flex items-center justify-center gap-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
                onMouseEnter={playHover}
              >
                <Play className="w-4 h-4 fill-white" />
                <span className="text-xs font-outfit">Run Secure Audit</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── RIGHT PANEL: Pipeline & Dynamic Accordion Telemetry (7 Columns) ── */}
      <div className="lg:col-span-7 flex flex-col gap-6">
        <PipelineTracker simStatus={simStatus} currentStep={currentStep} connectorWidth={connectorWidth} />

          {/* Typewriter Scrollable Console Terminal */}
          <div className="bg-[#030305] border border-white/5 rounded-xl p-5 h-[230px] flex flex-col overflow-hidden shadow-inner">
            <div className="flex justify-between items-center text-[10px] text-gray-500 font-bold uppercase font-fira pb-3 border-b border-white/5 mb-3">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                CONSOLE LOGGER
              </span>
              <span>TELEMETRY Tele_V1</span>
            </div>

            <div className="flex-1 overflow-y-auto pr-1 flex flex-col gap-2.5 font-fira text-xs scroll-smooth">
              {terminalLogs.map((log, idx) => (
                <TerminalLine key={idx} log={log} />
              ))}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>
      </div>

      {/* ── LOWER SECTION: Dynamic findings & Badge visualization once complete ── */}
      {simStatus === 'COMPLETED' && report && (
        <div className="lg:col-span-12 grid grid-cols-1 gap-8 animate-[fadeIn_0.5s_cubic-bezier(0.16,1,0.3,1)_forwards]">
          
          {/* dynamic call graph */}
          <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-cyan-400">
                Surya AST Function Mappings
              </h3>
              <div className="flex gap-3 text-[9px] font-bold font-fira">
                <span className="flex items-center gap-1.5 text-indigo-400">
                  <span className="w-2 h-2 rounded bg-indigo-500 shadow-glow-indigo" /> ENTRY
                </span>
                <span className="flex items-center gap-1.5 text-rose-400">
                  <span className="w-2 h-2 rounded bg-rose-500 shadow-glow-rose" /> HAZARD
                </span>
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-2 h-2 rounded bg-emerald-500 shadow-glow-emerald" /> INTERNAL
                </span>
              </div>
            </div>

            <div className="h-[340px] w-full">
              <CallGraph nodes={report.graphNodes} edges={report.graphEdges} />
            </div>
          </div>

          {/* on chain dynamic badging */}
          <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
            <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-emerald-400">
              Attestation Badge Matrix
            </h3>
            <BadgeViewer report={report} templateName={selectedTemplate} />
          </div>

          {/* vulnerability accordion detailer */}
          <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
            <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-rose-500 mb-2">
              Deep Telemetry Findings Explorer
            </h3>

            <div className="flex flex-col gap-4">
              <FindingsList findings={report.findings} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
