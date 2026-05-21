import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useAuditStore } from '../store/useAuditStore';
import { useCyberSynth } from '../hooks/useCyberSynth';
import { CallGraph } from './CallGraph';
import { BadgeViewer } from './BadgeViewer';
import { FindingsList } from './FindingsList';
import { PipelineTracker } from './PipelineTracker';
import { Play, RotateCcw, Upload, FileCode, AlertCircle } from 'lucide-react';
import { useSkyper } from '../hooks/useSkyper';

/* ─── Terminal Line with Skyper decode effect ─── */
const TerminalLine = ({ log }: { log: { type: string; text: string } }) => {
  const { displayedText, startDecoding } = useSkyper(log.text, { duration: 500, fps: 60 });
  useEffect(() => { startDecoding(); }, []);
  const colorClass =
    log.type === 'success' ? 'text-emerald-400' :
    log.type === 'warning'  ? 'text-amber-400'  :
    log.type === 'error'    ? 'text-rose-500'   :
    'text-indigo-400';
  return (
    <div className="flex gap-1.5 leading-relaxed align-top">
      <span className="text-gray-600 select-none">»</span>
      <span className={`${colorClass} whitespace-pre-wrap break-all`}>{displayedText}</span>
    </div>
  );
};

/* ─── Main Component ─── */
export const LiveAuditSimulator: React.FC = () => {
  const {
    code, filename,
    simStatus, currentStep, connectorWidth,
    terminalLogs, report,
    setCode, setFilename,
    startLiveAudit, resetSimulator,
  } = useAuditStore();

  const { playHover, playClick, startScanHum, stopScanHum, playAlertChime } = useCyberSynth();
  const terminalEndRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  /* Auto-scroll terminal */
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  /* Scan hum sound */
  useEffect(() => {
    if (simStatus === 'RUNNING') startScanHum();
    else stopScanHum();
    return () => stopScanHum();
  }, [simStatus]);

  /* Play chime on complete */
  useEffect(() => {
    if (simStatus === 'COMPLETED' && report) playAlertChime(report.status);
  }, [simStatus]);

  /* ─── File Loading ─── */
  const loadFile = useCallback((file: File) => {
    if (!file.name.endsWith('.sol')) {
      alert('Only .sol (Solidity) files are supported.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setCode(text);
      setFilename(file.name);
      resetSimulator();
    };
    reader.readAsText(file);
  }, [setCode, setFilename, resetSimulator]);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) { playClick(); loadFile(file); }
    e.target.value = '';
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) { playClick(); loadFile(file); }
  };

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = () => setIsDragging(false);

  /* ─── Run / Reset ─── */
  const handleRun = () => { playClick(); startLiveAudit(); };
  const handleReset = () => { playClick(); resetSimulator(); };

  const lineCount = code.split('\n').length;
  const lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1);
  const isRunning = simStatus === 'RUNNING';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mt-4 animate-[fadeIn_0.4s_ease-out]">

      {/* ── LEFT PANEL: Code Editor + Upload (5 cols) ── */}
      <div className="lg:col-span-5 flex flex-col gap-4">

        {/* Upload Bar */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          className={`relative flex items-center gap-3 px-4 py-3 rounded-xl border transition-all duration-300 cursor-pointer
            ${isDragging
              ? 'border-cyan-400 bg-cyan-400/10 shadow-glow-cyan'
              : 'border-white/10 bg-white/[0.03] hover:border-cyan-400/40 hover:bg-white/[0.05]'
            }`}
          onClick={() => { playClick(); fileInputRef.current?.click(); }}
        >
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 transition-colors duration-300 ${isDragging ? 'bg-cyan-400/20 text-cyan-400' : 'bg-white/5 text-gray-400'}`}>
            <Upload className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <p className="text-xs font-bold text-gray-200 font-outfit truncate">
              {filename !== 'MyContract.sol' ? filename : 'Upload .sol Contract'}
            </p>
            <p className="text-[10px] text-gray-500 font-fira">
              {isDragging ? 'Drop to load' : 'Click to browse or drag & drop .sol file'}
            </p>
          </div>
          {filename !== 'MyContract.sol' && (
            <div className="ml-auto flex-shrink-0">
              <span className="text-[9px] font-bold px-2 py-0.5 rounded border border-emerald-400/30 bg-emerald-500/10 text-emerald-400 font-fira uppercase">
                Loaded
              </span>
            </div>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".sol"
            className="hidden"
            onChange={handleFileInput}
          />
        </div>

        {/* Code Editor */}
        <div className="bg-cyber-card border border-white/5 rounded-2xl overflow-hidden flex flex-col h-[460px] backdrop-blur-md relative group">

          {/* Scan scanline */}
          {isRunning && (
            <div className="absolute top-0 left-0 w-full h-[6px] editor-scanline z-20 pointer-events-none animate-[scanning_2.2s_linear_infinite]" />
          )}

          {/* Editor header */}
          <div className="bg-cyber-dark/60 border-b border-white/5 px-5 py-3 flex justify-between items-center z-10">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              </div>
              <span className="text-[10px] text-gray-400 font-fira ml-2 truncate max-w-[180px]">{filename}</span>
            </div>
            <span className="text-[10px] text-gray-500 font-fira">
              {lineCount} lines · Solidity
            </span>
          </div>

          {/* Code area */}
          <div className="flex-1 flex overflow-hidden font-fira text-xs relative">
            <div className="w-12 bg-black/20 border-r border-white/5 text-right pr-3 select-none text-gray-600 leading-normal py-5 flex flex-col overflow-hidden">
              {lineNumbers.map((num) => (
                <div key={num}>{num}</div>
              ))}
            </div>
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              disabled={isRunning}
              spellCheck={false}
              placeholder="// Paste your Solidity code here or upload a .sol file above..."
              className="flex-1 bg-transparent text-gray-300 p-5 outline-none resize-none leading-normal overflow-y-auto whitespace-pre font-fira tracking-wide focus:text-white placeholder:text-gray-600"
            />
          </div>

          {/* Editor footer / action bar */}
          <div className="bg-cyber-dark/60 border-t border-white/5 px-5 py-3.5 flex justify-between items-center z-10">
            <div className="flex items-center gap-2">
              {simStatus === 'ERROR' && (
                <span className="flex items-center gap-1.5 text-[10px] text-rose-400 font-fira">
                  <AlertCircle className="w-3.5 h-3.5" /> Backend offline
                </span>
              )}
              {simStatus === 'COMPLETED' && (
                <span className="text-[10px] text-emerald-400 font-fira font-bold">✓ Audit complete</span>
              )}
            </div>

            <div className="flex gap-3">
              {simStatus !== 'IDLE' && (
                <button
                  onClick={handleReset}
                  onMouseEnter={playHover}
                  className="bg-white/5 hover:bg-white/10 text-gray-300 p-2.5 rounded-xl border border-white/5 transition-all duration-300"
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              )}
              <button
                onClick={handleRun}
                disabled={isRunning}
                onMouseEnter={playHover}
                className="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:to-indigo-600 border border-indigo-400/25 text-white font-bold py-2.5 px-6 rounded-xl hover:-translate-y-0.5 hover:shadow-glow-indigo transition-all duration-300 flex items-center gap-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Play className="w-4 h-4 fill-white" />
                <span className="text-xs font-outfit">{isRunning ? 'Auditing…' : 'Run Live Audit'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Backend info panel */}
        {simStatus === 'IDLE' && (
          <div className="bg-indigo-500/5 border border-indigo-400/10 rounded-xl px-4 py-3 flex items-start gap-3">
            <FileCode className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-[10px] font-bold text-indigo-300 font-outfit uppercase tracking-wider">Live Mode Active</p>
              <p className="text-[10px] text-gray-500 font-fira mt-0.5 leading-relaxed">
                Start the backend: <span className="text-indigo-400">node dist/cli.js --server</span><br/>
                Then upload any .sol file — results are real Slither + AI outputs.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* ── RIGHT PANEL: Pipeline + Console (7 cols) ── */}
      <div className="lg:col-span-7 flex flex-col gap-6">
        <PipelineTracker simStatus={simStatus} currentStep={currentStep} connectorWidth={connectorWidth} />

        {/* Console Terminal */}
        <div className="bg-[#030305] border border-white/5 rounded-xl p-5 h-[280px] flex flex-col overflow-hidden shadow-inner">
          <div className="flex justify-between items-center text-[10px] text-gray-500 font-bold uppercase font-fira pb-3 border-b border-white/5 mb-3">
            <span className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-emerald-400 animate-ping' : 'bg-gray-600'}`} />
              LIVE CONSOLE
            </span>
            <span className={`px-2 py-0.5 rounded border text-[9px] font-bold font-fira ${
              simStatus === 'RUNNING' ? 'text-amber-400 border-amber-400/20 bg-amber-500/5 animate-pulse' :
              simStatus === 'COMPLETED' ? 'text-emerald-400 border-emerald-400/20 bg-emerald-500/5' :
              simStatus === 'ERROR' ? 'text-rose-400 border-rose-400/20 bg-rose-500/5' :
              'text-gray-500 border-white/5 bg-cyber-dark'
            }`}>{simStatus}</span>
          </div>
          <div className="flex-1 overflow-y-auto pr-1 flex flex-col gap-2 font-fira text-xs scroll-smooth">
            {terminalLogs.map((log, idx) => (
              <TerminalLine key={idx} log={log} />
            ))}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </div>

      {/* ── LOWER: Findings + Badge (after completion) ── */}
      {simStatus === 'COMPLETED' && report && (
        <div className="lg:col-span-12 grid grid-cols-1 gap-8 animate-[fadeIn_0.5s_cubic-bezier(0.16,1,0.3,1)_forwards]">

          {/* Call Graph */}
          {report.graphNodes.length > 0 && (
            <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
              <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-cyan-400">
                Surya AST Function Mappings
              </h3>
              <div className="h-[300px] w-full">
                <CallGraph nodes={report.graphNodes} edges={report.graphEdges} />
              </div>
            </div>
          )}

          {/* Badge */}
          <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
            <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-emerald-400">
              Attestation Badge Matrix
            </h3>
            <BadgeViewer report={report} templateName={filename.replace('.sol', '')} />
          </div>

          {/* Findings */}
          <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-gray-300 font-outfit uppercase tracking-widest pl-2 border-l border-rose-500">
                Deep Telemetry Findings
              </h3>
              <div className="flex gap-3 text-[10px] font-bold font-fira">
                {report.critical > 0 && <span className="text-rose-400 border border-rose-500/25 bg-rose-500/10 px-2 py-0.5 rounded">{report.critical} CRITICAL</span>}
                {report.high > 0 && <span className="text-amber-400 border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 rounded">{report.high} HIGH</span>}
                {report.medium > 0 && <span className="text-indigo-400 border border-indigo-500/25 bg-indigo-500/10 px-2 py-0.5 rounded">{report.medium} MEDIUM</span>}
                {report.critical === 0 && report.high === 0 && (
                  <span className="text-emerald-400 border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 rounded">✓ NO CRITICAL ISSUES</span>
                )}
              </div>
            </div>
            {report.findings.length > 0 ? (
              <FindingsList findings={report.findings} />
            ) : (
              <div className="text-center py-12 text-gray-500 font-outfit text-sm">
                No vulnerabilities detected. Contract appears safe.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
