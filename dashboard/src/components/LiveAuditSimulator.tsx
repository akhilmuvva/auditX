import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useAuditStore, type UploadedFiles } from '../store/useAuditStore';
import { useCyberSynth } from '../hooks/useCyberSynth';
import { BadgeViewer } from './BadgeViewer';
import { FindingsList } from './FindingsList';
import {
  Play, RotateCcw, Upload, FileCode, FileJson,
  Eye, EyeOff, Key, ShieldCheck, ShieldX, AlertTriangle,
  CheckCircle2, Loader2,
} from 'lucide-react';

/* ──────────────────────────────────────────────
   Terminal Line
────────────────────────────────────────────── */
const TerminalLine = ({ log }: { log: { type: string; text: string } }) => {
  const colorClass =
    log.type === 'success' ? 'text-emerald-400' :
    log.type === 'warning'  ? 'text-amber-400'  :
    log.type === 'error'    ? 'text-rose-500'   :
    'text-indigo-300';
  const prefix =
    log.type === 'success' ? '✓' :
    log.type === 'error'   ? '✗' :
    log.type === 'warning' ? '⚠' : '›';
  return (
    <div className="flex gap-2 leading-relaxed font-fira text-xs">
      <span className={`${colorClass} flex-shrink-0`}>{prefix}</span>
      <span className={`${colorClass} whitespace-pre-wrap break-all`}>{log.text}</span>
    </div>
  );
};

/* ──────────────────────────────────────────────
   Upload Dropzone for a single file slot
────────────────────────────────────────────── */
interface DropzoneProps {
  label: string;
  accept: string;
  slot: keyof UploadedFiles;
  loaded: { name: string } | null;
  icon: React.ReactNode;
  hint: string;
  onLoad: (slot: keyof UploadedFiles, file: File) => void;
  onClear: (slot: keyof UploadedFiles) => void;
  disabled?: boolean;
}

const Dropzone: React.FC<DropzoneProps> = ({ label, accept, slot, loaded, icon, hint, onLoad, onClear, disabled }) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleFile = (file: File) => onLoad(slot, file);

  return (
    <div
      onClick={() => !disabled && !loaded && inputRef.current?.click()}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) handleFile(f); }}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      className={`relative flex items-center gap-3 px-4 py-3 rounded-xl border transition-all duration-300 group
        ${disabled ? 'opacity-40 cursor-not-allowed' :
          loaded ? 'border-emerald-400/30 bg-emerald-500/5 cursor-default' :
          dragging ? 'border-cyan-400 bg-cyan-400/10 cursor-pointer' :
          'border-white/10 bg-white/[0.03] hover:border-cyan-400/30 hover:bg-white/[0.05] cursor-pointer'
        }`}
    >
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 transition-colors
        ${loaded ? 'bg-emerald-500/15 text-emerald-400' : 'bg-white/5 text-gray-500'}`}>
        {icon}
      </div>

      <div className="min-w-0 flex-1">
        <p className="text-[11px] font-bold text-gray-200 font-outfit">{label}</p>
        <p className="text-[10px] text-gray-500 font-fira truncate">
          {loaded ? loaded.name : hint}
        </p>
      </div>

      {loaded ? (
        <button
          onClick={(e) => { e.stopPropagation(); onClear(slot); }}
          className="ml-auto text-gray-500 hover:text-rose-400 transition-colors p-1 rounded"
        >
          <RotateCcw className="w-3 h-3" />
        </button>
      ) : (
        <Upload className="w-3.5 h-3.5 text-gray-600 group-hover:text-cyan-400 transition-colors" />
      )}

      <input ref={inputRef} type="file" accept={accept} className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = ''; }}
      />
    </div>
  );
};

/* ──────────────────────────────────────────────
   Result Badge Card
────────────────────────────────────────────── */
const ResultBadge = ({ report }: { report: NonNullable<ReturnType<typeof useAuditStore>['report']> }) => {
  const s = report.analyticsSummary;
  const p = report.onChainPayload;
  const isApproved = s.certificationStatus !== 'DENIED_RISK_TOO_HIGH';
  const score = (s.aggregateCvssScoreRaw / 10).toFixed(1);

  return (
    <div className={`rounded-2xl border p-5 flex flex-col gap-4 backdrop-blur-md ${
      isApproved
        ? 'border-emerald-400/20 bg-emerald-500/5'
        : 'border-rose-500/30 bg-rose-500/5'
    }`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          {isApproved
            ? <ShieldCheck className="w-8 h-8 text-emerald-400" />
            : <ShieldX className="w-8 h-8 text-rose-500" />
          }
          <div>
            <p className={`text-xs font-bold font-outfit tracking-widest uppercase ${isApproved ? 'text-emerald-400' : 'text-rose-400'}`}>
              {s.certificationStatus.replace(/_/g, ' ')}
            </p>
            <p className="text-[10px] text-gray-500 font-fira mt-0.5">
              {s.targetContractName} · {s.compilerTarget}
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-extrabold font-fira ${
            s.riskClassification === 'critical' ? 'text-rose-500' :
            s.riskClassification === 'high'     ? 'text-orange-400' :
            s.riskClassification === 'medium'   ? 'text-amber-400' :
            'text-emerald-400'
          }`}>{score}</div>
          <div className="text-[9px] text-gray-500 font-fira uppercase tracking-wider">CVSS 3.1</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2 text-center">
        {(['critical','high','medium','low'] as const).map(sev => {
          const count = report.vulnerabilities.filter(v => v.severity === sev).length;
          if (count === 0) return null;
          const color = sev === 'critical' ? 'text-rose-400 border-rose-500/20 bg-rose-500/8' :
                        sev === 'high'     ? 'text-orange-400 border-orange-500/20 bg-orange-500/8' :
                        sev === 'medium'   ? 'text-amber-400 border-amber-500/20 bg-amber-500/8' :
                                            'text-sky-400 border-sky-500/20 bg-sky-500/8';
          return (
            <div key={sev} className={`rounded-lg border px-2 py-1.5 ${color}`}>
              <div className="text-lg font-bold font-fira">{count}</div>
              <div className="text-[9px] font-bold uppercase tracking-wider">{sev}</div>
            </div>
          );
        })}
      </div>

      {/* Badge */}
      {isApproved && p.svgProperties.badgeGrade !== 'NULL' && (
        <div className="flex items-center gap-2 bg-white/5 rounded-xl px-4 py-2.5 border border-white/5">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: p.svgProperties.shieldColor }} />
          <span className="text-xs font-bold font-outfit text-gray-200">{p.svgProperties.badgeGrade}</span>
          <span className="text-[9px] text-gray-500 font-fira ml-auto">EAS + NFT ready</span>
        </div>
      )}

      {/* On-chain payload info */}
      <div className="bg-black/20 rounded-xl p-3 font-fira text-[10px] text-gray-500 space-y-1">
        <div className="flex justify-between">
          <span>EAS Severity Score (uint8)</span>
          <span className="text-indigo-400 font-bold">{p.easSchemaVariables.severityScoreUint8}</span>
        </div>
        <div className="flex justify-between">
          <span>IPFS Hash</span>
          <span className="text-indigo-400">{p.easSchemaVariables.ipfsReportHashPlaceholder}</span>
        </div>
      </div>

      {/* Graph Insights */}
      <div className="space-y-2">
        <p className="text-[10px] font-bold text-gray-400 font-outfit uppercase tracking-wider">Surya Graph Topology</p>
        <p className="text-[10px] text-gray-500 font-fira leading-relaxed">{report.graphInsights.suryaCallGraphTopology}</p>
        <p className="text-[10px] font-bold text-gray-400 font-outfit uppercase tracking-wider mt-2">Attack Surface</p>
        <p className="text-[10px] text-gray-500 font-fira leading-relaxed">{report.graphInsights.attackSurfacePerimeter}</p>
      </div>
    </div>
  );
};

/* ──────────────────────────────────────────────
   Main Component
────────────────────────────────────────────── */
export const LiveAuditSimulator: React.FC = () => {
  const {
    files, apiKey, apiKeyVisible,
    simStatus, terminalLogs, report,
    setFile, setApiKey, toggleApiKeyVisible,
    resetAudit, runAudit,
  } = useAuditStore();

  const { playHover, playClick } = useCyberSynth();
  const terminalEndRef = useRef<HTMLDivElement | null>(null);
  const [apiKeyDraft, setApiKeyDraft] = useState(apiKey);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  const readFile = useCallback((slot: keyof UploadedFiles, file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      setFile(slot, { name: file.name, content: e.target?.result as string });
    };
    reader.readAsText(file);
  }, [setFile]);

  const handleSaveKey = () => {
    setApiKey(apiKeyDraft.trim());
    playClick();
  };

  const isRunning = simStatus === 'RUNNING';

  return (
    <div className="flex flex-col gap-6 mt-4 animate-[fadeIn_0.4s_ease-out]">

      {/* ── API KEY SETUP PANEL ── */}
      <div className="bg-cyber-card border border-white/5 rounded-2xl p-5 backdrop-blur-md">
        <div className="flex items-center gap-2 mb-3">
          <Key className="w-4 h-4 text-indigo-400" />
          <span className="text-xs font-bold text-gray-200 font-outfit uppercase tracking-wider">Anthropic API Key</span>
          <span className="ml-auto text-[9px] text-gray-600 font-fira">Stored in your browser only — never transmitted to any server</span>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type={apiKeyVisible ? 'text' : 'password'}
              value={apiKeyDraft}
              onChange={(e) => setApiKeyDraft(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSaveKey()}
              placeholder="sk-ant-api03-..."
              className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-2.5 text-xs text-gray-200 font-fira outline-none focus:border-indigo-400/50 placeholder:text-gray-600 transition-colors pr-10"
            />
            <button
              onClick={toggleApiKeyVisible}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300 transition-colors"
            >
              {apiKeyVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>
          </div>
          <button
            onClick={handleSaveKey}
            onMouseEnter={playHover}
            className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-outfit rounded-xl border border-indigo-400/25 transition-all duration-300 flex items-center gap-2 whitespace-nowrap"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            Save Key
          </button>
        </div>
        {ApiKeyStore.isSet() && (
          <p className="text-[10px] text-emerald-400 font-fira mt-2 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> API key saved in localStorage
          </p>
        )}
      </div>

      {/* ── MAIN GRID ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* LEFT — File Upload Panel (5 cols) */}
        <div className="lg:col-span-5 flex flex-col gap-4">

          <div className="bg-cyber-card border border-white/5 rounded-2xl p-5 backdrop-blur-md flex flex-col gap-3">
            <div className="flex items-center gap-2 mb-1">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-gray-200 font-outfit uppercase tracking-wider">Upload Contract Files</span>
            </div>

            {/* .sol — Required */}
            <Dropzone
              label="Solidity Contract (.sol)"
              accept=".sol"
              slot="sol"
              loaded={files.sol}
              icon={<FileCode className="w-4 h-4" />}
              hint="Required — drag & drop or click to browse"
              onLoad={readFile}
              onClear={(slot) => setFile(slot, null)}
              disabled={isRunning}
            />

            <div className="border-t border-white/5 pt-3">
              <p className="text-[10px] text-gray-500 font-fira mb-2 uppercase tracking-wider">
                Optional — Tool Output JSONs (improves analysis precision)
              </p>

              {/* Slither JSON */}
              <div className="flex flex-col gap-2">
                <Dropzone
                  label="Slither Output (.json)"
                  accept=".json"
                  slot="slither"
                  loaded={files.slither}
                  icon={<FileJson className="w-4 h-4" />}
                  hint="Run: slither contract.sol --json slither.json"
                  onLoad={readFile}
                  onClear={(slot) => setFile(slot, null)}
                  disabled={isRunning}
                />
                <Dropzone
                  label="Mythril Output (.json)"
                  accept=".json"
                  slot="mythril"
                  loaded={files.mythril}
                  icon={<FileJson className="w-4 h-4" />}
                  hint="Run: myth analyze contract.sol -o json"
                  onLoad={readFile}
                  onClear={(slot) => setFile(slot, null)}
                  disabled={isRunning}
                />
                <Dropzone
                  label="Surya Output (.json)"
                  accept=".json"
                  slot="surya"
                  loaded={files.surya}
                  icon={<FileJson className="w-4 h-4" />}
                  hint="Run: surya describe contract.sol > surya.json"
                  onLoad={readFile}
                  onClear={(slot) => setFile(slot, null)}
                  disabled={isRunning}
                />
              </div>
            </div>

            {/* Code preview */}
            {files.sol && (
              <div className="bg-black/30 rounded-xl border border-white/5 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 border-b border-white/5">
                  <span className="text-[10px] font-fira text-gray-400">{files.sol.name}</span>
                  <span className="text-[9px] font-fira text-gray-600">
                    {files.sol.content.split('\n').length} lines
                  </span>
                </div>
                <pre className="text-[10px] font-fira text-gray-400 p-4 max-h-48 overflow-y-auto leading-relaxed whitespace-pre-wrap">
                  {files.sol.content.slice(0, 800)}{files.sol.content.length > 800 ? '\n...' : ''}
                </pre>
              </div>
            )}

            {/* CLI hint */}
            <div className="bg-indigo-500/5 border border-indigo-400/10 rounded-xl px-4 py-3">
              <p className="text-[9px] font-bold text-indigo-400 font-outfit uppercase tracking-wider mb-1">Local CLI Runner</p>
              <p className="text-[10px] text-gray-500 font-fira leading-relaxed">
                Generate tool outputs locally (no server needed):<br />
                <span className="text-indigo-300">node dist/cli.js --target contract.sol</span>
              </p>
            </div>
          </div>

          {/* Run / Reset buttons */}
          <div className="flex gap-3">
            {simStatus !== 'IDLE' && (
              <button
                onClick={() => { playClick(); resetAudit(); }}
                onMouseEnter={playHover}
                disabled={isRunning}
                className="bg-white/5 hover:bg-white/10 text-gray-300 p-3 rounded-xl border border-white/5 transition-all duration-300 disabled:opacity-40"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
            <button
              onClick={() => { playClick(); runAudit(); }}
              disabled={isRunning || !files.sol}
              onMouseEnter={playHover}
              className="flex-1 bg-gradient-to-r from-indigo-600 to-purple-700 hover:from-indigo-500 hover:to-purple-600 border border-indigo-400/25 text-white font-bold py-3 px-6 rounded-xl hover:-translate-y-0.5 hover:shadow-glow-indigo transition-all duration-300 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {isRunning
                ? <><Loader2 className="w-4 h-4 animate-spin" /><span className="text-sm font-outfit">Analyzing…</span></>
                : <><Play className="w-4 h-4 fill-white" /><span className="text-sm font-outfit">Run Decentralized Audit</span></>
              }
            </button>
          </div>
        </div>

        {/* RIGHT — Console Terminal (7 cols) */}
        <div className="lg:col-span-7 flex flex-col gap-4">

          {/* Status indicator */}
          <div className="bg-cyber-card border border-white/5 rounded-2xl px-5 py-3 flex items-center justify-between backdrop-blur-md">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${
                simStatus === 'RUNNING'   ? 'bg-amber-400 animate-ping' :
                simStatus === 'COMPLETED' ? 'bg-emerald-400' :
                simStatus === 'ERROR'     ? 'bg-rose-500' :
                'bg-gray-600'
              }`} />
              <span className="text-xs font-bold font-outfit text-gray-300">
                {simStatus === 'RUNNING'   ? 'AI Analysis Running…' :
                 simStatus === 'COMPLETED' ? 'Audit Complete' :
                 simStatus === 'ERROR'     ? 'Analysis Failed' :
                 'Decentralized Engine Ready'}
              </span>
            </div>
            <div className="flex items-center gap-4 text-[10px] font-fira text-gray-500">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                Zero-Server
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                Browser-Native AI
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                EIP-1193 Wallet
              </span>
            </div>
          </div>

          {/* Terminal */}
          <div className="bg-[#020204] border border-white/5 rounded-2xl p-5 h-[420px] flex flex-col overflow-hidden shadow-inner flex-1">
            <div className="flex justify-between items-center text-[10px] text-gray-500 font-bold uppercase font-fira pb-3 border-b border-white/5 mb-3">
              <span className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-amber-400 animate-ping' : 'bg-gray-600'}`} />
                LIVE AUDIT CONSOLE
              </span>
              <span className="text-[9px] text-gray-600">
                {terminalLogs.length} events
              </span>
            </div>
            <div className="flex-1 overflow-y-auto flex flex-col gap-1.5 scroll-smooth">
              {terminalLogs.map((log, i) => <TerminalLine key={i} log={log} />)}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>
      </div>

      {/* ── RESULTS SECTION ── */}
      {simStatus === 'COMPLETED' && report && (
        <div className="flex flex-col gap-6 animate-[fadeIn_0.5s_ease-out]">

          {/* Summary badge */}
          <ResultBadge report={report} />

          {/* Vulnerability findings */}
          {report.vulnerabilities.length > 0 && (
            <div className="bg-cyber-card border border-white/5 rounded-3xl p-6 backdrop-blur-md">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-gray-200 font-outfit uppercase tracking-widest pl-2 border-l-2 border-rose-500">
                  Vulnerability Findings
                </h3>
                <span className="text-[10px] text-gray-500 font-fira">
                  {report.vulnerabilities.length} issue{report.vulnerabilities.length !== 1 ? 's' : ''} detected
                </span>
              </div>
              <div className="flex flex-col gap-3">
                {report.vulnerabilities.map((v) => (
                  <div key={v.vulnerabilityId} className={`rounded-xl border p-4 ${
                    v.severity === 'critical' ? 'border-rose-500/30 bg-rose-500/5' :
                    v.severity === 'high'     ? 'border-orange-500/30 bg-orange-500/5' :
                    v.severity === 'medium'   ? 'border-amber-500/30 bg-amber-500/5' :
                                               'border-sky-500/20 bg-sky-500/5'
                  }`}>
                    <div className="flex items-start justify-between gap-4 mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-bold font-fira px-2 py-0.5 rounded border ${
                          v.severity === 'critical' ? 'text-rose-400 border-rose-500/30 bg-rose-500/10' :
                          v.severity === 'high'     ? 'text-orange-400 border-orange-500/30 bg-orange-500/10' :
                          v.severity === 'medium'   ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' :
                                                     'text-sky-400 border-sky-500/30 bg-sky-500/10'
                        } uppercase`}>{v.severity}</span>
                        <span className="text-[9px] text-gray-500 font-fira">{v.vulnerabilityId}</span>
                        <span className="text-[9px] text-gray-600 font-fira border border-white/5 px-1.5 py-0.5 rounded">{v.sourceTool}</span>
                      </div>
                      <span className="text-[9px] text-gray-600 font-fira whitespace-nowrap">{v.vulnerabilityLocation}</span>
                    </div>
                    <p className="text-xs font-bold text-gray-200 font-outfit mb-2">{v.title}</p>
                    <p className="text-[10px] text-gray-400 font-fira leading-relaxed mb-3">{v.technicalDescription}</p>
                    <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                      <p className="text-[9px] font-bold text-emerald-400 font-outfit uppercase tracking-wider mb-1.5">Remediation</p>
                      <pre className="text-[10px] text-gray-300 font-fira whitespace-pre-wrap leading-relaxed overflow-x-auto">
                        {v.remediationPattern}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.vulnerabilities.length === 0 && (
            <div className="bg-emerald-500/5 border border-emerald-400/20 rounded-2xl p-8 text-center">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <p className="text-sm font-bold text-emerald-400 font-outfit">No Vulnerabilities Detected</p>
              <p className="text-xs text-gray-500 font-fira mt-1">Contract passed all security checks.</p>
            </div>
          )}

          {/* Mint / EAS actions */}
          <div className="bg-cyber-card border border-white/5 rounded-2xl p-5 backdrop-blur-md">
            <p className="text-xs font-bold text-gray-200 font-outfit uppercase tracking-wider mb-3 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-indigo-400" /> On-Chain Actions (EIP-1193 Wallet)
            </p>
            <div className="flex gap-3">
              <button
                onMouseEnter={playHover}
                className="flex-1 border border-indigo-400/25 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 text-xs font-bold font-outfit py-3 rounded-xl transition-all duration-300"
                onClick={() => alert('Connect MetaMask to trigger EAS attestation — implementation uses ethers.js + EIP-1193')}
              >
                EAS Attest on Base Sepolia
              </button>
              <button
                onMouseEnter={playHover}
                className="flex-1 border border-purple-400/25 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 text-xs font-bold font-outfit py-3 rounded-xl transition-all duration-300"
                onClick={() => alert('Connect MetaMask to mint SVG NFT Badge — implementation uses ethers.js + EIP-1193')}
              >
                Mint SVG Badge NFT
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Re-export for backwards compat
import { ApiKeyStore } from '../lib/aiTriage';
