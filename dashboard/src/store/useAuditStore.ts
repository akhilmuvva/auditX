import { create } from 'zustand';
import type { TerminalLog, SimulatorReport } from './constants';

const STEP_ORDER = ['parse', 'slither', 'mythril', 'surya', 'ai-triage', 'ipfs', 'eas', 'mint'] as const;

interface AuditState {
  activeView: 'blueprint' | 'simulator';
  selectedLayer: string | null;

  // Editor state
  code: string;
  filename: string;

  // Simulator State
  simStatus: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'ERROR';
  currentStep: number;
  connectorWidth: number;
  terminalLogs: TerminalLog[];
  report: SimulatorReport | null;
  rawReport: any | null;          // real backend report
  mode: 'demo' | 'live';         // demo = fake data, live = real backend

  // Controls
  setView: (view: 'blueprint' | 'simulator') => void;
  setSelectedLayer: (layer: string | null) => void;
  setCode: (code: string) => void;
  setFilename: (name: string) => void;
  resetSimulator: () => void;

  // Live audit from backend
  startLiveAudit: () => Promise<void>;
}

// Map backend step IDs to pipeline tracker step index (0-7)
function stepToIndex(step: string): number {
  return STEP_ORDER.indexOf(step as any);
}

// Convert backend raw findings to SimulatorReport shape for UI compatibility
function buildSimReport(raw: any, filename: string): SimulatorReport {
  const findings = (raw?.detailedFindings || raw?.findings || []).map((f: any, i: number) => ({
    id: `vln-${String(i + 1).padStart(2, '0')}`,
    title: f.title || f.check || 'Unknown Finding',
    severity: f.severity || 'medium',
    tool: (f.tool || 'slither') as 'slither' | 'mythril' | 'surya',
    description: f.desc || f.description || f.message || '',
    remediation: f.fixCode || f.remediation || 'Review and patch the affected code.',
    patch: f.vulnCode || f.patch || '',
    swc: f.swc,
    file: f.file || filename,
    line: f.line,
    cvss: f.cvss || (f.severity === 'critical' ? 9.5 : f.severity === 'high' ? 7.5 : f.severity === 'medium' ? 5.0 : 2.0),
  }));

  const criticals = findings.filter((f: any) => f.severity === 'critical').length;
  const highs = findings.filter((f: any) => f.severity === 'high').length;
  const score = raw?.riskLevel === 'critical' ? '9.5'
    : raw?.riskLevel === 'high' ? '7.5'
    : raw?.riskLevel === 'medium' ? '5.0'
    : '1.5';
  const status: 'safe' | 'warning' | 'danger' = criticals > 0 ? 'danger' : highs > 0 ? 'warning' : 'safe';

  return {
    score,
    status,
    badgeTitle: status === 'safe' ? 'EMERALD GUARD' : status === 'warning' ? 'AMBER GUARD' : 'CRIMSON GUARD',
    badgeRisk: raw?.summary || (status === 'safe' ? 'ZERO CRITICAL ISSUES — AUDIT SECURED' : 'VULNERABILITIES DETECTED'),
    badgeIcon: '',
    critical: criticals,
    high: highs,
    medium: findings.filter((f: any) => f.severity === 'medium').length,
    ipfs: raw?.ipfsCid || '',
    easTx: raw?.easUid || '',
    network: 'Base Sepolia (L2)',
    findings,
    graphNodes: [],
    graphEdges: [],
    terminal: [],
  };
}

export const useAuditStore = create<AuditState>((set, get) => ({
  activeView: 'blueprint',
  selectedLayer: null,
  code: '// Paste or upload your Solidity contract here...\n// Click "Upload .sol File" to load from disk.',
  filename: 'MyContract.sol',

  simStatus: 'IDLE',
  currentStep: -1,
  connectorWidth: 0,
  terminalLogs: [
    { type: 'system', text: 'AuditX ready. Upload a .sol file or paste code, then click Run Audit.' }
  ],
  report: null,
  rawReport: null,
  mode: 'live',

  setView: (view) => set({ activeView: view }),
  setSelectedLayer: (layer) => set({ selectedLayer: layer }),
  setCode: (code) => set({ code }),
  setFilename: (name) => set({ filename: name }),

  resetSimulator: () => set({
    simStatus: 'IDLE',
    currentStep: -1,
    connectorWidth: 0,
    terminalLogs: [{ type: 'system', text: 'Reset. Upload a .sol file and run audit.' }],
    report: null,
    rawReport: null,
  }),

  startLiveAudit: async () => {
    const { code, filename } = get();

    if (!code.trim() || code.startsWith('// Paste')) {
      set(s => ({
        terminalLogs: [...s.terminalLogs,
          { type: 'error', text: 'No contract loaded. Please upload or paste Solidity code first.' }
        ]
      }));
      return;
    }

    set({
      simStatus: 'RUNNING',
      currentStep: 0,
      connectorWidth: 0,
      terminalLogs: [{ type: 'system', text: `[AuditX] Uploading ${filename} to backend pipeline...` }],
      report: null,
      rawReport: null,
    });

    // Connect to SSE stream FIRST
    const es = new EventSource('http://localhost:3000/stream');

    es.addEventListener('step', (e) => {
      try {
        const event = JSON.parse((e as MessageEvent).data);
        const { step, status, data } = event;

        const logType: TerminalLog['type'] =
          status === 'error' ? 'error' :
          status === 'complete' ? 'success' : 'system';

        const msg = data?.message || `[${step}] ${status}`;

        set(s => ({
          terminalLogs: [...s.terminalLogs, { type: logType, text: msg }],
          currentStep: Math.max(s.currentStep, stepToIndex(step)),
          connectorWidth: Math.max(s.connectorWidth, (stepToIndex(step) / 7) * 100),
        }));

        // Final complete event contains the full report
        if (step === 'parse' && status === 'complete' && data?.report) {
          const simReport = buildSimReport(data.report, get().filename);
          set({
            simStatus: 'COMPLETED',
            currentStep: 7,
            connectorWidth: 100,
            report: simReport,
            rawReport: data.report,
          });
          es.close();
        }
      } catch {
        // ignore parse errors
      }
    });

    es.addEventListener('status', (e) => {
      try {
        const { status } = JSON.parse((e as MessageEvent).data);
        if (status === 'ERROR') {
          set({ simStatus: 'ERROR' });
          es.close();
        }
      } catch {}
    });

    es.onerror = () => {
      set(s => ({
        terminalLogs: [...s.terminalLogs, { type: 'warning', text: '[SSE] Connection lost or backend not running.' }],
      }));
      es.close();
    };

    // POST the contract code to the backend
    try {
      const res = await fetch('http://localhost:3000/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename, code }),
      });

      if (!res.ok) {
        const err = await res.json();
        set(s => ({
          simStatus: 'ERROR',
          terminalLogs: [...s.terminalLogs, { type: 'error', text: `Backend error: ${err.error}` }],
        }));
        es.close();
        return;
      }

      set(s => ({
        terminalLogs: [...s.terminalLogs, { type: 'success', text: `[AuditX] Pipeline started — streaming live telemetry...` }],
      }));
    } catch (err: any) {
      set(s => ({
        simStatus: 'ERROR',
        terminalLogs: [...s.terminalLogs, {
          type: 'error',
          text: `Cannot reach backend. Start the server: node dist/cli.js --server\nError: ${err.message}`
        }],
      }));
      es.close();
    }
  },
}));
