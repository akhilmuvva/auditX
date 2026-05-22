import { create } from 'zustand';
import { runBrowserAITriage, ApiKeyStore, type AuditXReport } from '../lib/aiTriage';

export type SimStatus = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'ERROR';

export interface TerminalLog {
  type: 'system' | 'success' | 'warning' | 'error';
  text: string;
  ts?: number;
}

export interface UploadedFiles {
  sol: { name: string; content: string } | null;
  slither: { name: string; content: string } | null;
  mythril: { name: string; content: string } | null;
  surya: { name: string; content: string } | null;
}

interface AuditState {
  activeView: 'blueprint' | 'simulator';
  selectedLayer: string | null;

  // File uploads
  files: UploadedFiles;

  // API key (persisted in localStorage)
  apiKey: string;
  apiKeyVisible: boolean;

  // Audit state
  simStatus: SimStatus;
  terminalLogs: TerminalLog[];
  report: AuditXReport | null;

  // Actions
  setView: (view: 'blueprint' | 'simulator') => void;
  setSelectedLayer: (layer: string | null) => void;
  setFile: (slot: keyof UploadedFiles, data: { name: string; content: string } | null) => void;
  setApiKey: (key: string) => void;
  toggleApiKeyVisible: () => void;
  resetAudit: () => void;
  runAudit: () => Promise<void>;
}

function addLog(state: AuditState, log: TerminalLog): Partial<AuditState> {
  return { terminalLogs: [...state.terminalLogs, { ...log, ts: Date.now() }] };
}

export const useAuditStore = create<AuditState>((set, get) => ({
  activeView: 'blueprint',
  selectedLayer: null,

  files: { sol: null, slither: null, mythril: null, surya: null },

  apiKey: ApiKeyStore.get(),
  apiKeyVisible: false,

  simStatus: 'IDLE',
  terminalLogs: [
    { type: 'system', text: 'AuditX Decentralized Engine ready.', ts: Date.now() },
    { type: 'system', text: 'Upload your .sol file — Slither/Mythril/Surya JSON outputs are optional.', ts: Date.now() },
    { type: 'system', text: 'Your Anthropic API key never leaves your browser.', ts: Date.now() },
  ],
  report: null,

  setView: (view) => set({ activeView: view }),
  setSelectedLayer: (layer) => set({ selectedLayer: layer }),

  setFile: (slot, data) =>
    set((s) => ({ files: { ...s.files, [slot]: data } })),

  setApiKey: (key) => {
    ApiKeyStore.set(key);
    set({ apiKey: key });
  },

  toggleApiKeyVisible: () => set((s) => ({ apiKeyVisible: !s.apiKeyVisible })),

  resetAudit: () =>
    set({
      simStatus: 'IDLE',
      report: null,
      terminalLogs: [
        { type: 'system', text: 'Reset. Ready for new audit.', ts: Date.now() },
      ],
    }),

  runAudit: async () => {
    const { files, apiKey } = get();

    if (!files.sol) {
      set((s) => ({ ...addLog(s, { type: 'error', text: 'No .sol file loaded. Upload a Solidity contract to continue.' }) }));
      return;
    }
    if (!apiKey.trim()) {
      set((s) => ({ ...addLog(s, { type: 'error', text: 'Anthropic API key is required. Enter it in the Key panel above.' }) }));
      return;
    }

    set({
      simStatus: 'RUNNING',
      report: null,
      terminalLogs: [
        { type: 'system', text: `[AuditX] Initiating decentralized audit — ${files.sol.name}`, ts: Date.now() },
        { type: 'system', text: `[AuditX] Tool outputs: Slither=${!!files.slither} | Mythril=${!!files.mythril} | Surya=${!!files.surya}`, ts: Date.now() },
      ],
    });

    try {
      const report = await runBrowserAITriage({
        contractName: files.sol.name.replace('.sol', ''),
        solidityCode: files.sol.content,
        slitherOutput: files.slither?.content,
        mythrilOutput: files.mythril?.content,
        suryaOutput: files.surya?.content,
        apiKey,
        onProgress: (msg) =>
          set((s) => ({ ...addLog(s, { type: 'system', text: msg }) })),
      });

      const status = report.analyticsSummary.certificationStatus;
      const risk = report.analyticsSummary.riskClassification;
      const score = (report.analyticsSummary.aggregateCvssScoreRaw / 10).toFixed(1);
      const vulnCount = report.vulnerabilities.length;

      set((s) => ({
        simStatus: 'COMPLETED',
        report,
        terminalLogs: [
          ...s.terminalLogs,
          { type: status === 'DENIED_RISK_TOO_HIGH' ? 'error' : 'success', text: `[RESULT] Status: ${status}`, ts: Date.now() },
          { type: risk === 'critical' || risk === 'high' ? 'error' : 'warning', text: `[RESULT] Risk: ${risk.toUpperCase()} | CVSS: ${score} | Findings: ${vulnCount}`, ts: Date.now() },
          { type: 'success', text: `[RESULT] Badge: ${report.onChainPayload.svgProperties.badgeGrade}`, ts: Date.now() },
          { type: 'system', text: `[AuditX] Audit sealed. Ready for EAS attestation + NFT mint via wallet.`, ts: Date.now() },
        ],
      }));
    } catch (err: any) {
      set((s) => ({
        simStatus: 'ERROR',
        terminalLogs: [
          ...s.terminalLogs,
          { type: 'error', text: `[ERROR] ${err.message}` },
        ],
      }));
    }
  },
}));
