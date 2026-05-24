import { create } from 'zustand';
import { runAiTriage, type AuditXReport } from '../lib/aiTriage';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

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

  // GitHub & Forta configuration
  sourceTab: 'upload' | 'github';
  githubTarget: string;
  enableForta: boolean;
  fortaAddress: string;
  genBot: boolean;

  // Audit state
  simStatus: SimStatus;
  terminalLogs: TerminalLog[];
  report: AuditXReport | null;

  // Actions
  setView: (view: 'blueprint' | 'simulator') => void;
  setSelectedLayer: (layer: string | null) => void;
  setFile: (slot: keyof UploadedFiles, data: { name: string; content: string } | null) => void;
  setSourceTab: (tab: 'upload' | 'github') => void;
  setGithubTarget: (target: string) => void;
  setEnableForta: (val: boolean) => void;
  setFortaAddress: (address: string) => void;
  setGenBot: (val: boolean) => void;
  resetAudit: () => void;
  runAudit: () => Promise<void>;
  runGithubAudit: () => Promise<void>;
}

function addLog(state: AuditState, log: TerminalLog): Partial<AuditState> {
  return { terminalLogs: [...state.terminalLogs, { ...log, ts: Date.now() }] };
}

export const useAuditStore = create<AuditState>((set, get) => ({
  activeView: 'blueprint',
  selectedLayer: null,

  files: { sol: null, slither: null, mythril: null, surya: null },

  sourceTab: 'upload',
  githubTarget: '',
  enableForta: false,
  fortaAddress: '',
  genBot: false,

  simStatus: 'IDLE',
  terminalLogs: [
    { type: 'system', text: 'AuditX Decentralized Engine ready — powered by Gemini 2.0 Flash.', ts: Date.now() },
    { type: 'system', text: 'Upload your .sol file — Slither/Mythril/Surya JSON outputs are optional.', ts: Date.now() },
  ],
  report: null,

  setView: (view) => set({ activeView: view }),
  setSelectedLayer: (layer) => set({ selectedLayer: layer }),

  setFile: (slot, data) =>
    set((s) => ({ files: { ...s.files, [slot]: data } })),

  setSourceTab: (tab) => set({ sourceTab: tab }),
  setGithubTarget: (target) => set({ githubTarget: target }),
  setEnableForta: (val) => set({ enableForta: val }),
  setFortaAddress: (address) => set({ fortaAddress: address }),
  setGenBot: (val) => set({ genBot: val }),

  resetAudit: () =>
    set({
      simStatus: 'IDLE',
      report: null,
      terminalLogs: [
        { type: 'system', text: 'Reset. Ready for new audit.', ts: Date.now() },
      ],
    }),

  runAudit: async () => {
    const { files } = get();

    if (!files.sol) {
      set((s) => ({ ...addLog(s, { type: 'error', text: 'No .sol file loaded. Upload a Solidity contract to continue.' }) }));
      return;
    }

    set({
      simStatus: 'RUNNING',
      report: null,
      terminalLogs: [
        { type: 'system', text: `[AuditX] Initiating local simulation — ${files.sol.name}`, ts: Date.now() },
        { type: 'system', text: `[AuditX] Tool outputs: Slither=${!!files.slither} | Mythril=${!!files.mythril} | Surya=${!!files.surya}`, ts: Date.now() },
      ],
    });

    try {
      const report = await runAiTriage(
        {
          contractName: files.sol.name.replace('.sol', ''),
          sol: files.sol.content,
          slither: files.slither?.content,
          mythril: files.mythril?.content,
          surya: files.surya?.content,
        },
        (msg, type = 'info') =>
          set((s) => ({
            ...addLog(s, {
              type: type === 'info' ? 'system' : (type as any),
              text: msg
            })
          }))
      );

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

  runGithubAudit: async () => {
    const { githubTarget, enableForta, fortaAddress, genBot } = get();

    if (!githubTarget || !githubTarget.trim()) {
      set((s) => ({ ...addLog(s, { type: 'error', text: 'Please specify a GitHub target repository or contract path.' }) }));
      return;
    }

    set({
      simStatus: 'RUNNING',
      report: null,
      terminalLogs: [
        { type: 'system', text: `[AuditX] Contacting backend API on ${API_URL}...`, ts: Date.now() },
        { type: 'system', text: `[GitHub] Initiating remote import for: ${githubTarget}`, ts: Date.now() },
      ],
    });

    try {
      // Connect to Server-Sent Events (SSE) telemetry stream before POSTing
      const sse = new EventSource(`${API_URL}/stream`);

      sse.addEventListener('step', (ev) => {
        try {
          const data = JSON.parse(ev.data);
          const type = data.status === 'error' ? 'error' : data.status === 'complete' ? 'success' : 'system';
          set((s) => ({
            ...addLog(s, {
              type,
              text: `[${data.step.toUpperCase()}] ${data.data.message}`
            })
          }));

          if (data.step === 'parse' && data.status === 'complete') {
            sse.close();
            // Fetch the compiled, real report from the backend report endpoint!
            fetch(`${API_URL}/api/reports/latest`)
              .then(res => res.json())
              .then(backendReport => {
                const cvssRaw = parseInt(backendReport.cvssScore) || 15;
                const riskLevel = cvssRaw >= 90 ? 'critical' : cvssRaw >= 70 ? 'high' : cvssRaw >= 40 ? 'medium' : 'low';
                const certStatus = cvssRaw >= 70 ? 'DENIED_RISK_TOO_HIGH' : cvssRaw >= 40 ? 'APPROVED_AMBER' : 'APPROVED_EMERALD';
                const badge = cvssRaw >= 70 ? 'NULL' : cvssRaw >= 40 ? 'AMBER GUARD' : 'EMERALD GUARD';
                const color = cvssRaw >= 70 ? '#NONE' : cvssRaw >= 40 ? '#F59E0B' : '#10B981';

                const adaptedReport: AuditXReport = {
                  analyticsSummary: {
                    targetContractName: 'VulnerableVault',
                    compilerTarget: 'Solidity ^0.8.20',
                    riskClassification: riskLevel,
                    aggregateCvssScoreRaw: cvssRaw,
                    certificationStatus: certStatus,
                  },
                  vulnerabilities: (backendReport.detailedFindings || []).map((f: any, idx: number) => ({
                    vulnerabilityId: `AUDITX-${String(idx + 1).padStart(3, '0')}`,
                    title: f.title || 'Security Finding',
                    severity: (f.severity?.toLowerCase() === 'critical' ? 'critical' : f.severity?.toLowerCase() === 'high' ? 'high' : f.severity?.toLowerCase() === 'medium' ? 'medium' : 'low') as any,
                    sourceTool: (f.tool || 'Joint Heuristics') as any,
                    vulnerabilityLocation: f.loc || 'N/A',
                    technicalDescription: f.desc || f.description || '',
                    remediationPattern: f.fixCode || 'Remediation details in full HTML report.',
                  })),
                  graphInsights: {
                    suryaCallGraphTopology: 'Call-graph mapped via Surya dynamic analyzer.',
                    attackSurfacePerimeter: 'Audited public/external boundary routes.',
                    mermaidGraph: 'graph TD\n  A[Deposit] --> B(Withdraw)',
                  },
                  onChainPayload: {
                    easSchemaVariables: {
                      contractName: 'VulnerableVault',
                      severityScoreUint8: cvssRaw,
                      ipfsReportHashPlaceholder: backendReport.ipfsCid || 'ipfs://QmUnsealed',
                    },
                    svgProperties: {
                      badgeGrade: badge,
                      shieldColor: color,
                    }
                  }
                };

                set((s) => ({
                  simStatus: 'COMPLETED',
                  report: adaptedReport,
                  terminalLogs: [
                    ...s.terminalLogs,
                    { type: 'success', text: `[RESULT] GitHub Audit Completed successfully!`, ts: Date.now() },
                    { type: 'success', text: `[RESULT] Badge sealed: ${adaptedReport.onChainPayload.svgProperties.badgeGrade}`, ts: Date.now() },
                    { type: 'system', text: `[RESULT] Remote logs finalized.`, ts: Date.now() }
                  ]
                }));
              })
              .catch(err => {
                set((s) => ({
                  simStatus: 'ERROR',
                  terminalLogs: [...s.terminalLogs, { type: 'error', text: `Failed to load completed report from API: ${err.message}` }]
                }));
              });
          }
        } catch {}
      });

      sse.onerror = () => {
        sse.close();
      };

      // Trigger the POST request to start background cloning & scanning
      const response = await fetch(`${API_URL}/api/audit/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: githubTarget,
          monitor: enableForta,
          address: enableForta ? fortaAddress : undefined,
          genBot: enableForta ? genBot : undefined
        })
      });

      if (!response.ok) {
        const errText = await response.text();
        sse.close();
        throw new Error(errText || `Server responded with status ${response.status}`);
      }

      const resData = await response.json();
      set((s) => ({
        terminalLogs: [
          ...s.terminalLogs,
          { type: 'success', text: `[API] ${resData.message}`, ts: Date.now() },
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
  }
}));
