export type StepId =
  | 'parse' | 'slither' | 'mythril' | 'surya'
  | 'ai-triage' | 'ipfs' | 'eas' | 'mint'
  | 'siem-classify' | 'siem-anomaly' | 'siem-intel' | 'siem-alert';

export type StepStatus = 'pending' | 'active' | 'complete' | 'error';

export interface StepEvent {
  step: StepId;
  status: StepStatus;
  data?: unknown;
  ts: number;
}
