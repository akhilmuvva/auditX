export type StepId =
  | 'parse' | 'slither' | 'mythril' | 'surya'
  | 'ai-triage' | 'ipfs' | 'eas' | 'mint'
  | 'siem-classify' | 'siem-anomaly' | 'siem-intel' | 'siem-alert'

export type StepStatus = 'pending' | 'active' | 'complete' | 'error'

export interface StepEvent {
  step: StepId
  status: StepStatus
  data?: unknown
  ts: number
}

export interface Finding {
  id: string
  tool: 'slither' | 'mythril' | 'surya'
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss: number
  swc?: string
  file?: string
  line?: number
  remediation: string
  patch?: string
}

export interface AuditReport {
  contractPath: string
  contractHash: string
  timestamp: number
  cvssScore: number
  /** RED = critical (≥9.0), AMBER = high/medium, EMERALD = low/safe, null if not yet determined */
  badgeGrade: 'red' | 'amber' | 'emerald' | null
  ipfsCid: string | null
  easUid: string | null
  txHash: string | null
  findings: Finding[]
  /** Number of SIEM alerts generated during post-deploy monitoring */
  siemAlertCount?: number
}
