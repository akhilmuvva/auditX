/**
 * AuditX SIEM — Shared Type Definitions
 * All types used across the SIEM subsystem live here.
 */

// ─── On-chain event captured by the indexer ────────────────────────────────

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ChainEvent {
  /** Unique event ID (txHash + logIndex) */
  id: string;
  /** Unix timestamp (ms) */
  timestamp: number;
  /** EVM chain identifier */
  chainId: number;
  /** Emitting contract address (lowercase) */
  contractAddress: string;
  /** Emitting contract name (from ABI label, if known) */
  contractName?: string;
  /** Transaction hash */
  txHash: string;
  /** Block number */
  blockNumber: number;
  /** Solidity event name */
  eventName: string;
  /** Decoded event args (key→value) */
  args: Record<string, unknown>;
  /** Gas used in the transaction */
  gasUsed: number;
  /** ETH value sent (in wei, as bigint string) */
  callValue: string;
  /** Sender address */
  from: string;
}

// ─── Classification ─────────────────────────────────────────────────────────

export type EventCategory =
  | 'TRANSFER'
  | 'APPROVAL'
  | 'OWNERSHIP_CHANGE'
  | 'LARGE_WITHDRAWAL'
  | 'FLASH_LOAN'
  | 'REENTRANCY_SIGNAL'
  | 'ORACLE_MANIPULATION'
  | 'GOVERNANCE'
  | 'UPGRADE'
  | 'PAUSE'
  | 'UNKNOWN';

export interface ClassifiedEvent extends ChainEvent {
  category: EventCategory;
  /** Human-readable reason for the classification */
  reason: string;
  /** Initial pre-anomaly-score severity from rule engine */
  ruleSeverity: EventSeverity;
}

// ─── Anomaly Detection ───────────────────────────────────────────────────────

export interface AnomalyScore {
  /** z-score for gasUsed relative to baseline */
  gasZScore: number;
  /** z-score for callValue relative to baseline */
  valueZScore: number;
  /** Combined anomaly score [0..1] */
  score: number;
  /** Whether this event is flagged as anomalous */
  isAnomaly: boolean;
}

export interface ScoredEvent extends ClassifiedEvent {
  anomaly: AnomalyScore;
  /** Final severity after anomaly scoring */
  finalSeverity: EventSeverity;
}

// ─── Threat Intelligence ─────────────────────────────────────────────────────

export interface ThreatFeed {
  /** Address being flagged */
  address: string;
  /** Human-readable label (e.g. "Tornado Cash") */
  label: string;
  /** Threat category */
  category: 'SANCTIONS' | 'EXPLOIT' | 'MIXER' | 'DRAINER' | 'PHISHING';
  /** CVSS-style risk score [0..10] */
  riskScore: number;
  /** ISO date of when the threat was first seen */
  firstSeen: string;
  /** Source of the intelligence */
  source: string;
}

export interface ThreatMatch {
  /** Matched address */
  address: string;
  /** The threat feed entry that matched */
  feed: ThreatFeed;
  /** Which field matched ('from' | 'contractAddress' | arg key) */
  matchedField: string;
}

export interface EnrichedEvent extends ScoredEvent {
  threatMatches: ThreatMatch[];
  /** Escalated severity if threat matched */
  escalatedSeverity: EventSeverity;
}

// ─── Alerts ──────────────────────────────────────────────────────────────────

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'SUPPRESSED';

export interface Alert {
  /** Unique alert ID */
  id: string;
  /** Alert creation timestamp (ms) */
  timestamp: number;
  /** The enriched event that triggered the alert */
  event: EnrichedEvent;
  /** Triggered rule or anomaly description */
  title: string;
  /** Detailed description */
  description: string;
  /** Final severity */
  severity: EventSeverity;
  /** Current alert lifecycle status */
  status: AlertStatus;
  /** Optional IPFS CID for immutable alert storage */
  ipfsCid?: string;
  /** Optional EAS attestation UID */
  easUid?: string;
}

// ─── SIEM Engine Options ─────────────────────────────────────────────────────

export interface SIEMOptions {
  /** Minimum severity level to create an alert (default: LOW) */
  alertThreshold?: EventSeverity;
  /** Whether to upload alerts to IPFS */
  uploadToIpfs?: boolean;
  /** Whether to create EAS attestations for CRITICAL alerts */
  createEasAttestation?: boolean;
  /** Custom threat feeds to add to the default set */
  customThreatFeeds?: ThreatFeed[];
}
