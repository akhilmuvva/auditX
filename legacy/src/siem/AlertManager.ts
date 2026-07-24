/**
 * AuditX SIEM — AlertManager
 *
 * Manages the lifecycle of SIEM alerts:
 *  - Creates alerts from enriched events above a severity threshold
 *  - Deduplicates correlated alerts within a time window
 *  - Supports acknowledge / resolve / suppress operations
 *  - Optionally uploads critical alerts to IPFS (via injected upload fn)
 *  - Emits structured alert notifications via EventEmitter
 *
 * Design: In-memory store backed by optional persistence.
 * For production, swap the in-memory Map for a LevelDB/SQLite adapter.
 */

import { EventEmitter } from 'events';
import { randomBytes } from 'crypto';
import type {
  EnrichedEvent,
  Alert,
  AlertStatus,
  EventSeverity,
  SIEMOptions,
} from './types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER: EventSeverity[] = [
  'INFO',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
];

/** Dedup window: if an identical alert fires within this ms, suppress it */
const DEDUP_WINDOW_MS = 60_000; // 1 minute

// ─── AlertManager ─────────────────────────────────────────────────────────────

export class AlertManager extends EventEmitter {
  private alerts: Map<string, Alert> = new Map();
  private dedupCache: Map<string, number> = new Map(); // dedupKey → lastAlertTimestamp

  private threshold: EventSeverity;
  private uploadToIpfs: boolean;
  private createEasAttestation: boolean;

  /** Optional injected upload function (avoids hard dependency on ipfs.ts) */
  private ipfsUploadFn?: (data: unknown) => Promise<string>;
  /** Optional injected EAS attestation function */
  private easAttestFn?: (alert: Alert) => Promise<string>;

  constructor(
    opts: Pick<SIEMOptions, 'alertThreshold' | 'uploadToIpfs' | 'createEasAttestation'> = {}
  ) {
    super();
    this.threshold = opts.alertThreshold ?? 'LOW';
    this.uploadToIpfs = opts.uploadToIpfs ?? false;
    this.createEasAttestation = opts.createEasAttestation ?? false;
  }

  /**
   * Inject optional IPFS and EAS functions.
   * Keeps AlertManager decoupled from storage modules.
   */
  setIpfsUpload(fn: (data: unknown) => Promise<string>): this {
    this.ipfsUploadFn = fn;
    return this;
  }

  setEasAttest(fn: (alert: Alert) => Promise<string>): this {
    this.easAttestFn = fn;
    return this;
  }

  // ── Core alert creation ──────────────────────────────────────────────────

  /**
   * Process a single enriched event and create an alert if warranted.
   * Returns the created Alert, or null if below threshold / deduplicated.
   */
  async processEvent(event: EnrichedEvent): Promise<Alert | null> {
    if (!this.meetsThreshold(event.escalatedSeverity)) return null;

    const dedupKey = this.buildDedupKey(event);
    const now = Date.now();
    const lastSeen = this.dedupCache.get(dedupKey);

    if (lastSeen && now - lastSeen < DEDUP_WINDOW_MS) {
      // Duplicate — update timestamp but don't create new alert
      this.dedupCache.set(dedupKey, now);
      return null;
    }

    this.dedupCache.set(dedupKey, now);

    const alert = this.buildAlert(event);

    // Async: upload to IPFS / EAS if configured
    await this.attachIpfs(alert);
    await this.attachEas(alert);

    this.alerts.set(alert.id, alert);
    this.emit('alert', alert);

    if (alert.severity === 'CRITICAL') {
      this.emit('critical', alert);
    }

    return alert;
  }

  /**
   * Process a batch of enriched events.
   * Returns all created alerts (deduplicated, threshold-filtered).
   */
  async processBatch(events: EnrichedEvent[]): Promise<Alert[]> {
    const results: Alert[] = [];
    for (const event of events) {
      const alert = await this.processEvent(event);
      if (alert) results.push(alert);
    }
    return results;
  }

  // ── Lifecycle management ─────────────────────────────────────────────────

  acknowledge(alertId: string): boolean {
    return this.updateStatus(alertId, 'ACKNOWLEDGED');
  }

  resolve(alertId: string): boolean {
    return this.updateStatus(alertId, 'RESOLVED');
  }

  suppress(alertId: string): boolean {
    return this.updateStatus(alertId, 'SUPPRESSED');
  }

  private updateStatus(alertId: string, status: AlertStatus): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert) return false;
    alert.status = status;
    this.emit('alertUpdated', { alertId, status });
    return true;
  }

  // ── Query ────────────────────────────────────────────────────────────────

  getAlert(id: string): Alert | undefined {
    return this.alerts.get(id);
  }

  getAlerts(filter?: {
    status?: AlertStatus;
    severity?: EventSeverity;
    since?: number;
  }): Alert[] {
    let list = Array.from(this.alerts.values());
    if (filter?.status) list = list.filter((a) => a.status === filter.status);
    if (filter?.severity)
      list = list.filter(
        (a) =>
          SEVERITY_ORDER.indexOf(a.severity) >=
          SEVERITY_ORDER.indexOf(filter.severity!)
      );
    if (filter?.since) list = list.filter((a) => a.timestamp >= filter.since!);
    return list.sort((a, b) => b.timestamp - a.timestamp);
  }

  getOpenAlerts(): Alert[] {
    return this.getAlerts({ status: 'OPEN' });
  }

  getCriticalAlerts(): Alert[] {
    return this.getAlerts({ severity: 'CRITICAL' });
  }

  get totalCount(): number {
    return this.alerts.size;
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  private meetsThreshold(severity: EventSeverity): boolean {
    return (
      SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(this.threshold)
    );
  }

  private buildDedupKey(event: EnrichedEvent): string {
    // Same contract + same event name + same category within dedup window = duplicate
    return `${event.contractAddress}:${event.eventName}:${event.category}`;
  }

  private buildAlert(event: EnrichedEvent): Alert {
    const id = randomBytes(8).toString('hex');
    const hasThreat = event.threatMatches.length > 0;
    const isAnomaly = event.anomaly.isAnomaly;

    let title: string;
    let description: string;

    if (hasThreat) {
      const match = event.threatMatches[0];
      title = `🚨 Threat Match: ${match.feed.label}`;
      description =
        `Known-bad address "${match.address}" (${match.feed.category}) ` +
        `detected in ${match.matchedField} of "${event.eventName}" ` +
        `on contract ${event.contractAddress}. ` +
        `Risk score: ${match.feed.riskScore}/10. Source: ${match.feed.source}.`;
    } else if (isAnomaly) {
      title = `⚠️ Anomalous ${event.category}: ${event.eventName}`;
      description =
        `Statistical anomaly detected — gas z-score: ${event.anomaly.gasZScore.toFixed(2)}, ` +
        `value z-score: ${event.anomaly.valueZScore.toFixed(2)} ` +
        `(combined score: ${(event.anomaly.score * 100).toFixed(1)}%). ` +
        `Classification: ${event.reason}.`;
    } else {
      title = `ℹ️ ${event.category}: ${event.eventName}`;
      description = event.reason;
    }

    return {
      id,
      timestamp: Date.now(),
      event,
      title,
      description,
      severity: event.escalatedSeverity,
      status: 'OPEN',
    };
  }

  private async attachIpfs(alert: Alert): Promise<void> {
    if (!this.uploadToIpfs || !this.ipfsUploadFn) return;
    if (
      SEVERITY_ORDER.indexOf(alert.severity) < SEVERITY_ORDER.indexOf('HIGH')
    )
      return; // Only upload HIGH+ to IPFS
    try {
      alert.ipfsCid = await this.ipfsUploadFn(alert);
    } catch (err: any) {
      console.warn(`[AlertManager] IPFS upload failed: ${err.message}`);
    }
  }

  private async attachEas(alert: Alert): Promise<void> {
    if (!this.createEasAttestation || !this.easAttestFn) return;
    if (alert.severity !== 'CRITICAL') return; // Only attest CRITICAL
    try {
      alert.easUid = await this.easAttestFn(alert);
    } catch (err: any) {
      console.warn(`[AlertManager] EAS attestation failed: ${err.message}`);
    }
  }
}
