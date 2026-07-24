/**
 * AuditX SIEM — Engine (public API barrel)
 *
 * Wires EventClassifier → AnomalyDetector → ThreatIntelligence → AlertManager
 * into a single easy-to-use SIEMEngine class.
 *
 * Usage:
 *   const siem = new SIEMEngine({ alertThreshold: 'MEDIUM' });
 *   await siem.train(historicalEvents);
 *   const { alerts } = await siem.process(newEvents);
 */

export * from './types.js';
export { EventClassifier } from './EventClassifier.js';
export { AnomalyDetector } from './AnomalyDetector.js';
export { ThreatIntelligence } from './ThreatIntelligence.js';
export { AlertManager } from './AlertManager.js';

import { EventClassifier } from './EventClassifier.js';
import { AnomalyDetector } from './AnomalyDetector.js';
import { ThreatIntelligence } from './ThreatIntelligence.js';
import { AlertManager } from './AlertManager.js';
import type {
  ChainEvent,
  ClassifiedEvent,
  ScoredEvent,
  EnrichedEvent,
  Alert,
  SIEMOptions,
  ThreatFeed,
} from './types.js';

// ─── SIEMEngine ──────────────────────────────────────────────────────────────

export interface SIEMProcessResult {
  classified: ClassifiedEvent[];
  scored: ScoredEvent[];
  enriched: EnrichedEvent[];
  alerts: Alert[];
}

export class SIEMEngine {
  public readonly classifier: EventClassifier;
  public readonly detector: AnomalyDetector;
  public readonly intel: ThreatIntelligence;
  public readonly alertManager: AlertManager;

  private trained = false;

  constructor(opts: SIEMOptions = {}) {
    this.classifier = new EventClassifier();
    this.detector = new AnomalyDetector();
    this.intel = new ThreatIntelligence(opts.customThreatFeeds ?? []);
    this.alertManager = new AlertManager({
      alertThreshold: opts.alertThreshold,
      uploadToIpfs: opts.uploadToIpfs,
      createEasAttestation: opts.createEasAttestation,
    });
  }

  /**
   * Train the anomaly detector on historical events.
   * Must be called before process().
   * Handles cold-start automatically (< 100 events → synthetic baseline).
   */
  async train(historicalEvents: ChainEvent[]): Promise<void> {
    const classified = this.classifier.classifyBatch(historicalEvents);
    this.detector.train(classified);
    this.trained = true;

    const baseline = this.detector.getBaseline();
    console.info(
      `[SIEM] Trained on ${historicalEvents.length} events ` +
      `(${baseline.syntheticSamples} synthetic). ` +
      `Gas baseline: μ=${baseline.gasUsed.mean.toFixed(0)} σ=${baseline.gasUsed.stdDev.toFixed(0)}. ` +
      `Threat feeds loaded: ${this.intel.size}.`
    );
  }

  /**
   * Process a batch of new chain events through the full SIEM pipeline.
   * Returns classified, scored, enriched events and generated alerts.
   */
  async process(events: ChainEvent[]): Promise<SIEMProcessResult> {
    if (!this.trained) {
      // Auto-train with zero history (cold-start) if not already trained
      await this.train([]);
    }

    const classified = this.classifier.classifyBatch(events);
    const scored = this.detector.scoreBatch(classified);
    const enriched = this.intel.enrichBatch(scored);
    const alerts = await this.alertManager.processBatch(enriched);

    return { classified, scored, enriched, alerts };
  }

  /**
   * Process a single event in real-time (streaming mode).
   */
  async processSingle(event: ChainEvent): Promise<{
    enriched: EnrichedEvent;
    alert: Alert | null;
  }> {
    if (!this.trained) await this.train([]);

    const classified = this.classifier.classify(event);
    const anomaly = this.detector.scoreAndUpdate(classified);
    const scored: ScoredEvent = {
      ...classified,
      anomaly,
      finalSeverity:
        anomaly.isAnomaly ? classified.ruleSeverity : classified.ruleSeverity,
    };
    const enriched = this.intel.enrich(scored);
    const alert = await this.alertManager.processEvent(enriched);

    return { enriched, alert };
  }

  /**
   * Add custom threat feed entries (live update, no restart needed).
   */
  addThreatFeeds(entries: ThreatFeed[]): void {
    this.intel.addFeed(entries);
  }

  /**
   * Sync threat feeds from a community IPFS CID.
   */
  async syncThreatFeeds(cid: string): Promise<number> {
    return this.intel.syncFromIpfs(cid);
  }

  /**
   * Get current anomaly detector baseline stats.
   */
  getBaseline() {
    return this.detector.getBaseline();
  }

  /**
   * Get all open alerts.
   */
  getOpenAlerts(): Alert[] {
    return this.alertManager.getOpenAlerts();
  }

  /**
   * Acknowledge an alert by ID.
   */
  acknowledgeAlert(id: string): boolean {
    return this.alertManager.acknowledge(id);
  }

  /**
   * Resolve an alert by ID.
   */
  resolveAlert(id: string): boolean {
    return this.alertManager.resolve(id);
  }
}
