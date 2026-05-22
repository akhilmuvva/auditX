/**
 * SIEM Engine Unit Tests — Jest / ts-jest
 * Tests EventClassifier, AnomalyDetector (cold-start), ThreatIntelligence, AlertManager, SIEMEngine
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { AnomalyDetector } from '../src/siem/AnomalyDetector.js';
import { EventClassifier } from '../src/siem/EventClassifier.js';
import { ThreatIntelligence } from '../src/siem/ThreatIntelligence.js';
import { AlertManager } from '../src/siem/AlertManager.js';
import { SIEMEngine } from '../src/siem/index.js';
import type { ChainEvent, ClassifiedEvent, ScoredEvent } from '../src/siem/types.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeEvent(overrides: Partial<ChainEvent> = {}): ChainEvent {
  return {
    id: 'tx_0001-0',
    timestamp: Date.now(),
    chainId: 84532,
    contractAddress: '0xdeadbeef00000000000000000000000000000001',
    txHash: '0xabc123',
    blockNumber: 12345,
    eventName: 'Transfer',
    args: { from: '0xsender', to: '0xrecipient', value: '1000000000000000000' },
    gasUsed: 65_000,
    callValue: '0',
    from: '0xsender',
    ...overrides,
  };
}

function makeClassifiedEvent(overrides: Partial<ChainEvent> = {}): ClassifiedEvent {
  const classifier = new EventClassifier();
  return classifier.classify(makeEvent(overrides));
}

// ─── EventClassifier Tests ────────────────────────────────────────────────────

describe('EventClassifier', () => {
  const classifier = new EventClassifier();

  it('classifies Transfer as TRANSFER / INFO', () => {
    const result = classifier.classify(makeEvent({ eventName: 'Transfer' }));
    expect(result.category).toBe('TRANSFER');
    expect(result.ruleSeverity).toBe('INFO');
  });

  it('classifies OwnershipTransferred as OWNERSHIP_CHANGE / HIGH', () => {
    const result = classifier.classify(makeEvent({ eventName: 'OwnershipTransferred' }));
    expect(result.category).toBe('OWNERSHIP_CHANGE');
    expect(result.ruleSeverity).toBe('HIGH');
  });

  it('classifies Upgraded as UPGRADE / CRITICAL', () => {
    const result = classifier.classify(makeEvent({ eventName: 'Upgraded' }));
    expect(result.category).toBe('UPGRADE');
    expect(result.ruleSeverity).toBe('CRITICAL');
  });

  it('classifies FlashLoan as FLASH_LOAN / HIGH', () => {
    const result = classifier.classify(makeEvent({ eventName: 'FlashLoan' }));
    expect(result.category).toBe('FLASH_LOAN');
    expect(result.ruleSeverity).toBe('HIGH');
  });

  it('classifies Paused as PAUSE / MEDIUM', () => {
    const result = classifier.classify(makeEvent({ eventName: 'Paused' }));
    expect(result.category).toBe('PAUSE');
    expect(result.ruleSeverity).toBe('MEDIUM');
  });

  it('classifies ProposalExecuted with 0 delay as GOVERNANCE / HIGH', () => {
    const result = classifier.classify(makeEvent({
      eventName: 'ProposalExecuted',
      args: { delay: 0 },
    }));
    expect(result.category).toBe('GOVERNANCE');
    expect(result.ruleSeverity).toBe('HIGH');
  });

  it('classifies Swap with identical sender and recipient as FLASH_LOAN / MEDIUM', () => {
    const result = classifier.classify(makeEvent({
      eventName: 'Swap',
      args: { sender: '0xuser', recipient: '0xuser' },
    }));
    expect(result.category).toBe('FLASH_LOAN');
    expect(result.ruleSeverity).toBe('MEDIUM');
  });

  it('classifies EmergencyShutdown as UPGRADE / CRITICAL', () => {
    const result = classifier.classify(makeEvent({
      eventName: 'EmergencyShutdown',
    }));
    expect(result.category).toBe('UPGRADE');
    expect(result.ruleSeverity).toBe('CRITICAL');
  });

  it('classifies unknown event as UNKNOWN / INFO', () => {
    const result = classifier.classify(makeEvent({ eventName: 'SomethingRandom123' }));
    expect(result.category).toBe('UNKNOWN');
    expect(result.ruleSeverity).toBe('INFO');
  });

  it('classifyBatch processes multiple events', () => {
    const events = [
      makeEvent({ eventName: 'Transfer' }),
      makeEvent({ eventName: 'Upgraded' }),
      makeEvent({ eventName: 'FlashLoan' }),
    ];
    const results = classifier.classifyBatch(events);
    expect(results).toHaveLength(3);
    expect(results[0].category).toBe('TRANSFER');
    expect(results[1].category).toBe('UPGRADE');
    expect(results[2].category).toBe('FLASH_LOAN');
  });
});

// ─── AnomalyDetector Cold-Start Tests ────────────────────────────────────────

describe('AnomalyDetector — cold-start', () => {
  it('trains with zero events and injects 100 synthetic samples', () => {
    const detector = new AnomalyDetector();
    detector.train([]);
    const baseline = detector.getBaseline();
    expect(detector.syntheticSamples).toBe(100);
    expect(baseline.gasUsed.n).toBe(100);
    // Mean should be near ERC-20 typical gas (65000 ± tolerance)
    expect(baseline.gasUsed.mean).toBeGreaterThan(50_000);
    expect(baseline.gasUsed.mean).toBeLessThan(80_000);
  });

  it('trains with 50 events and injects 50 synthetic samples', () => {
    const detector = new AnomalyDetector();
    const events = Array.from({ length: 50 }, () =>
      makeClassifiedEvent({ gasUsed: 65_000 })
    );
    detector.train(events);
    expect(detector.syntheticSamples).toBe(50);
    // 50 synthetic + 50 real = 100 total
    expect(detector.getBaseline().gasUsed.n).toBe(100);
  });

  it('trains with 100+ events and uses NO synthetic samples', () => {
    const detector = new AnomalyDetector();
    const events = Array.from({ length: 120 }, () =>
      makeClassifiedEvent({ gasUsed: 65_000 })
    );
    detector.train(events);
    expect(detector.syntheticSamples).toBe(0);
    expect(detector.getBaseline().gasUsed.n).toBe(120);
  });

  it('does NOT flag a normal Transfer as anomalous after cold-start', () => {
    const detector = new AnomalyDetector();
    detector.train([]);
    const normalEvent = makeClassifiedEvent({ gasUsed: 65_000, callValue: '0' });
    const score = detector.score(normalEvent);
    expect(score.isAnomaly).toBe(false);
  });

  it('flags a 10x-gas event as anomalous after cold-start', () => {
    const detector = new AnomalyDetector();
    detector.train([]);
    const anomalousEvent = makeClassifiedEvent({
      gasUsed: 650_000,
      callValue: '50000000000000000000',
    });
    const score = detector.score(anomalousEvent);
    expect(score.isAnomaly).toBe(true);
    expect(score.gasZScore).toBeGreaterThan(3);
  });

  it('online update shifts baseline over time', () => {
    const detector = new AnomalyDetector();
    detector.train([]);
    const baselineBefore = detector.getBaseline().gasUsed.n;
    const event = makeClassifiedEvent({ gasUsed: 70_000 });
    detector.update(event);
    expect(detector.getBaseline().gasUsed.n).toBe(baselineBefore + 1);
  });
});

// ─── ThreatIntelligence Tests ─────────────────────────────────────────────────

describe('ThreatIntelligence', () => {
  let ti: ThreatIntelligence;
  beforeEach(() => { ti = new ThreatIntelligence(); });

  it('loads built-in seed feeds on construction', () => {
    expect(ti.size).toBeGreaterThan(0);
  });

  it('detects Tornado Cash by address', () => {
    const feed = ti.checkAddress('0xd90e2f925da726b50c4ed8d0fb90ad053324f31b');
    expect(feed).not.toBeNull();
    expect(feed!.label).toContain('Tornado Cash');
    expect(feed!.category).toBe('MIXER');
  });

  it('is case-insensitive for address lookup', () => {
    const feed = ti.checkAddress('0xD90E2F925DA726B50C4ED8D0FB90AD053324F31B');
    expect(feed).not.toBeNull();
  });

  it('returns null for a clean address', () => {
    const feed = ti.checkAddress('0x1234567890abcdef1234567890abcdef12345678');
    expect(feed).toBeNull();
  });

  it('adds custom feed entries', () => {
    ti.addFeed([{
      address: '0xcafebabe00000000000000000000000000000001',
      label: 'Custom Bad Actor',
      category: 'EXPLOIT',
      riskScore: 9.0,
      firstSeen: '2024-01-01',
      source: 'Internal',
    }]);
    const feed = ti.checkAddress('0xcafebabe00000000000000000000000000000001');
    expect(feed).not.toBeNull();
    expect(feed!.label).toBe('Custom Bad Actor');
  });

  it('enriches event with threat match and escalates severity to CRITICAL', () => {
    const classifier = new EventClassifier();
    const detector = new AnomalyDetector();
    detector.train([]);

    const event = makeEvent({ from: '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b' });
    const classified = classifier.classify(event);
    const anomaly = detector.scoreAndUpdate(classified);
    const scored: ScoredEvent = {
      ...classified,
      anomaly,
      finalSeverity: classified.ruleSeverity,
    };

    const enriched = ti.enrich(scored);
    expect(enriched.threatMatches).toHaveLength(1);
    expect(enriched.threatMatches[0].feed.category).toBe('MIXER');
    expect(enriched.escalatedSeverity).toBe('CRITICAL');
  });

  it('enriches clean event with no threat matches', () => {
    const classifier = new EventClassifier();
    const detector = new AnomalyDetector();
    detector.train([]);

    const event = makeEvent({ from: '0x0000000000000000000000000000000000000001' });
    const classified = classifier.classify(event);
    const anomaly = detector.scoreAndUpdate(classified);
    const scored: ScoredEvent = { ...classified, anomaly, finalSeverity: classified.ruleSeverity };

    const enriched = ti.enrich(scored);
    expect(enriched.threatMatches).toHaveLength(0);
    expect(enriched.escalatedSeverity).toBe(classified.ruleSeverity);
  });
});

// ─── AlertManager Tests ───────────────────────────────────────────────────────

describe('AlertManager', () => {
  let engine: SIEMEngine;

  beforeEach(async () => {
    engine = new SIEMEngine({ alertThreshold: 'MEDIUM' });
    await engine.train([]);
  });

  it('creates CRITICAL alert for Upgraded event', async () => {
    const result = await engine.process([makeEvent({ eventName: 'Upgraded' })]);
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0].severity).toBe('CRITICAL');
    expect(result.alerts[0].status).toBe('OPEN');
  });

  it('suppresses duplicate alert within the dedup window', async () => {
    const event = makeEvent({ eventName: 'Upgraded' });
    const r1 = await engine.process([event]);
    const r2 = await engine.process([event]); // same contract+event+category
    expect(r1.alerts).toHaveLength(1);
    expect(r2.alerts).toHaveLength(0);
  });

  it('filters events below the severity threshold', async () => {
    // Transfer is INFO — below MEDIUM threshold
    const result = await engine.process([makeEvent({ eventName: 'Transfer' })]);
    expect(result.alerts).toHaveLength(0);
  });

  it('can acknowledge and resolve an alert', async () => {
    const result = await engine.process([makeEvent({ eventName: 'Upgraded' })]);
    const alertId = result.alerts[0].id;
    engine.acknowledgeAlert(alertId);
    expect(engine.alertManager.getAlert(alertId)!.status).toBe('ACKNOWLEDGED');
    engine.resolveAlert(alertId);
    expect(engine.alertManager.getAlert(alertId)!.status).toBe('RESOLVED');
  });
});

// ─── SIEMEngine Integration Test ─────────────────────────────────────────────

describe('SIEMEngine — full pipeline integration', () => {
  it('handles cold-start and produces CRITICAL alert for known exploiter', async () => {
    const engine = new SIEMEngine({ alertThreshold: 'LOW' });
    await engine.train([]); // cold-start: 0 real events → 100 synthetic

    const events: ChainEvent[] = [
      makeEvent({ eventName: 'Transfer', gasUsed: 65_000 }),
      makeEvent({ eventName: 'OwnershipTransferred', gasUsed: 65_000 }),
      makeEvent({ eventName: 'Upgraded', gasUsed: 65_000 }),
      // Anomalous flash loan
      makeEvent({ eventName: 'FlashLoan', gasUsed: 900_000, callValue: '100000000000000000000' }),
      // Ronin Bridge Exploiter (Lazarus Group) — threat intel match
      makeEvent({ from: '0x098b716b8aaf21512996dc57eb0615e2383e2f96', eventName: 'Transfer' }),
    ];

    const result = await engine.process(events);

    expect(result.classified).toHaveLength(5);
    expect(result.scored).toHaveLength(5);
    expect(result.enriched).toHaveLength(5);
    expect(result.alerts.length).toBeGreaterThan(0);

    // Threat intel match on Ronin exploiter must generate CRITICAL alert
    const criticalAlerts = result.alerts.filter(a => a.severity === 'CRITICAL');
    expect(criticalAlerts.length).toBeGreaterThan(0);
  });

  it('getBaseline reflects cold-start synthetic samples', async () => {
    const engine = new SIEMEngine();
    await engine.train([]);
    const baseline = engine.getBaseline();
    expect(baseline.syntheticSamples).toBe(100);
    expect(baseline.gasUsed.mean).toBeGreaterThan(50_000);
  });

  it('getOpenAlerts only returns OPEN status alerts', async () => {
    const engine = new SIEMEngine({ alertThreshold: 'LOW' });
    await engine.train([]);
    await engine.process([makeEvent({ eventName: 'Upgraded' })]);
    const open = engine.getOpenAlerts();
    expect(open.every(a => a.status === 'OPEN')).toBe(true);
  });
});
