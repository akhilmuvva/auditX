/**
 * AuditX SIEM — AnomalyDetector
 *
 * Lightweight statistical anomaly detector based on Welford's online algorithm
 * for computing running mean and variance.  No ML dependencies — works in any
 * Node.js environment without native add-ons.
 *
 * Cold-start handling (per user spec):
 *   If historicalEvents.length < 100, synthetic baseline training data is
 *   generated using a normal distribution around typical ERC-20 transfer
 *   gasUsed (65 000) and callValue (0).  This ensures meaningful z-scores
 *   from the very first real event.
 */

import type {
  ClassifiedEvent,
  AnomalyScore,
  ScoredEvent,
  EventSeverity,
} from './types.js';

// ─── Welford online statistics ───────────────────────────────────────────────

interface WelfordState {
  n: number;
  mean: number;
  M2: number;
}

function welfordUpdate(state: WelfordState, value: number): WelfordState {
  const n = state.n + 1;
  const delta = value - state.mean;
  const mean = state.mean + delta / n;
  const delta2 = value - mean;
  const M2 = state.M2 + delta * delta2;
  return { n, mean, M2 };
}

function welfordVariance(state: WelfordState): number {
  return state.n < 2 ? 0 : state.M2 / (state.n - 1);
}

function welfordStdDev(state: WelfordState): number {
  return Math.sqrt(welfordVariance(state));
}

// ─── Normal distribution PRNG (Box-Muller) ───────────────────────────────────

function gaussianRandom(mean: number, std: number): number {
  // Box-Muller transform
  const u1 = 1 - Math.random(); // avoid 0
  const u2 = Math.random();
  const z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z0 * std;
}

// ─── Detector ────────────────────────────────────────────────────────────────

const SYNTHETIC_SAMPLE_COUNT = 100;
const ERC20_GAS_MEAN = 65_000;
const ERC20_GAS_STD = 5_000;
const ERC20_VALUE_MEAN = 0;
const ERC20_VALUE_STD = 1e15; // 0.001 ETH std in wei

/** Anomaly z-score threshold — events beyond this are flagged. */
const Z_THRESHOLD = 3.0;

/** Weight of gas vs value z-score in combined score (must sum to 1.0). */
const GAS_WEIGHT = 0.6;
const VALUE_WEIGHT = 0.4;

export class AnomalyDetector {
  private gasState: WelfordState = { n: 0, mean: 0, M2: 0 };
  private valueState: WelfordState = { n: 0, mean: 0, M2: 0 };

  /** Injected synthetic event count (visible for diagnostics) */
  public syntheticSamples = 0;

  /**
   * Train the detector on historical events.
   *
   * If historicalEvents.length < 100, synthetic baseline data is generated
   * using a normal distribution around typical ERC-20 transfer parameters
   * to handle the cold-start problem.
   */
  train(historicalEvents: ClassifiedEvent[]): void {
    // ── Cold-start synthetic data ──────────────────────────────────────────
    if (historicalEvents.length < SYNTHETIC_SAMPLE_COUNT) {
      const synthCount = SYNTHETIC_SAMPLE_COUNT - historicalEvents.length;
      this.syntheticSamples = synthCount;

      for (let i = 0; i < synthCount; i++) {
        const gasUsed = Math.max(21_000, gaussianRandom(ERC20_GAS_MEAN, ERC20_GAS_STD));
        const callValue = Math.max(0, gaussianRandom(ERC20_VALUE_MEAN, ERC20_VALUE_STD));
        this.gasState = welfordUpdate(this.gasState, gasUsed);
        this.valueState = welfordUpdate(this.valueState, callValue);
      }
    }

    // ── Real events ───────────────────────────────────────────────────────
    for (const event of historicalEvents) {
      const val = Number(event.callValue ?? '0');
      this.gasState = welfordUpdate(this.gasState, event.gasUsed);
      this.valueState = welfordUpdate(this.valueState, val);
    }
  }

  /**
   * Score a single classified event for anomalousness.
   * Returns a normalised [0..1] score where ≥ 0.7 is "anomalous".
   */
  score(event: ClassifiedEvent): AnomalyScore {
    const gasStd = welfordStdDev(this.gasState) || 1;
    const valueStd = welfordStdDev(this.valueState) || 1;

    const gasZ = Math.abs((event.gasUsed - this.gasState.mean) / gasStd);
    const valueZ = Math.abs(
      (Number(event.callValue ?? '0') - this.valueState.mean) / valueStd
    );

    // Sigmoid normalise combined z-score to [0..1]
    const combinedZ = GAS_WEIGHT * gasZ + VALUE_WEIGHT * valueZ;
    const normScore = 1 / (1 + Math.exp(-0.5 * (combinedZ - Z_THRESHOLD)));

    return {
      gasZScore: gasZ,
      valueZScore: valueZ,
      score: normScore,
      isAnomaly: combinedZ >= Z_THRESHOLD,
    };
  }

  /**
   * Update the running baseline with a newly observed event (online learning).
   */
  update(event: ClassifiedEvent): void {
    this.gasState = welfordUpdate(this.gasState, event.gasUsed);
    this.valueState = welfordUpdate(
      this.valueState,
      Number(event.callValue ?? '0')
    );
  }

  /**
   * Score and update in one step — call this for real-time streaming events.
   */
  scoreAndUpdate(event: ClassifiedEvent): AnomalyScore {
    const result = this.score(event);
    this.update(event);
    return result;
  }

  /**
   * Apply anomaly scoring to a batch of classified events and return
   * ScoredEvent[] with an escalated finalSeverity if anomalous.
   */
  scoreBatch(events: ClassifiedEvent[]): ScoredEvent[] {
    return events.map((event) => {
      const anomaly = this.scoreAndUpdate(event);

      // Escalate severity if strongly anomalous
      let finalSeverity: EventSeverity = event.ruleSeverity;
      if (anomaly.isAnomaly) {
        finalSeverity = escalateSeverity(event.ruleSeverity, anomaly.score);
      }

      return { ...event, anomaly, finalSeverity };
    });
  }

  /** Return current baseline stats (useful for debugging / dashboards) */
  getBaseline() {
    return {
      gasUsed: {
        mean: this.gasState.mean,
        stdDev: welfordStdDev(this.gasState),
        n: this.gasState.n,
      },
      callValue: {
        mean: this.valueState.mean,
        stdDev: welfordStdDev(this.valueState),
        n: this.valueState.n,
      },
      syntheticSamples: this.syntheticSamples,
    };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: EventSeverity[] = [
  'INFO',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
];

function escalateSeverity(
  current: EventSeverity,
  anomalyScore: number
): EventSeverity {
  const idx = SEVERITY_ORDER.indexOf(current);
  // Escalate by 1 level for mild anomaly, by 2 for strong anomaly
  const bump = anomalyScore >= 0.9 ? 2 : 1;
  return SEVERITY_ORDER[Math.min(idx + bump, SEVERITY_ORDER.length - 1)];
}
