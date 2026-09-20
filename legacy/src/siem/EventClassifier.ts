/**
 * AuditX SIEM — EventClassifier
 *
 * Pure rule-based classification engine. Maps raw on-chain events to typed
 * categories and assigns an initial rule-severity.  No ML, no async — just
 * fast deterministic logic that runs inside or outside a worker thread.
 */

import type {
  ChainEvent,
  ClassifiedEvent,
  EventCategory,
  EventSeverity,
} from './types.js';

// ─── Rule Table ──────────────────────────────────────────────────────────────

function parseValueWei(valStr?: string | number): bigint {
  if (valStr === undefined || valStr === null) return 0n;
  const str = String(valStr).trim();
  if (!str) return 0n;
  try {
    if (str.includes('.')) {
      const parts = str.split('.');
      const whole = BigInt(parts[0] || '0');
      const frac = (parts[1] || '').padEnd(18, '0').slice(0, 18);
      return whole * 10n ** 18n + BigInt(frac);
    }
    return BigInt(str);
  } catch {
    return 0n;
  }
}

interface ClassifyRule {
  category: EventCategory;
  severity: EventSeverity;
  /** Returns a human-readable reason string if the rule matches, or null */
  match(event: ChainEvent): string | null;
}

const RULES: ClassifyRule[] = [
  // ── Escrow Security Threat Detection Rules ─────────────────────────────
  {
    category: 'GOVERNANCE',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'disputeresolved' || (n.includes('dispute') && n.includes('resolve'))) {
        const bps = Number(e.args['freelancerBps'] ?? e.args['bps'] ?? 0);
        const unauthorizedJudge = e.args['isArbitrator'] === false || e.args['unauthorizedJudge'] === true || e.args['unauthorized'] === true;
        if (unauthorizedJudge || bps > 10000) {
          return `Unauthorized dispute resolution or invalid split (${bps} bps) on JobEscrow`;
        }
      }
      return null;
    },
  },
  {
    category: 'GOVERNANCE',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'paymentreleased' || n === 'fund-release') {
        const unfundedOrUnsubmitted = e.args['unfunded'] === true || e.args['unsubmitted'] === true || e.args['bypassed'] === true;
        const toFreelancer = parseValueWei(e.args['toFreelancer'] as any);
        const fee = parseValueWei(e.args['fee'] as any);
        const fundedAmount = parseValueWei(e.args['fundedAmount'] as any);
        const overflow = fundedAmount > 0n && (toFreelancer + fee > fundedAmount);

        if (unfundedOrUnsubmitted || overflow) {
          return `Unauthorized escrow fund release: PaymentReleased without required funding or submitted work validation`;
        }
      }
      return null;
    },
  },
  {
    category: 'GOVERNANCE',
    severity: 'HIGH',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'autoreleased' || n === 'auto-release') {
        const premature = e.args['premature'] === true || e.args['reviewPeriodActive'] === true;
        const elapsed = Number(e.args['elapsedSeconds'] ?? 999999);
        const reviewPeriod = Number(e.args['reviewPeriod'] ?? 7 * 86400);
        if (premature || elapsed < reviewPeriod) {
          return `Premature auto-release: escrow claimed before mandatory review period elapsed`;
        }
      }
      return null;
    },
  },
  {
    category: 'GOVERNANCE',
    severity: 'HIGH',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'feecollected' || n === 'paymentreleased' || n === 'fund-release') {
        const feeBps = Number(e.args['feeBps'] ?? 0);
        const feeAnomaly = e.args['feeAnomaly'] === true || feeBps > 250;
        if (feeAnomaly) {
          return `Platform fee rate anomaly: fee (${feeBps} bps) exceeds 2.5% (250 bps) platform limit`;
        }
      }
      return null;
    },
  },
  {
    category: 'LARGE_WITHDRAWAL',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'transfer' && (e.args['unmatchedEscrowDrain'] === true || e.args['isEscrowDrain'] === true)) {
        return `Escrow drain detected: direct token/native asset transfer without matching release or cancellation event`;
      }
      return null;
    },
  },
  {
    category: 'OWNERSHIP_CHANGE',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if ((n === 'rolegranted' || n === 'rolerevoked') && (e.args['unauthorized'] === true || e.args['senderIsNotAdmin'] === true)) {
        return `Unauthorized factory role change: ${e.eventName} on JobFactory without administrative authorization`;
      }
      return null;
    },
  },

  // ── Governance Speedrun Heuristic ───────────────────────────────────────
  {
    category: 'GOVERNANCE',
    severity: 'HIGH',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        (n.includes('proposalexecuted') || n.includes('ruleexecuted')) &&
        (e.args['delay'] === 0 || e.args['delay'] === '0' || e.args['emergency'] === true || e.args['speedrun'] === true)
      ) {
        return `Governance speedrun detected: instant execution event "${e.eventName}" with 0 delay`;
      }
      return null;
    },
  },

  // ── MEV / Sandwich Heuristic ─────────────────────────────────────────────
  {
    category: 'FLASH_LOAN',
    severity: 'MEDIUM',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        (n.includes('swap') || n.includes('arbitrage')) &&
        e.args['sender'] !== undefined &&
        e.args['sender'] === e.args['recipient']
      ) {
        return `Circular swap detected: sender "${e.args['sender']}" matches recipient (possible sandwich/arbitrage)`;
      }
      return null;
    },
  },

  // ── Emergency Shutdown / Selfdestruct Heuristic ──────────────────────────
  {
    category: 'UPGRADE',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        n.includes('selfdestruct') ||
        n.includes('suicide') ||
        n.includes('killcontract') ||
        n.includes('emergencyshutdown')
      ) {
        return `Emergency contract destruction signature "${e.eventName}" detected`;
      }
      return null;
    },
  },

  // ── Flash Loan ──────────────────────────────────────────────────────────
  {
    category: 'FLASH_LOAN',
    severity: 'HIGH',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n.includes('flashloan') || n.includes('flash_loan')) {
        return `Flash-loan event "${e.eventName}" detected`;
      }
      return null;
    },
  },

  // ── Reentrancy signal: abnormally deep call + value ─────────────────────
  {
    category: 'REENTRANCY_SIGNAL',
    severity: 'HIGH',
    match(e) {
      const val = parseValueWei(e.callValue);
      // High-gas + non-zero value transfer in a Withdrawal-like event
      if (
        (e.eventName.toLowerCase().includes('withdraw') ||
          e.eventName.toLowerCase().includes('transfer') ||
          e.eventName.toLowerCase().includes('fund-release')) &&
        e.gasUsed > 150_000 &&
        val > 0n
      ) {
        return `High-gas withdrawal/fund-release (${e.gasUsed} gas) — potential reentrancy`;
      }
      return null;
    },
  },

  // ── Ownership change ────────────────────────────────────────────────────
  {
    category: 'OWNERSHIP_CHANGE',
    severity: 'HIGH',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        n.includes('ownershiptransferred') ||
        n.includes('adminchanged') ||
        n.includes('ownershiprenounced') ||
        n.includes('rolerevoked') ||
        n.includes('rolegranted')
      ) {
        return `Privilege change event "${e.eventName}"`;
      }
      return null;
    },
  },

  // ── Contract upgrade / proxy beacon ─────────────────────────────────────
  {
    category: 'UPGRADE',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        n.includes('upgraded') ||
        n.includes('implementationset') ||
        n.includes('beaconupgraded')
      ) {
        return `Proxy upgrade event "${e.eventName}"`;
      }
      return null;
    },
  },

  // ── Contract pause / unpause ─────────────────────────────────────────────
  {
    category: 'PAUSE',
    severity: 'MEDIUM',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (n === 'paused' || n === 'unpaused') {
        return `Circuit-breaker ${n} triggered`;
      }
      return null;
    },
  },

  // ── Governance ───────────────────────────────────────────────────────────
  {
    category: 'GOVERNANCE',
    severity: 'MEDIUM',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        n.includes('proposalcreated') ||
        n.includes('proposalexecuted') ||
        n.includes('votecast') ||
        n.includes('votingperiodset') ||
        n.includes('quorumset')
      ) {
        return `Governance action "${e.eventName}"`;
      }
      return null;
    },
  },

  // ── Oracle / price manipulation signal ─────────────────────────────────
  {
    category: 'ORACLE_MANIPULATION',
    severity: 'CRITICAL',
    match(e) {
      const n = e.eventName.toLowerCase();
      if (
        n.includes('priceupdated') ||
        n.includes('answerupdated') ||
        n.includes('oracleset')
      ) {
        // Flag if price swing arg looks suspicious (> 50% from prev, if available)
        const newPrice = Number(e.args['current'] ?? e.args['price'] ?? 0);
        const oldPrice = Number(e.args['previous'] ?? e.args['previousPrice'] ?? 0);
        if (oldPrice > 0 && Math.abs(newPrice - oldPrice) / oldPrice > 0.5) {
          return `Oracle price moved >50% in one update (${oldPrice} → ${newPrice})`;
        }
        // Otherwise just classify, no anomaly yet
        return null;
      }
      return null;
    },
  },

  // ── Large withdrawal ─────────────────────────────────────────────────────
  {
    category: 'LARGE_WITHDRAWAL',
    severity: 'HIGH',
    match(e) {
      const val = parseValueWei(e.callValue);
      const THRESHOLD_WEI = 10n * 10n ** 18n; // 10 ETH
      if (
        (e.eventName.toLowerCase().includes('withdraw') || e.eventName.toLowerCase().includes('fund-release')) &&
        val > THRESHOLD_WEI
      ) {
        return `Large withdrawal: ${Number(val / 10n ** 15n) / 1000} ETH`;
      }
      // Also check args for 'amount' in case it's a token withdrawal
      const amount = parseValueWei(e.args['amount'] as string | undefined);
      const TOKEN_THRESHOLD = 10n * 10n ** 18n; // 10e18 tokens
      if (
        (e.eventName.toLowerCase().includes('withdraw') || e.eventName.toLowerCase().includes('fund-release')) &&
        amount > TOKEN_THRESHOLD
      ) {
        return `Large token withdrawal: ${amount.toString()} units`;
      }
      return null;
    },
  },

  // ── ERC-20 Approval ──────────────────────────────────────────────────────
  {
    category: 'APPROVAL',
    severity: 'LOW',
    match(e) {
      if (e.eventName === 'Approval') return 'ERC-20/721 Approval event';
      return null;
    },
  },

  // ── ERC-20 Transfer ──────────────────────────────────────────────────────
  {
    category: 'TRANSFER',
    severity: 'INFO',
    match(e) {
      if (e.eventName === 'Transfer') return 'ERC-20/721 Transfer event';
      return null;
    },
  },
];

// ─── Classifier ──────────────────────────────────────────────────────────────

export class EventClassifier {
  /**
   * Classify a single chain event.
   * Rules are evaluated in priority order; the first match wins.
   */
  classify(event: ChainEvent): ClassifiedEvent {
    for (const rule of RULES) {
      const reason = rule.match(event);
      if (reason !== null) {
        return {
          ...event,
          category: rule.category,
          reason,
          ruleSeverity: rule.severity,
        };
      }
    }

    return {
      ...event,
      category: 'UNKNOWN',
      reason: `No rule matched event "${event.eventName}"`,
      ruleSeverity: 'INFO',
    };
  }

  /**
   * Classify a batch of events.
   */
  classifyBatch(events: ChainEvent[]): ClassifiedEvent[] {
    return events.map((e) => this.classify(e));
  }
}
