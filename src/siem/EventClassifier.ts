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

interface ClassifyRule {
  category: EventCategory;
  severity: EventSeverity;
  /** Returns a human-readable reason string if the rule matches, or null */
  match(event: ChainEvent): string | null;
}

const RULES: ClassifyRule[] = [
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
      const val = BigInt(e.callValue ?? '0');
      // High-gas + non-zero value transfer in a Withdrawal-like event
      if (
        (e.eventName.toLowerCase().includes('withdraw') ||
          e.eventName.toLowerCase().includes('transfer')) &&
        e.gasUsed > 150_000 &&
        val > 0n
      ) {
        return `High-gas withdrawal (${e.gasUsed} gas) — potential reentrancy`;
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
      const val = BigInt(e.callValue ?? '0');
      const THRESHOLD_WEI = BigInt('10000000000000000000'); // 10 ETH
      if (
        e.eventName.toLowerCase().includes('withdraw') &&
        val > THRESHOLD_WEI
      ) {
        return `Large withdrawal: ${Number(val) / 1e18} ETH`;
      }
      // Also check args for 'amount' in case it's a token withdrawal
      const amount = BigInt((e.args['amount'] as string | undefined) ?? '0');
      const TOKEN_THRESHOLD = BigInt('10000000000000000000'); // 10e18 tokens
      if (
        e.eventName.toLowerCase().includes('withdraw') &&
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
