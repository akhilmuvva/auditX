/**
 * AuditX SIEM — EventClassifier
 *
 * Deterministic rule-based classification engine for Web3 / SIEM events.
 * Operates on real on-chain events and evaluates state against StateTracker.
 * Zero hand-typed synthetic flags.
 */

import type {
  ChainEvent,
  ClassifiedEvent,
  EventCategory,
  EventSeverity,
} from './types.js';
import { StateTracker } from './StateTracker.js';

export class EventClassifier {
  private tracker: StateTracker;

  constructor(tracker?: StateTracker) {
    this.tracker = tracker || new StateTracker();
  }

  getTracker(): StateTracker {
    return this.tracker;
  }

  classifyBatch(events: ChainEvent[]): ClassifiedEvent[] {
    return events.map((e) => this.classify(e));
  }

  classify(event: ChainEvent): ClassifiedEvent {
    const eName = event.eventName;
    const cAddr = event.contractAddress.toLowerCase();
    const args = event.args || {};
    const clone = this.tracker.getClone(cAddr);

    // ── Rule 1: DisputeResolved by non-arbitrator or invalid split ──────────
    if (eName === 'DisputeResolved') {
      const judge = String(args.judge || event.from).toLowerCase();
      const bps = BigInt(String(args.freelancerBps ?? args.bps ?? 0));
      if (!this.tracker.hasArbitrator(judge)) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `DisputeResolved by unauthorized non-arbitrator account ${judge}`,
        };
      }
      if (bps > 10000n) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `Invalid dispute resolution split (${bps} bps > 10000)`,
        };
      }
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'LOW',
        reason: `Dispute resolved legitimately by arbitrator ${judge} with ${bps} bps to freelancer`,
      };
    }

    // ── Rule 2: PaymentReleased validations ─────────────────────────────────
    if (eName === 'PaymentReleased') {
      const toFreelancer = BigInt(String(args.toFreelancer ?? 0));
      const fee = BigInt(String(args.fee ?? 0));
      const totalReleased = toFreelancer + fee;

      // 2a. Unfunded release
      if (!clone || clone.fundedAmount === 0n) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `PaymentReleased on unfunded escrow clone ${cAddr}`,
        };
      }

      // 2b. Unsubmitted work release
      if (!clone.workSubmitted) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `PaymentReleased without submitted work deliverable on ${cAddr}`,
        };
      }

      // 2c. Released amount > funded
      if (totalReleased > clone.fundedAmount) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'LARGE_WITHDRAWAL',
          ruleSeverity: 'CRITICAL',
          reason: `PaymentReleased amount (${totalReleased}) exceeds funded escrow amount (${clone.fundedAmount}) on ${cAddr}`,
        };
      }

      // 2d. Platform fee anomaly check (standard 250 bps = 2.5%)
      if (totalReleased > 0n) {
        const feeRatioBps = (fee * 10000n) / totalReleased;
        if (feeRatioBps !== 250n && (feeRatioBps < 240n || feeRatioBps > 260n)) {
          this.tracker.recordEvent(event);
          return {
            ...event,
            category: 'GOVERNANCE',
            ruleSeverity: 'HIGH',
            reason: `Platform fee anomaly: fee ratio ${feeRatioBps} bps deviates from configured platform fee (250 bps) on ${cAddr}`,
          };
        }
      }

      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'INFO',
        reason: `Legitimate payment released: ${toFreelancer} to freelancer, ${fee} platform fee`,
      };
    }

    // ── Rule 3: Premature AutoReleased ───────────────────────────────────────
    if (eName === 'AutoReleased') {
      const currentSec = Math.floor(event.timestamp / 1000);
      if (!clone || clone.workSubmittedAt === 0 || currentSec < clone.workSubmittedAt + clone.reviewPeriod) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'HIGH',
          reason: `Premature auto-release: escrow claimed before mandatory review period elapsed on ${cAddr}`,
        };
      }
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'LOW',
        reason: `Auto-release claimed legitimately after review period elapsed on ${cAddr}`,
      };
    }

    // ── Rule 4: ERC20 Transfer / Escrow Drain ───────────────────────────────
    if (eName === 'Transfer') {
      const fromAddr = (args.from as string)?.toLowerCase();
      if (fromAddr && this.tracker.isClone(fromAddr)) {
        const txEvents = this.tracker.getTxEvents(event.txHash);
        const hasLegitRelease =
          txEvents.has('PaymentReleased') ||
          txEvents.has('JobCancelled') ||
          txEvents.has('DisputeResolved') ||
          txEvents.has('AutoReleased');

        if (!hasLegitRelease) {
          this.tracker.recordEvent(event);
          return {
            ...event,
            category: 'LARGE_WITHDRAWAL',
            ruleSeverity: 'CRITICAL',
            reason: `Unmatched escrow drain: ERC20 Transfer of ${args.value ?? 0} tokens from clone ${fromAddr} without legitimate escrow release in tx ${event.txHash}`,
          };
        }
      }
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'TRANSFER',
        ruleSeverity: 'INFO',
        reason: `ERC20 Transfer from ${args.from} to ${args.to}`,
      };
    }

    // ── Rule 5: Factory Role Modifications & Payment Token Approvals ────────────────
    if (eName === 'RoleGranted' || eName === 'RoleRevoked') {
      const sender = String(args.sender || event.from || '').toLowerCase();
      const account = String(args.account || '').toLowerCase();
      const role = String(args.role || '');

      if (!this.tracker.hasAdmin(sender)) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `Unauthorized factory role modification: ${eName} role ${role} for account ${account} by non-admin ${sender}`,
        };
      }

      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'INFO',
        reason: `Authorized factory role modification: ${eName} role ${role} for account ${account} by admin ${sender}`,
      };
    }

    if (eName === 'PaymentTokenApproved') {
      const sender = String(args.sender || event.from || '').toLowerCase();
      const token = String(args.token || args.paymentToken || '').toLowerCase();
      const approved = Boolean(args.approved);

      if (!this.tracker.hasAdmin(sender)) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'CRITICAL',
          reason: `Unauthorized payment token modification: token ${token} approved=${approved} by non-admin ${sender}`,
        };
      }

      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'INFO',
        reason: `Authorized payment token modification: token ${token} approved=${approved} by admin ${sender}`,
      };
    }

    // ── General DeFi / SIEM rules ───────────────────────────────────────────
    if (eName === 'Upgraded' || eName === 'EmergencyShutdown') {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'UPGRADE',
        ruleSeverity: 'CRITICAL',
        reason: `Contract implementation upgraded or emergency shutdown executed: ${eName}`,
      };
    }

    if (eName === 'Paused' || eName === 'EmergencyStop') {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'PAUSE',
        ruleSeverity: 'MEDIUM',
        reason: `Contract execution paused: ${eName}`,
      };
    }

    if (eName === 'FlashLoan' || eName.toLowerCase().includes('flashloan')) {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'FLASH_LOAN',
        ruleSeverity: 'HIGH',
        reason: `Flash loan detected: ${args.amount || event.callValue} borrowed`,
      };
    }

    if (eName === 'Swap') {
      const sender = String(args.sender || '').toLowerCase();
      const recipient = String(args.recipient || '').toLowerCase();
      if (sender && recipient && sender === recipient) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'FLASH_LOAN',
          ruleSeverity: 'MEDIUM',
          reason: `Self-directed swap (sender == recipient), potential sandwich/atomic routing`,
        };
      }
    }

    if (eName === 'ProposalExecuted') {
      const delay = Number(args.delay ?? 0);
      if (delay === 0) {
        this.tracker.recordEvent(event);
        return {
          ...event,
          category: 'GOVERNANCE',
          ruleSeverity: 'HIGH',
          reason: `Timelock bypass: ProposalExecuted with zero timelock delay`,
        };
      }
    }

    if (eName === 'Approval') {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'APPROVAL',
        ruleSeverity: 'INFO',
        reason: `Token approval granted`,
      };
    }

    if (eName === 'OwnershipTransferred' || eName === 'RoleAdminChanged') {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'OWNERSHIP_CHANGE',
        ruleSeverity: 'HIGH',
        reason: `Administrative ownership or role admin changed`,
      };
    }

    // Default Fallback
    const knownEscrowEvents = [
      'JobPosted',
      'ApplicationSubmitted',
      'FreelancerSelected',
      'SelectionDeclined',
      'TermsProposed',
      'JobFunded',
      'ProgressUpdatePosted',
      'ModificationRequested',
      'TimeExtensionRequested',
      'TimeExtensionResponded',
      'WorkSubmitted',
      'FeeCollected',
      'DisputeRaised',
      'DisputeResponseSubmitted',
      'CancelConsentGiven',
      'JobCancelled',
      'TreasuryWithdrawal',
    ];

    if (knownEscrowEvents.includes(eName)) {
      this.tracker.recordEvent(event);
      return {
        ...event,
        category: 'GOVERNANCE',
        ruleSeverity: 'INFO',
        reason: `Processed ${eName} on ${cAddr}`,
      };
    }

    // Completely unknown event
    this.tracker.recordEvent(event);
    return {
      ...event,
      category: 'UNKNOWN',
      ruleSeverity: 'INFO',
      reason: `Unknown contract event: ${eName}`,
    };
  }
}
