import { describe, it, expect, beforeEach } from '@jest/globals';
import { EventClassifier } from '../legacy/src/siem/EventClassifier.js';
import { StateTracker } from '../legacy/src/siem/StateTracker.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

describe('Phase 4: PolyLance Escrow Security Threat Rules (StateTracker + Real Event Fields)', () => {
  let tracker: StateTracker;
  let classifier: EventClassifier;
  const cloneAddress = '0x1111111111111111111111111111111111111111';
  const factoryAddress = '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317';
  const clientAddress = '0x2222222222222222222222222222222222222222';
  const freelancerAddress = '0x3333333333333333333333333333333333333333';
  const authorizedJudge = '0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A';
  const unauthorizedAttacker = '0x9999999999999999999999999999999999999999';

  beforeEach(() => {
    tracker = new StateTracker();
    tracker.addFactoryAddress(factoryAddress);
    tracker.addArbitrator(authorizedJudge);
    classifier = new EventClassifier(tracker);
  });

  function createRealEvent(
    contract: string,
    eventName: string,
    args: Record<string, unknown>,
    txHash: string = '0x4f8a12bc90de45f678901234567890abcdef1234567890abcdef1234567890ab',
    timestampMs: number = 1700000000000
  ): ChainEvent {
    return {
      id: `ev-${txHash}-${Math.random()}`,
      timestamp: timestampMs,
      chainId: 137,
      contractAddress: contract.toLowerCase(),
      txHash,
      blockNumber: 50000000,
      eventName,
      args,
      gasUsed: 85000,
      callValue: '0',
      from: clientAddress.toLowerCase(),
    };
  }

  // ── Rule 1: PaymentReleased Validation ──────────────────────────────────────
  describe('Rule 1: PaymentReleased Integrity (Unfunded, Unsubmitted, Overflow)', () => {
    it('POSITIVE: flags CRITICAL when PaymentReleased is emitted on an unfunded clone', () => {
      // Step 1: Clone deployed and posted, but never funded
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));

      // Step 2: PaymentReleased arrives
      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = classifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('PaymentReleased on unfunded escrow clone');
    });

    it('POSITIVE: flags CRITICAL when PaymentReleased is emitted without submitted work deliverable', () => {
      // Clone deployed and funded, but work was never submitted
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));

      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = classifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.reason).toContain('without submitted work deliverable');
    });

    it('POSITIVE: flags CRITICAL when released sum exceeds funded balance (overflow drain)', () => {
      // Funded with 1 token
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'SIEM Audit Report',
        evidenceCount: 2n,
      }));

      // Release attempts 2 tokens (toFreelancer = 1.95, fee = 0.05 -> total 2.0 > 1.0)
      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 1950000000000000000n,
        fee: 50000000000000000n,
      });

      const classified = classifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('LARGE_WITHDRAWAL');
      expect(classified.reason).toContain('exceeds funded escrow amount');
    });

    it('NEGATIVE: legitimate PaymentReleased with funding, submitted work, and valid amount passes with INFO', () => {
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'SIEM Audit Report',
        evidenceCount: 2n,
      }));

      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = classifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.reason).toContain('Legitimate payment released');
    });
  });

  // ── Rule 2: Dispute Resolution Authority ────────────────────────────────────
  describe('Rule 2: Dispute Resolution by Non-Arbitrator or Invalid Split', () => {
    it('POSITIVE: flags CRITICAL when DisputeResolved is emitted with an unauthorized judge', () => {
      const disputeEvent = createRealEvent(cloneAddress, 'DisputeResolved', {
        judge: unauthorizedAttacker,
        freelancerBps: 5000n,
        reasoningIpfsHash: 'QmTestRuling',
      });

      const classified = classifier.classify(disputeEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('unauthorized non-arbitrator account');
    });

    it('POSITIVE: flags CRITICAL when DisputeResolved split exceeds 10,000 bps (100%)', () => {
      const disputeEvent = createRealEvent(cloneAddress, 'DisputeResolved', {
        judge: authorizedJudge,
        freelancerBps: 15000n,
        reasoningIpfsHash: 'QmInvalidSplitRuling',
      });

      const classified = classifier.classify(disputeEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.reason).toContain('Invalid dispute resolution split (15000 bps > 10000)');
    });

    it('NEGATIVE: DisputeResolved by authorized arbitrator with valid bps passes normally', () => {
      const disputeEvent = createRealEvent(cloneAddress, 'DisputeResolved', {
        judge: authorizedJudge,
        freelancerBps: 8000n,
        reasoningIpfsHash: 'QmValidRuling',
      });

      const classified = classifier.classify(disputeEvent);
      expect(classified.ruleSeverity).toBe('LOW');
      expect(classified.reason).toContain('Dispute resolved legitimately');
    });
  });

  // ── Rule 3: Premature AutoReleased ──────────────────────────────────────────
  describe('Rule 3: Premature AutoRelease before Review Period', () => {
    it('POSITIVE: flags HIGH when AutoReleased is emitted before 7-day review period expires', () => {
      const workTimestampMs = 1700000000000;
      // Work submitted at t = 1,700,000,000s
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Deliverable',
        evidenceCount: 1n,
      }, '0xtx_work', workTimestampMs));

      // AutoRelease claimed only 1 day later (86,400s < 604,800s review period)
      const prematureTimestampMs = workTimestampMs + (86400 * 1000);
      const autoEvent = createRealEvent(cloneAddress, 'AutoReleased', {}, '0xtx_auto', prematureTimestampMs);

      const classified = classifier.classify(autoEvent);
      expect(classified.ruleSeverity).toBe('HIGH');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Premature auto-release: escrow claimed before mandatory review period elapsed');
    });

    it('NEGATIVE: AutoReleased claimed after 7-day review period passes as LOW severity', () => {
      const workTimestampMs = 1700000000000;
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Deliverable',
        evidenceCount: 1n,
      }, '0xtx_work', workTimestampMs));

      // AutoRelease claimed 8 days later (691,200s > 604,800s review period)
      const validTimestampMs = workTimestampMs + (8 * 86400 * 1000);
      const autoEvent = createRealEvent(cloneAddress, 'AutoReleased', {}, '0xtx_auto_valid', validTimestampMs);

      const classified = classifier.classify(autoEvent);
      expect(classified.ruleSeverity).toBe('LOW');
      expect(classified.reason).toContain('Auto-release claimed legitimately');
    });
  });

  // ── Rule 4: Platform Fee Anomaly ────────────────────────────────────────────
  describe('Rule 4: Platform Fee Ratio Anomaly', () => {
    it('POSITIVE: flags HIGH when fee ratio deviates from configured 250 bps (e.g. 1000 bps / 10%)', () => {
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Work',
        evidenceCount: 1n,
      }));

      // Fee is 100 / 1000 = 10% (1000 bps != 250 bps)
      const anomalyFeeEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 900000000000000000n,
        fee: 100000000000000000n,
      });

      const classified = classifier.classify(anomalyFeeEvent);
      expect(classified.ruleSeverity).toBe('HIGH');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Platform fee anomaly: fee ratio 1000 bps deviates from configured platform fee (250 bps)');
    });

    it('NEGATIVE: PaymentReleased with standard 250 bps (2.5%) fee passes without anomaly', () => {
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Work',
        evidenceCount: 1n,
      }));

      const normalFeeEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = classifier.classify(normalFeeEvent);
      expect(classified.ruleSeverity).toBe('INFO');
    });

    it('NEGATIVE: a clone with a different configured fee (e.g. 500 bps / 5%) does not false-positive', () => {
      const customClone = '0xcustom_fee_clone_500bps';
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: customClone,
        client: clientAddress,
        paymentToken: '0xtoken',
        feeBps: 500, // 5% configured fee
      }));
      tracker.recordEvent(createRealEvent(customClone, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(customClone, 'WorkSubmitted', {
        title: 'Work',
        evidenceCount: 1n,
      }));

      // Fee is 50 / 1000 = 5% (500 bps)
      const customFeeEvent = createRealEvent(customClone, 'PaymentReleased', {
        toFreelancer: 950000000000000000n,
        fee: 50000000000000000n,
      });

      const classified = classifier.classify(customFeeEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.reason).toContain('Legitimate payment released');
    });
  });

  // ── Rule 5: Unmatched Escrow Drain ──────────────────────────────────────────
  describe('Rule 5: Unmatched Escrow Drain (ERC20 Transfer without release event in tx)', () => {
    it('POSITIVE: flags CRITICAL when ERC20 Transfer originates from clone without release/cancel in tx', () => {
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));

      const drainTxHash = '0xdrain_tx_99999999999999999999999999999999999999999999999999999999999999';
      const transferEvent = createRealEvent('0xtoken_contract', 'Transfer', {
        from: cloneAddress,
        to: unauthorizedAttacker,
        value: 1000000000000000000n,
      }, drainTxHash);

      const classified = classifier.classify(transferEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('LARGE_WITHDRAWAL');
      expect(classified.reason).toContain('Unmatched escrow drain: ERC20 Transfer');
    });

    it('NEGATIVE: ERC20 Transfer in the same tx as legitimate PaymentReleased passes normally', () => {
      tracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      tracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Work',
        evidenceCount: 1n,
      }));

      const releaseTxHash = '0xlegit_release_tx_111111111111111111111111111111111111111111111111111111111';
      tracker.recordEvent(createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      }, releaseTxHash));

      const transferEvent = createRealEvent('0xtoken_contract', 'Transfer', {
        from: cloneAddress,
        to: freelancerAddress,
        value: 975000000000000000n,
      }, releaseTxHash);

      const classified = classifier.classify(transferEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.category).toBe('TRANSFER');
    });
  });

  // ── Rule 6: Factory Role Escalation & Token Modification ─────────────────────
  describe('Rule 6: Factory Role Modifications & Payment Token Approvals', () => {
    it('POSITIVE: flags CRITICAL when RoleGranted occurs by a non-admin', () => {
      const roleEvent = createRealEvent(factoryAddress, 'RoleGranted', {
        role: '0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6',
        account: unauthorizedAttacker,
        sender: unauthorizedAttacker,
      });

      const classified = classifier.classify(roleEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Unauthorized factory role modification');
    });

    it('NEGATIVE: passes with INFO when RoleGranted occurs by an authorized admin', () => {
      const adminAddress = '0x1111111111111111111111111111111111111111';
      tracker.addAdmin(adminAddress);

      const roleEvent = createRealEvent(factoryAddress, 'RoleGranted', {
        role: '0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6',
        account: authorizedJudge,
        sender: adminAddress,
      });

      const classified = classifier.classify(roleEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.category).toBe('GOVERNANCE');
      expect(tracker.hasArbitrator(authorizedJudge)).toBe(true);
    });

    it('POSITIVE: flags CRITICAL when PaymentTokenApproved occurs by a non-admin', () => {
      const tokenEvent = createRealEvent(factoryAddress, 'PaymentTokenApproved', {
        token: '0xmalicious_token',
        approved: true,
        sender: unauthorizedAttacker,
      });

      const classified = classifier.classify(tokenEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Unauthorized payment token modification');
    });

    it('NEGATIVE: passes with INFO when PaymentTokenApproved occurs by an authorized admin', () => {
      const adminAddress = '0x1111111111111111111111111111111111111111';
      tracker.addAdmin(adminAddress);

      const tokenEvent = createRealEvent(factoryAddress, 'PaymentTokenApproved', {
        token: '0xvalid_usdt_token',
        approved: true,
        sender: adminAddress,
      });

      const classified = classifier.classify(tokenEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.category).toBe('GOVERNANCE');
    });
  });

  // ── State Initialization & Dynamic Replay ──────────────────────────────────
  describe('State Initialization: Startup Replay & Release Invariants', () => {
    it('start streamer AFTER funded job exists -> replay -> release payment -> asserts NO alert', () => {
      const dynamicTracker = new StateTracker();
      const dynamicClassifier = new EventClassifier(dynamicTracker);

      // Replay pre-existing on-chain state on startup
      dynamicTracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));
      dynamicTracker.recordEvent(createRealEvent(cloneAddress, 'JobFunded', {
        amount: 1000000000000000000n,
      }));
      dynamicTracker.recordEvent(createRealEvent(cloneAddress, 'WorkSubmitted', {
        title: 'Complete SIEM Deliverable',
        evidenceCount: 1n,
      }));

      // Streamer starts and receives PaymentReleased
      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = dynamicClassifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.reason).toContain('Legitimate payment released');
    });

    it('release on an unfunded real clone DOES alert with CRITICAL', () => {
      const dynamicTracker = new StateTracker();
      const dynamicClassifier = new EventClassifier(dynamicTracker);

      dynamicTracker.recordEvent(createRealEvent(factoryAddress, 'JobDeployed', {
        jobContract: cloneAddress,
        client: clientAddress,
        paymentToken: '0xtoken',
      }));

      // PaymentReleased on unfunded clone
      const releaseEvent = createRealEvent(cloneAddress, 'PaymentReleased', {
        toFreelancer: 975000000000000000n,
        fee: 25000000000000000n,
      });

      const classified = dynamicClassifier.classify(releaseEvent);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.reason).toContain('PaymentReleased on unfunded escrow clone');
    });
  });
});

