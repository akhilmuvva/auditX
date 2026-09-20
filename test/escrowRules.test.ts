// @ts-nocheck
import { EventClassifier } from '../legacy/src/siem/EventClassifier.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

describe('Phase 4: PolyLance Escrow Security Detection Rules Matrix', () => {
  const classifier = new EventClassifier();

  function baseEvent(eventName: string, args: Record<string, any> = {}): ChainEvent {
    return {
      id: `ev-test-${Date.now()}-${Math.random()}`,
      timestamp: Date.now(),
      chainId: 137,
      contractAddress: '0xbe74923bbfd72d400a681915dbcf6e6adc72c317',
      txHash: '0x4f8a12bc90de45f678901234567890abcdef1234567890abcdef1234567890ab',
      blockNumber: 50000000,
      eventName,
      args,
      gasUsed: 80000,
      callValue: '0',
      from: '0x1234567890123456789012345678901234567890',
    };
  }

  // ── Rule 1: PaymentReleased without Funding or Submitted Work ───────────────
  describe('Rule 1: Unfunded/Unsubmitted Release Bypass', () => {
    it('POSITIVE: triggers CRITICAL alert when PaymentReleased occurs without funding or work submission', () => {
      const ev = baseEvent('PaymentReleased', {
        unfunded: true,
        toFreelancer: '1000000000000000000',
        fee: '25000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('PaymentReleased without required funding');
    });

    it('POSITIVE: triggers CRITICAL alert when PaymentReleased amount exceeds fundedAmount', () => {
      const ev = baseEvent('PaymentReleased', {
        fundedAmount: '1000000000000000000',
        toFreelancer: '2000000000000000000',
        fee: '50000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.reason).toContain('PaymentReleased without required funding');
    });

    it('NEGATIVE: normal PaymentReleased within funded balance does not trigger bypass rule', () => {
      const ev = baseEvent('PaymentReleased', {
        fundedAmount: '1000000000000000000',
        toFreelancer: '975000000000000000',
        fee: '25000000000000000',
        feeBps: 250,
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).not.toBe('CRITICAL');
    });
  });

  // ── Rule 2: DisputeResolved by Non-Arbitrator or Invalid Split ──────────────
  describe('Rule 2: Unauthorized Dispute Resolution', () => {
    it('POSITIVE: triggers CRITICAL alert when DisputeResolved is called by unauthorized judge', () => {
      const ev = baseEvent('DisputeResolved', {
        isArbitrator: false,
        judge: '0x9999999999999999999999999999999999999999',
        freelancerBps: 5000,
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Unauthorized dispute resolution');
    });

    it('POSITIVE: triggers CRITICAL alert when freelancerBps > 10000 (> 100%)', () => {
      const ev = baseEvent('DisputeResolved', {
        isArbitrator: true,
        judge: '0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A',
        freelancerBps: 15000,
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.reason).toContain('invalid split (15000 bps)');
    });

    it('NEGATIVE: valid DisputeResolved by authorized arbitrator with valid bps passes normally', () => {
      const ev = baseEvent('DisputeResolved', {
        isArbitrator: true,
        judge: '0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A',
        freelancerBps: 7000,
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).not.toBe('CRITICAL');
    });
  });

  // ── Rule 3: Premature AutoReleased ──────────────────────────────────────────
  describe('Rule 3: Premature AutoRelease', () => {
    it('POSITIVE: triggers HIGH alert when AutoReleased occurs before reviewPeriod has elapsed', () => {
      const ev = baseEvent('AutoReleased', {
        premature: true,
        elapsedSeconds: 86400, // 1 day instead of 7 days
        reviewPeriod: 604800, // 7 days
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('HIGH');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Premature auto-release');
    });

    it('NEGATIVE: AutoReleased after review period has elapsed passes without anomaly', () => {
      const ev = baseEvent('AutoReleased', {
        premature: false,
        elapsedSeconds: 700000, // > 7 days
        reviewPeriod: 604800,
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).not.toBe('HIGH');
    });
  });

  // ── Rule 4: Platform Fee Anomaly (>2.5%) ────────────────────────────────────
  describe('Rule 4: Platform Fee Anomaly', () => {
    it('POSITIVE: triggers HIGH alert when fee exceeds 2.5% (250 bps)', () => {
      const ev = baseEvent('FeeCollected', {
        feeBps: 500, // 5%
        amount: '50000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('HIGH');
      expect(classified.category).toBe('GOVERNANCE');
      expect(classified.reason).toContain('Platform fee rate anomaly');
    });

    it('NEGATIVE: FeeCollected at exactly 2.5% (250 bps) passes normally', () => {
      const ev = baseEvent('FeeCollected', {
        feeBps: 250,
        amount: '25000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).not.toBe('HIGH');
    });
  });

  // ── Rule 5: Escrow Balance Drain / Unmatched Transfer ───────────────────────
  describe('Rule 5: Escrow Balance Drain / Unmatched Transfer', () => {
    it('POSITIVE: triggers CRITICAL alert when direct Transfer out of escrow occurs without release event', () => {
      const ev = baseEvent('Transfer', {
        unmatchedEscrowDrain: true,
        from: '0xbe74923bbfd72d400a681915dbcf6e6adc72c317',
        to: '0xattacker',
        value: '10000000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('LARGE_WITHDRAWAL');
      expect(classified.reason).toContain('Escrow drain detected');
    });

    it('NEGATIVE: normal Transfer event without drain flag classified as standard Transfer', () => {
      const ev = baseEvent('Transfer', {
        from: '0xuser1',
        to: '0xuser2',
        value: '100000000000000000',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('INFO');
      expect(classified.category).toBe('TRANSFER');
    });
  });

  // ── Rule 6: Factory Role Escalation / Governance Tampering ──────────────────
  describe('Rule 6: Factory Role Escalation', () => {
    it('POSITIVE: triggers CRITICAL alert on unauthorized RoleGranted or RoleRevoked on JobFactory', () => {
      const ev = baseEvent('RoleGranted', {
        unauthorized: true,
        role: '0x992488bd2b61d3d729f4b33b26659ecab37870584fdfaa3b4036cb56ab331895', // ARBITRATOR_ROLE
        account: '0xattacker',
        sender: '0xunauthorized',
      });
      const classified = classifier.classify(ev);
      expect(classified.ruleSeverity).toBe('CRITICAL');
      expect(classified.category).toBe('OWNERSHIP_CHANGE');
      expect(classified.reason).toContain('Unauthorized factory role change');
    });

    it('NEGATIVE: authorized governance RoleGranted event does not flag unauthorized anomaly', () => {
      const ev = baseEvent('RoleGranted', {
        unauthorized: false,
        role: '0x992488bd2b61d3d729f4b33b26659ecab37870584fdfaa3b4036cb56ab331895',
        account: '0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A',
        sender: '0xc0Af73834fc45E88664e94D98B77cde62Fc1139E',
      });
      const classified = classifier.classify(ev);
      expect(classified.reason).not.toContain('Unauthorized factory role change');
    });
  });
});
