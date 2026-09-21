/**
 * AuditX SIEM — StateTracker
 *
 * Maintains on-chain state per JobEscrow clone and JobFactory.
 * State is updated strictly from verified on-chain events and optional view calls.
 */

import type { ChainEvent } from './types.js';

export interface CloneState {
  address: string;
  client: string;
  freelancer: string;
  paymentToken: string;
  status: string;
  fundedAmount: bigint;
  workSubmitted: boolean;
  workSubmittedAt: number; // Unix timestamp in seconds
  reviewPeriod: number; // In seconds (default 7 days = 604800)
  configuredFeeBps: number; // Platform fee in basis points (default 250 = 2.5%)
}

export class StateTracker {
  private clones = new Map<string, CloneState>();
  private factoryAddresses = new Set<string>();
  private adminAddresses = new Set<string>();
  private arbitratorAddresses = new Set<string>();
  private approvedPaymentTokens = new Set<string>();
  private txEventNames = new Map<string, Set<string>>(); // txHash -> Set of eventNames in that tx

  constructor() {
    // Default known PolyLance on-chain role addresses from bundle
    this.adminAddresses.add('0xc0Af73834fc45E88664e94D98B77cde62Fc1139E'.toLowerCase());
    this.adminAddresses.add('0x2BfAAE968b81C1817647498660088F74e1B4cAE3'.toLowerCase());
    this.arbitratorAddresses.add('0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A'.toLowerCase());
    this.arbitratorAddresses.add('0x62cDfc0692cC675c95304BaCE2C834D8F901dCba'.toLowerCase());
    this.arbitratorAddresses.add('0xB8aa0398B91A150B041DA819bc954Bb356e009Dd'.toLowerCase());
    this.factoryAddresses.add('0xbE74923BBfd72d400a681915dBcf6e6Adc72C317'.toLowerCase());
    this.factoryAddresses.add('0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b'.toLowerCase());
  }

  addFactoryAddress(address: string): void {
    this.factoryAddresses.add(address.toLowerCase());
  }

  isFactory(address: string): boolean {
    return this.factoryAddresses.has(address.toLowerCase());
  }

  addAdmin(address: string): void {
    this.adminAddresses.add(address.toLowerCase());
  }

  removeAdmin(address: string): void {
    this.adminAddresses.delete(address.toLowerCase());
  }

  hasAdmin(address: string): boolean {
    return this.adminAddresses.has(address.toLowerCase());
  }

  addArbitrator(address: string): void {
    this.arbitratorAddresses.add(address.toLowerCase());
  }

  removeArbitrator(address: string): void {
    this.arbitratorAddresses.delete(address.toLowerCase());
  }

  hasArbitrator(address: string): boolean {
    return this.arbitratorAddresses.has(address.toLowerCase());
  }

  isClone(address: string): boolean {
    return this.clones.has(address.toLowerCase());
  }

  getClone(address: string): CloneState | undefined {
    return this.clones.get(address.toLowerCase());
  }

  getOrCreateClone(address: string): CloneState {
    const key = address.toLowerCase();
    let state = this.clones.get(key);
    if (!state) {
      state = {
        address: key,
        client: '',
        freelancer: '',
        paymentToken: '',
        status: 'INITIALIZED',
        fundedAmount: 0n,
        workSubmitted: false,
        workSubmittedAt: 0,
        reviewPeriod: 7 * 86400, // 7 days in seconds
        configuredFeeBps: 250, // 2.5%
      };
      this.clones.set(key, state);
    }
    return state;
  }

  getTxEvents(txHash: string): Set<string> {
    return this.txEventNames.get(txHash.toLowerCase()) || new Set<string>();
  }

  recordEvent(event: ChainEvent): void {
    const tx = event.txHash?.toLowerCase() || '';
    if (tx) {
      let set = this.txEventNames.get(tx);
      if (!set) {
        set = new Set<string>();
        this.txEventNames.set(tx, set);
      }
      set.add(event.eventName);
    }

    const cAddr = event.contractAddress.toLowerCase();
    const eName = event.eventName;
    const args = event.args || {};
    const timestampSec = Math.floor(event.timestamp / 1000);

    // Factory Events
    if (eName === 'JobDeployed') {
      const jobContract = (args.jobContract as string)?.toLowerCase();
      if (jobContract) {
        const clone = this.getOrCreateClone(jobContract);
        if (args.client) clone.client = (args.client as string).toLowerCase();
        if (args.paymentToken) clone.paymentToken = (args.paymentToken as string).toLowerCase();
        clone.status = 'DEPLOYED';
      }
      return;
    }

    if (eName === 'RoleGranted') {
      const account = (args.account as string)?.toLowerCase();
      const role = String(args.role || '');
      if (account) {
        // ARBITRATOR_ROLE hash: 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6 or standard
        if (role.includes('ARBITRATOR') || role.startsWith('0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6')) {
          this.addArbitrator(account);
        } else {
          this.addAdmin(account);
        }
      }
      return;
    }

    if (eName === 'RoleRevoked') {
      const account = (args.account as string)?.toLowerCase();
      const role = String(args.role || '');
      if (account) {
        if (role.includes('ARBITRATOR') || role.startsWith('0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6')) {
          this.removeArbitrator(account);
        } else {
          this.removeAdmin(account);
        }
      }
      return;
    }

    // Escrow Clone Events
    const clone = this.getOrCreateClone(cAddr);

    switch (eName) {
      case 'JobPosted':
        if (args.client) clone.client = (args.client as string).toLowerCase();
        if (args.paymentToken) clone.paymentToken = (args.paymentToken as string).toLowerCase();
        clone.status = 'POSTED';
        break;

      case 'FreelancerSelected':
        if (args.freelancer) clone.freelancer = (args.freelancer as string).toLowerCase();
        clone.status = 'FREELANCER_SELECTED';
        break;

      case 'SelectionDeclined':
        clone.freelancer = '';
        clone.status = 'SELECTION_DECLINED';
        break;

      case 'JobFunded':
        if (args.amount !== undefined) {
          clone.fundedAmount = BigInt(String(args.amount));
        }
        clone.status = 'FUNDED';
        break;

      case 'WorkSubmitted':
        clone.workSubmitted = true;
        clone.workSubmittedAt = timestampSec;
        clone.status = 'WORK_SUBMITTED';
        break;

      case 'ModificationRequested':
        clone.workSubmitted = false;
        clone.status = 'MODIFICATION_REQUESTED';
        break;

      case 'PaymentReleased':
        clone.status = 'PAYMENT_RELEASED';
        break;

      case 'AutoReleased':
        clone.status = 'AUTO_RELEASED';
        break;

      case 'CancelConsentGiven':
        clone.status = 'CANCEL_CONSENT';
        break;

      case 'JobCancelled':
        clone.status = 'CANCELLED';
        break;

      case 'DisputeRaised':
        clone.status = 'DISPUTED';
        break;

      case 'DisputeResolved':
        clone.status = 'RESOLVED';
        break;
    }
  }

  clear(): void {
    this.clones.clear();
    this.txEventNames.clear();
  }
}
