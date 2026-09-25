/**
 * AuditX SIEM — StateTracker
 *
 * Maintains on-chain state per JobEscrow clone and JobFactory.
 * State is initialized dynamically from on-chain events and verified RPC replays.
 * No hardcoded addresses.
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

  constructor(
    initialAdmins: string[] = [],
    initialArbitrators: string[] = [],
    initialFactories: string[] = []
  ) {
    for (const a of initialAdmins) this.adminAddresses.add(a.toLowerCase());
    for (const a of initialArbitrators) this.arbitratorAddresses.add(a.toLowerCase());
    for (const f of initialFactories) this.factoryAddresses.add(f.toLowerCase());

    const envFactories = (process.env.POLYLANCE_FACTORY_ADDRESSES || process.env.POLYLANCE_FACTORY_ADDRESS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const f of envFactories) this.factoryAddresses.add(f.toLowerCase());

    const envAdmins = (process.env.POLYLANCE_ADMIN_ADDRESSES || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const a of envAdmins) this.adminAddresses.add(a.toLowerCase());

    const envArbitrators = (process.env.POLYLANCE_ARBITRATOR_ADDRESSES || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const a of envArbitrators) this.arbitratorAddresses.add(a.toLowerCase());
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
        if (
          role.includes('ARBITRATOR') ||
          role.startsWith('0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6') ||
          role.startsWith('0x16ceee8289685dd2a02b9c8ae81d2df373176ce53519e6284e2a2950d6546ffa')
        ) {
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
        if (
          role.includes('ARBITRATOR') ||
          role.startsWith('0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6') ||
          role.startsWith('0x16ceee8289685dd2a02b9c8ae81d2df373176ce53519e6284e2a2950d6546ffa')
        ) {
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
