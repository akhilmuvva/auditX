/**
 * AuditX SIEM — ThreatIntelligence
 *
 * Maintains a curated threat-feed database and enriches scored events with
 * known-bad address information.  Ships with a built-in seed list of
 * high-profile exploiters, mixers, and sanctioned addresses.
 *
 * The feed is designed to be extended at runtime:
 *   ti.addFeed(entries)
 *
 * In production, call ti.syncFromIpfs(cid) to pull a community-maintained
 * feed stored on IPFS.
 */

import type {
  ScoredEvent,
  EnrichedEvent,
  ThreatFeed,
  ThreatMatch,
  EventSeverity,
} from './types.js';

// ─── Built-in seed data ──────────────────────────────────────────────────────

const SEED_FEEDS: ThreatFeed[] = [
  // Tornado Cash (OFAC sanctioned)
  {
    address: '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
    label: 'Tornado Cash: Router',
    category: 'MIXER',
    riskScore: 9.5,
    firstSeen: '2022-08-08',
    source: 'OFAC SDN List',
  },
  {
    address: '0x722122df12d4e14e13ac3b6895a86e84145b6967',
    label: 'Tornado Cash: Proxy',
    category: 'MIXER',
    riskScore: 9.5,
    firstSeen: '2022-08-08',
    source: 'OFAC SDN List',
  },
  // Ronin / Lazarus Group
  {
    address: '0x098b716b8aaf21512996dc57eb0615e2383e2f96',
    label: 'Ronin Bridge Exploiter (Lazarus Group)',
    category: 'EXPLOIT',
    riskScore: 10.0,
    firstSeen: '2022-03-29',
    source: 'Chainalysis / OFAC',
  },
  // Euler Finance exploiter
  {
    address: '0xb66cd966670d962c227b3eaba30a872dbfb995db',
    label: 'Euler Finance Exploiter',
    category: 'EXPLOIT',
    riskScore: 9.8,
    firstSeen: '2023-03-13',
    source: 'Euler Finance Incident Report',
  },
  // Multichain exploiter
  {
    address: '0x9d5765ae1c4e4a16e9ada6a4d2a8d0d6c1f6b6e',
    label: 'Multichain Exploiter',
    category: 'EXPLOIT',
    riskScore: 9.7,
    firstSeen: '2023-07-07',
    source: 'Multichain Post-Mortem',
  },
  // Generic drainer (example)
  {
    address: '0xf6da21e95d74767009accb145b96897ac3630bd',
    label: 'Known NFT Drainer',
    category: 'DRAINER',
    riskScore: 8.5,
    firstSeen: '2023-01-01',
    source: 'ZachXBT',
  },
];

// ─── ThreatIntelligence ───────────────────────────────────────────────────────

export class ThreatIntelligence {
  private feeds: Map<string, ThreatFeed> = new Map();

  constructor(extraFeeds: ThreatFeed[] = []) {
    this.addFeed(SEED_FEEDS);
    this.addFeed(extraFeeds);
  }

  /**
   * Add one or more threat feed entries.
   * Normalises addresses to lowercase.
   */
  addFeed(entries: ThreatFeed[]): void {
    for (const entry of entries) {
      this.feeds.set(entry.address.toLowerCase(), entry);
    }
  }

  /**
   * Remove a feed entry by address.
   */
  removeFeed(address: string): void {
    this.feeds.delete(address.toLowerCase());
  }

  /** Total number of threat feed entries loaded */
  get size(): number {
    return this.feeds.size;
  }

  /**
   * Check a single address against the feed.
   */
  checkAddress(address: string): ThreatFeed | null {
    return this.feeds.get(address.toLowerCase()) ?? null;
  }

  /**
   * Enrich a single ScoredEvent with threat intelligence.
   * Checks the 'from', 'contractAddress', and all string-valued event args.
   */
  enrich(event: ScoredEvent): EnrichedEvent {
    const matches: ThreatMatch[] = [];

    // Helper to check + record match
    const check = (addr: string, field: string) => {
      const feed = this.checkAddress(addr);
      if (feed) {
        matches.push({ address: addr.toLowerCase(), feed, matchedField: field });
      }
    };

    check(event.from, 'from');
    check(event.contractAddress, 'contractAddress');

    for (const [key, value] of Object.entries(event.args)) {
      if (typeof value === 'string' && value.startsWith('0x') && value.length >= 40) {
        check(value, `args.${key}`);
      }
    }

    // Escalate severity if any threat matched
    const escalatedSeverity: EventSeverity =
      matches.length > 0
        ? maxSeverity(event.finalSeverity, threatToSeverity(matches[0].feed.riskScore))
        : event.finalSeverity;

    return { ...event, threatMatches: matches, escalatedSeverity };
  }

  /**
   * Enrich a batch of scored events.
   */
  enrichBatch(events: ScoredEvent[]): EnrichedEvent[] {
    return events.map((e) => this.enrich(e));
  }

  /**
   * Sync threat feeds from an IPFS CID.
   * Fetches the JSON feed from the IPFS gateway and merges entries.
   *
   * Expected format: ThreatFeed[]
   */
  async syncFromIpfs(cid: string, gateway = 'https://dweb.link/ipfs'): Promise<number> {
    const url = `${gateway}/${cid}`;
    let entries: ThreatFeed[];
    try {
      // Dynamic import of fetch for ESM compatibility
      const { default: fetch } = await import('node-fetch');
      const res = await (fetch as any)(url, { timeout: 10_000 });
      if (!res.ok) throw new Error(`IPFS gateway ${res.status}`);
      entries = await res.json() as ThreatFeed[];
    } catch (err: any) {
      console.warn(`[ThreatIntelligence] IPFS sync failed: ${err.message}`);
      return 0;
    }
    this.addFeed(entries);
    return entries.length;
  }

  /** Export all feeds (useful for uploading to IPFS) */
  exportFeeds(): ThreatFeed[] {
    return Array.from(this.feeds.values());
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

function maxSeverity(a: EventSeverity, b: EventSeverity): EventSeverity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function threatToSeverity(riskScore: number): EventSeverity {
  if (riskScore >= 9.0) return 'CRITICAL';
  if (riskScore >= 7.0) return 'HIGH';
  if (riskScore >= 4.0) return 'MEDIUM';
  if (riskScore >= 2.0) return 'LOW';
  return 'INFO';
}
