import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';
import { setTimeout as sleep } from 'timers/promises';
import { ethers } from 'ethers';
import type { ChainEvent } from '../siem/types.js';
import type { TenantRegistry, MonitoredAddress } from '../tenantRegistry.js';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../contracts/polylanceArtifacts.js';

export interface StreamerConfig {
  rpcUrls: string[];
  jobFactoryAddress?: string;
  confirmations: number;
  cursorFilePath: string;
  backfillBatchSize: number;
  maxDedupeSize: number;
}

export interface StreamerStatus {
  connected: boolean;
  activeRpc: string;
  lastProcessedBlock: number;
  watchedAddressesCount: number;
  totalEventsProcessed: number;
  dedupedCount: number;
}

export class PolygonStreamer extends EventEmitter {
  private config: StreamerConfig;
  private registry?: TenantRegistry;
  private provider: ethers.JsonRpcProvider | ethers.WebSocketProvider | null = null;
  private activeRpcIndex = 0;
  private running = false;
  private watchedAddresses = new Set<string>();
  private processedLogs = new Set<string>(); // key: `${txHash}:${logIndex}`
  private lastProcessedBlock = 0;
  private totalEventsProcessed = 0;
  private dedupedCount = 0;
  private blockHistory = new Map<number, string>(); // blockNumber -> blockHash (for reorg detection)

  constructor(config?: Partial<StreamerConfig>, registry?: TenantRegistry) {
    super();
    const envUrls = (process.env.POLYGON_RPC_URLS || process.env.POLYGON_RPC_URL || '')
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean);

    this.config = {
      rpcUrls: config?.rpcUrls || (envUrls.length > 0 ? envUrls : [
        'https://polygon-rpc.com',
        'https://rpc.ankr.com/polygon',
        'https://1rpc.io/matic',
      ]),
      jobFactoryAddress: config?.jobFactoryAddress || process.env.POLYLANCE_FACTORY_ADDRESS,
      confirmations: config?.confirmations ?? 2,
      cursorFilePath: config?.cursorFilePath || path.join(process.cwd(), 'reports-cache', 'streamer-cursor.json'),
      backfillBatchSize: config?.backfillBatchSize || 2000,
      maxDedupeSize: config?.maxDedupeSize || 10000,
    };

    this.registry = registry;
    this.loadCursor();
    this.bindRegistryEvents();
  }

  private loadCursor(): void {
    try {
      if (fs.existsSync(this.config.cursorFilePath)) {
        const data = JSON.parse(fs.readFileSync(this.config.cursorFilePath, 'utf8'));
        if (typeof data.lastBlock === 'number') {
          this.lastProcessedBlock = data.lastBlock;
        }
      }
    } catch {
      // ignore
    }
  }

  private saveCursor(blockNumber: number): void {
    this.lastProcessedBlock = blockNumber;
    try {
      fs.mkdirSync(path.dirname(this.config.cursorFilePath), { recursive: true });
      fs.writeFileSync(
        this.config.cursorFilePath,
        JSON.stringify({ lastBlock: blockNumber, timestamp: new Date().toISOString() }, null, 2),
        'utf8'
      );
    } catch {
      // ignore
    }
  }

  private bindRegistryEvents(): void {
    if (!this.registry) return;
    this.registry.on('monitored-changed', (monitored: MonitoredAddress[]) => {
      for (const m of monitored) {
        if (m.chain.toLowerCase().includes('polygon') || m.chain.toLowerCase().includes('matic')) {
          this.watchedAddresses.add(m.address.toLowerCase());
        }
      }
      this.emit('watch-updated', Array.from(this.watchedAddresses));
    });
  }

  addWatchedAddress(address: string): void {
    this.watchedAddresses.add(address.toLowerCase());
  }

  removeWatchedAddress(address: string): void {
    this.watchedAddresses.delete(address.toLowerCase());
  }

  getStatus(): StreamerStatus {
    return {
      connected: this.running && this.provider !== null,
      activeRpc: this.config.rpcUrls[this.activeRpcIndex] || 'none',
      lastProcessedBlock: this.lastProcessedBlock,
      watchedAddressesCount: this.watchedAddresses.size,
      totalEventsProcessed: this.totalEventsProcessed,
      dedupedCount: this.dedupedCount,
    };
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Load initial monitored addresses from registry
    if (this.registry) {
      const allMonitored = this.registry.listAllMonitoredAddresses();
      for (const m of allMonitored) {
        this.watchedAddresses.add(m.address.toLowerCase());
      }
    }

    await this.connectWithFallback();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.provider) {
      try {
        this.provider.destroy();
      } catch {
        // ignore
      }
      this.provider = null;
    }
  }

  private async connectWithFallback(): Promise<void> {
    let attempt = 0;
    while (this.running) {
      const url = this.config.rpcUrls[this.activeRpcIndex];
      try {
        if (url.startsWith('ws://') || url.startsWith('wss://')) {
          this.provider = new ethers.WebSocketProvider(url);
        } else {
          this.provider = new ethers.JsonRpcProvider(url);
        }

        const network = await this.provider.getNetwork();
        const currentBlock = await this.provider.getBlockNumber();
        console.log(`[PolygonStreamer] Connected to RPC ${url} (Chain ID: ${network.chainId}, Head: ${currentBlock})`);

        // Backfill jobs if Factory is configured
        await this.backfillFactoryJobs();

        // Start polling / block subscription
        await this.listenBlocks(currentBlock);
        return;
      } catch (err: any) {
        console.warn(`[PolygonStreamer] RPC ${url} failed: ${err.message}. Rotating...`);
        this.activeRpcIndex = (this.activeRpcIndex + 1) % this.config.rpcUrls.length;
        attempt++;
        const jitter = Math.floor(Math.random() * 500);
        const backoff = Math.min(1000 * Math.pow(1.5, attempt) + jitter, 15000);
        await sleep(backoff);
      }
    }
  }

  private async backfillFactoryJobs(): Promise<void> {
    if (!this.config.jobFactoryAddress || !this.provider) return;
    try {
      const factory = new ethers.Contract(this.config.jobFactoryAddress, JOB_FACTORY_ABI, this.provider);
      const jobs: string[] = await factory.getAllJobs();
      for (const job of jobs) {
        this.watchedAddresses.add(job.toLowerCase());
      }
      console.log(`[PolygonStreamer] Backfilled ${jobs.length} escrow clones from JobFactory`);
    } catch (err: any) {
      console.warn(`[PolygonStreamer] JobFactory backfill skipped: ${err.message}`);
    }
  }

  private async listenBlocks(startBlock: number): Promise<void> {
    if (!this.provider) return;
    if (this.lastProcessedBlock === 0) {
      this.lastProcessedBlock = Math.max(0, startBlock - this.config.confirmations);
    }

    while (this.running && this.provider) {
      try {
        const latestBlock = await this.provider.getBlockNumber();
        const confirmedHead = latestBlock - this.config.confirmations;

        if (confirmedHead > this.lastProcessedBlock) {
          const fromBlock = this.lastProcessedBlock + 1;
          const toBlock = Math.min(confirmedHead, fromBlock + this.config.backfillBatchSize);

          await this.processBlockRange(fromBlock, toBlock);
          this.saveCursor(toBlock);
        }
        await sleep(2000);
      } catch (err: any) {
        console.error(`[PolygonStreamer] Block processing error: ${err.message}`);
        await sleep(3000);
        if (!this.running) break;
        return this.connectWithFallback();
      }
    }
  }

  private async processBlockRange(fromBlock: number, toBlock: number): Promise<void> {
    if (!this.provider) return;

    for (let b = fromBlock; b <= toBlock; b++) {
      const block = await this.provider.getBlock(b, true);
      if (!block) continue;

      // Reorg Check
      const prevRecordedHash = this.blockHistory.get(b);
      if (prevRecordedHash && prevRecordedHash !== block.hash) {
        console.warn(`[PolygonStreamer] REORG DETECTED at block ${b}! Previous: ${prevRecordedHash}, New: ${block.hash}`);
        this.emit('reorg', { blockNumber: b, oldHash: prevRecordedHash, newHash: block.hash });
      }
      this.blockHistory.set(b, block.hash || '');
      if (this.blockHistory.size > 200) {
        const oldest = Math.min(...this.blockHistory.keys());
        this.blockHistory.delete(oldest);
      }

      // Check transactions for watched contracts or factory deploys
      for (const tx of block.prefetchedTransactions) {
        const to = tx.to?.toLowerCase();

        // Check if interaction with JobFactory
        if (this.config.jobFactoryAddress && to === this.config.jobFactoryAddress.toLowerCase()) {
          const receipt = await this.provider.getTransactionReceipt(tx.hash);
          if (receipt) {
            this.inspectFactoryLogs(receipt);
          }
        }

        // Check if interaction with any watched escrow contract
        if (to && this.watchedAddresses.has(to)) {
          const receipt = await this.provider.getTransactionReceipt(tx.hash);
          if (receipt) {
            this.processContractReceipt(tx, receipt, block.timestamp);
          }
        }
      }
    }
  }

  private inspectFactoryLogs(receipt: ethers.TransactionReceipt): void {
    const factoryInterface = new ethers.Interface(JOB_FACTORY_ABI);
    for (const log of receipt.logs) {
      try {
        const parsed = factoryInterface.parseLog({ topics: log.topics as string[], data: log.data });
        if (parsed && parsed.name === 'JobDeployed') {
          const deployedJob = (parsed.args.jobContract || parsed.args.jobAddress)?.toLowerCase();
          if (deployedJob) {
            this.watchedAddresses.add(deployedJob);
            this.emit('job-deployed', {
              jobAddress: deployedJob,
              jobContract: deployedJob,
              client: parsed.args.client,
              paymentToken: parsed.args.paymentToken,
              txHash: receipt.hash,
            });
            console.log(`[PolygonStreamer] Dynamically watched new job escrow clone: ${deployedJob}`);
          }
        }
      } catch {
        // Not a JobDeployed log
      }
    }
  }

  private processContractReceipt(tx: ethers.TransactionResponse, receipt: ethers.TransactionReceipt, blockTimestamp: number): void {
    const escrowInterface = new ethers.Interface(JOB_ESCROW_ABI);

    for (const log of receipt.logs) {
      const dedupeKey = `${receipt.hash}:${log.index}`;
      if (this.processedLogs.has(dedupeKey)) {
        this.dedupedCount++;
        continue;
      }
      this.recordDedupe(dedupeKey);

      let eventName = 'ContractInteraction';
      let parsedArgs: Record<string, any> = {};

      try {
        const parsed = escrowInterface.parseLog({ topics: log.topics as string[], data: log.data });
        if (parsed) {
          eventName = parsed.name;
          parsedArgs = parsed.args.toObject();
        }
      } catch {
        eventName = log.topics[0] || 'UnknownTopic';
      }

      const chainEvent: ChainEvent = {
        id: `ev-${receipt.hash}-${log.index}`,
        timestamp: blockTimestamp * 1000,
        chainId: 137, // Polygon Mainnet
        contractAddress: log.address.toLowerCase(),
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        eventName: eventName,
        args: parsedArgs,
        gasUsed: Number(receipt.gasUsed),
        callValue: tx.value ? ethers.formatEther(tx.value) : '0',
        from: tx.from.toLowerCase(),
      };

      this.totalEventsProcessed++;
      this.emit('event', chainEvent);
    }
  }

  private recordDedupe(key: string): void {
    if (this.processedLogs.size >= this.config.maxDedupeSize) {
      const iterator = this.processedLogs.values();
      for (let i = 0; i < 2000; i++) {
        const next = iterator.next();
        if (next.done) break;
        this.processedLogs.delete(next.value);
      }
    }
    this.processedLogs.add(key);
  }
}
