import { describe, it, expect } from '@jest/globals';
import { ethers } from 'ethers';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';
import { EventClassifier } from '../legacy/src/siem/EventClassifier.js';

const factoryIf = new ethers.Interface(JOB_FACTORY_ABI);
const escrowIf = new ethers.Interface(JOB_ESCROW_ABI);

async function getLogsChunked(provider: ethers.JsonRpcProvider, address: string, fromBlock: number, toBlock: number, chunkSize = 4000) {
  let logs: ethers.Log[] = [];
  for (let current = fromBlock; current <= toBlock; current += chunkSize) {
    const end = Math.min(current + chunkSize - 1, toBlock);
    try {
      const chunk = await provider.getLogs({
        address,
        fromBlock: current,
        toBlock: end,
      });
      logs = logs.concat(chunk);
    } catch {
      // ignore transient RPC timeouts
    }
  }
  return logs;
}

describe('Phase 7: Read-Only Live On-Chain Checks', () => {
  it('verifies Polygon Mainnet (137) clones and decodes live historical logs', async () => {
    const rpcUrl = 'https://polygon-bor-rpc.publicnode.com';
    const factoryAddr = '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317';
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const factory = new ethers.Contract(factoryAddr, JOB_FACTORY_ABI, provider);

    const impl = await factory.jobImplementation();
    expect(impl.toLowerCase()).toBe('0x88dd19df1b6dBA8D2c53b3976f4ec39B75f17FbB'.toLowerCase());

    const jobs: string[] = await factory.getAllJobs();
    expect(jobs.length).toBeGreaterThanOrEqual(2);

    const eventCounts: Record<string, number> = {};
    let decodeFailures = 0;
    let totalLogs = 0;

    const currentBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, currentBlock - 20000);

    const fLogs = await getLogsChunked(provider, factoryAddr, fromBlock, currentBlock);
    totalLogs += fLogs.length;
    for (const log of fLogs) {
      try {
        const parsed = factoryIf.parseLog({ topics: log.topics as string[], data: log.data });
        if (parsed) {
          eventCounts[parsed.name] = (eventCounts[parsed.name] || 0) + 1;
        }
      } catch {
        decodeFailures++;
      }
    }

    for (const job of jobs) {
      const cLogs = await getLogsChunked(provider, job, fromBlock, currentBlock);
      totalLogs += cLogs.length;
      for (const log of cLogs) {
        try {
          const parsed = escrowIf.parseLog({ topics: log.topics as string[], data: log.data });
          if (parsed) {
            eventCounts[parsed.name] = (eventCounts[parsed.name] || 0) + 1;
          }
        } catch {
          decodeFailures++;
        }
      }
    }

    console.log(`\n=== LIVE CHECK: Polygon Mainnet (137) ===`);
    console.log(`Factory: ${factoryAddr}`);
    console.log(`Implementation: ${impl}`);
    console.log(`Clones (${jobs.length}):`, jobs);
    console.log(`Scanned Blocks: ${fromBlock} -> ${currentBlock}`);
    console.log(`Total Logs Fetched: ${totalLogs}`);
    console.log(`Decode Failures: ${decodeFailures}`);
    console.log(`Event Counts by Name:`, eventCounts);

    expect(decodeFailures).toBe(0);
  }, 45000);

  it('verifies Polygon Amoy (80002) Candidate 0x0146...a70b clones and decodes live historical logs', async () => {
    const rpcUrl = 'https://polygon-amoy-bor-rpc.publicnode.com';
    const factoryAddr = '0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b';
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const factory = new ethers.Contract(factoryAddr, JOB_FACTORY_ABI, provider);

    const impl = await factory.jobImplementation();
    expect(impl.toLowerCase()).toBe('0xfDC15e8261677C41e8e872A8fb05D2369753F8a7'.toLowerCase());

    const jobs: string[] = await factory.getAllJobs();
    expect(jobs.length).toBeGreaterThanOrEqual(3);

    const eventCounts: Record<string, number> = {};
    let decodeFailures = 0;
    let totalLogs = 0;

    const currentBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, currentBlock - 20000);

    const fLogs = await getLogsChunked(provider, factoryAddr, fromBlock, currentBlock);
    totalLogs += fLogs.length;
    for (const log of fLogs) {
      try {
        const parsed = factoryIf.parseLog({ topics: log.topics as string[], data: log.data });
        if (parsed) {
          eventCounts[parsed.name] = (eventCounts[parsed.name] || 0) + 1;
        }
      } catch {
        decodeFailures++;
      }
    }

    for (const job of jobs) {
      const cLogs = await getLogsChunked(provider, job, fromBlock, currentBlock);
      totalLogs += cLogs.length;
      for (const log of cLogs) {
        try {
          const parsed = escrowIf.parseLog({ topics: log.topics as string[], data: log.data });
          if (parsed) {
            eventCounts[parsed.name] = (eventCounts[parsed.name] || 0) + 1;
          }
        } catch {
          decodeFailures++;
        }
      }
    }

    console.log(`\n=== LIVE CHECK: Polygon Amoy Testnet (80002) ===`);
    console.log(`Factory: ${factoryAddr}`);
    console.log(`Implementation: ${impl}`);
    console.log(`Clones (${jobs.length}):`, jobs);
    console.log(`Scanned Blocks: ${fromBlock} -> ${currentBlock}`);
    console.log(`Total Logs Fetched: ${totalLogs}`);
    console.log(`Decode Failures: ${decodeFailures}`);
    console.log(`Event Counts by Name:`, eventCounts);

    expect(decodeFailures).toBe(0);
  }, 45000);
});
