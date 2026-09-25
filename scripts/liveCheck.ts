/**
 * Sentinel Live On-Chain Verification Script
 * Scans real PolyLance deployments on Polygon Mainnet (137) and Amoy Testnet (80002)
 * Decodes all logs from creation block to head using authoritative ABIs.
 * Retries with exponential backoff; fails loudly on errors.
 */

import { ethers } from 'ethers';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';

interface ChainTarget {
  name: string;
  chainId: number;
  rpcs: string[];
  factoryAddress: string;
  expectedImplementation: string;
  creationBlock: number;
  chunkSize: number;
}

const TARGETS: ChainTarget[] = [
  {
    name: 'Polygon Mainnet (137)',
    chainId: 137,
    rpcs: [
      'https://polygon.gateway.tenderly.co',
      'https://polygon-bor-rpc.publicnode.com',
      'https://polygon.drpc.org',
    ],
    factoryAddress: '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317',
    expectedImplementation: '0x88dd19df1b6dBA8D2c53b3976f4ec39B75f17FbB',
    creationBlock: 94115000,
    chunkSize: 8000,
  },
  {
    name: 'Polygon Amoy Testnet (80002)',
    chainId: 80002,
    rpcs: [
      'https://80002.rpc.thirdweb.com',
      'https://polygon-amoy.drpc.org',
      'https://polygon-amoy-bor-rpc.publicnode.com',
    ],
    factoryAddress: '0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b',
    expectedImplementation: '0xfDC15e8261677C41e8e872A8fb05D2369753F8a7',
    creationBlock: 48470000,
    chunkSize: 1000,
  },
];

const ifaces = [
  new ethers.Interface(JOB_FACTORY_ABI),
  new ethers.Interface(JOB_ESCROW_ABI),
];

function parseAnyLog(log: ethers.Log): ethers.LogDescription | null {
  for (const iface of ifaces) {
    try {
      const parsed = iface.parseLog({
        topics: Array.from(log.topics),
        data: log.data,
      });
      if (parsed) return parsed;
    } catch {
      // Try next interface
    }
  }
  return null;
}

async function getWorkingProvider(target: ChainTarget): Promise<ethers.JsonRpcProvider> {
  for (const rpc of target.rpcs) {
    try {
      const provider = new ethers.JsonRpcProvider(rpc, target.chainId, {
        staticNetwork: ethers.Network.from(target.chainId),
      });
      await provider.getBlockNumber();
      return provider;
    } catch (e: any) {
      console.warn(`[WARN] RPC ${rpc} unreachable: ${e.message}. Trying next...`);
    }
  }
  throw new Error(`All RPC endpoints failed for ${target.name}`);
}

async function fetchLogsWithBackoff(
  provider: ethers.JsonRpcProvider,
  addresses: string[],
  fromBlock: number,
  toBlock: number,
  maxRetries = 5
): Promise<ethers.Log[]> {
  let delay = 300;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await provider.getLogs({
        address: addresses,
        fromBlock,
        toBlock,
      });
    } catch (err: any) {
      if (attempt === maxRetries) {
        throw new Error(
          `Failed getLogs [${fromBlock} -> ${toBlock}] after ${maxRetries} attempts: ${err.message}`
        );
      }
      await new Promise((r) => setTimeout(r, delay));
      delay *= 2;
    }
  }
  return [];
}

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(' 🛡️  SENTINEL LIVE CHAIN LOG VERIFICATION');
  console.log('═══════════════════════════════════════════════════════════════\n');

  let hasFailure = false;

  for (const target of TARGETS) {
    console.log(`\n--- Inspecting ${target.name} ---`);
    const provider = await getWorkingProvider(target);
    const head = await provider.getBlockNumber();

    const factory = new ethers.Contract(target.factoryAddress, JOB_FACTORY_ABI, provider);
    const liveImpl = await factory.jobImplementation();

    if (liveImpl.toLowerCase() !== target.expectedImplementation.toLowerCase()) {
      console.error(
        `[FATAL] Implementation mismatch on ${target.name}: Expected ${target.expectedImplementation}, got ${liveImpl}`
      );
      hasFailure = true;
      continue;
    }
    console.log(`✓ Factory: ${target.factoryAddress}`);
    console.log(`✓ Implementation: ${liveImpl} (Verified Match)`);

    const clones: string[] = await factory.getAllJobs();
    console.log(`✓ Discovered Clones (${clones.length}):`);
    clones.forEach((c, idx) => console.log(`   [${idx + 1}] ${c}`));

    const watchedAddresses = [target.factoryAddress, ...clones];
    const fromBlock = target.creationBlock;
    const toBlock = head;
    console.log(`Scanning blocks ${fromBlock} -> ${toBlock} (Range: ${toBlock - fromBlock} blocks)...`);

    const allLogs: ethers.Log[] = [];
    const eventCounts: Record<string, number> = {};
    let decodeFailures = 0;

    for (let from = fromBlock; from <= toBlock; from += target.chunkSize) {
      const to = Math.min(toBlock, from + target.chunkSize - 1);
      const chunkLogs = await fetchLogsWithBackoff(provider, watchedAddresses, from, to);
      for (const log of chunkLogs) {
        allLogs.push(log);
        const parsed = parseAnyLog(log);
        if (!parsed) {
          decodeFailures++;
        }
        const eventName = parsed ? parsed.name : `Unparsed_${log.topics[0]}`;
        eventCounts[eventName] = (eventCounts[eventName] || 0) + 1;
      }
    }

    console.log(`\n=== Verification Summary for ${target.name} ===`);
    console.log(`Total Monitored Contracts: ${watchedAddresses.length}`);
    console.log(`Total Logs Fetched: ${allLogs.length}`);
    console.log(`Decode Failures: ${decodeFailures}`);
    console.log('Event Counts:', JSON.stringify(eventCounts, null, 2));

    if (decodeFailures > 0) {
      console.error(`[FAIL] ${decodeFailures} logs failed to decode with real ABI!`);
      hasFailure = true;
    }

    if (clones.length > 0 && target.chainId === 137 && allLogs.length === 0) {
      console.error(`[FAIL] Chain has ${clones.length} clones but 0 logs were fetched!`);
      hasFailure = true;
    }
  }

  if (hasFailure) {
    console.error('\n❌ Live check failed invariants.');
    process.exit(1);
  } else {
    console.log('\n✅ All live chains verified successfully.');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
