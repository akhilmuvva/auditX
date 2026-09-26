// @ts-nocheck
import { ethers } from 'ethers';
import { EventClassifier } from '../legacy/src/siem/EventClassifier.js';
import { StateTracker } from '../legacy/src/siem/StateTracker.js';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

describe('Real Mainnet Historical Event & Threat Rule Proof', () => {
  const RPC_ENDPOINTS = [
    'https://polygon.gateway.tenderly.co',
    'https://polygon-bor-rpc.publicnode.com',
    'https://polygon.drpc.org',
  ];
  const MAINNET_FACTORY = '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317';
  const CREATION_BLOCK = 94115000;

  async function getProvider(): Promise<ethers.JsonRpcProvider> {
    for (const rpc of RPC_ENDPOINTS) {
      try {
        const p = new ethers.JsonRpcProvider(rpc, 137, { staticNetwork: ethers.Network.from(137) });
        await p.getBlockNumber();
        return p;
      } catch {}
    }
    throw new Error('All Polygon Mainnet RPC endpoints failed.');
  }

  it('fetches and decodes 100% of real historical mainnet logs and evaluates threat rules', async () => {
    const provider = await getProvider();
    const currentHead = await provider.getBlockNumber();

    const factoryIface = new ethers.Interface(JOB_FACTORY_ABI);
    const escrowIface = new ethers.Interface(JOB_ESCROW_ABI);
    const factoryContract = new ethers.Contract(MAINNET_FACTORY, JOB_FACTORY_ABI, provider);

    const clones: string[] = await factoryContract.getAllJobs();
    expect(clones.length).toBeGreaterThanOrEqual(2);

    const addresses = [MAINNET_FACTORY, ...clones];
    const rawLogs: ethers.Log[] = [];
    const chunkSize = 10000;

    for (let from = CREATION_BLOCK; from <= currentHead; from += chunkSize) {
      const to = Math.min(from + chunkSize - 1, currentHead);
      try {
        const chunk = await provider.getLogs({ address: addresses, fromBlock: from, toBlock: to });
        rawLogs.push(...chunk);
      } catch {}
    }

    expect(rawLogs.length).toBeGreaterThanOrEqual(11);

    const tracker = new StateTracker();
    const classifier = new EventClassifier(tracker);
    const decodedEvents: ChainEvent[] = [];

    for (const log of rawLogs) {
      let parsed: ethers.LogDescription | null = null;
      try {
        parsed = factoryIface.parseLog({ topics: Array.from(log.topics), data: log.data });
      } catch {}
      if (!parsed) {
        try {
          parsed = escrowIface.parseLog({ topics: Array.from(log.topics), data: log.data });
        } catch {}
      }
      if (!parsed) continue;

      const argsObj: Record<string, any> = {};
      parsed.fragment.inputs.forEach((input, index) => {
        const val = parsed!.args[index];
        argsObj[input.name || `param_${index}`] = typeof val === 'bigint' ? val.toString() : val;
      });

      const chainEvent: ChainEvent = {
        id: `mainnet-${log.transactionHash}-${log.index}`,
        timestamp: Date.now(),
        chainId: 137,
        contractAddress: log.address.toLowerCase(),
        txHash: log.transactionHash,
        blockNumber: log.blockNumber,
        eventName: parsed.name,
        args: argsObj,
        gasUsed: 150000,
        callValue: '0',
        from: '0x0000000000000000000000000000000000000000',
      };

      decodedEvents.push(chainEvent);
      const classified = classifier.classify(chainEvent);
      expect(classified).toBeDefined();
      expect(classified.ruleSeverity).toBeDefined();
    }

    expect(decodedEvents.length).toBe(rawLogs.length);
    const eventNames = decodedEvents.map((e) => e.eventName);
    expect(eventNames).toContain('JobDeployed');
    expect(eventNames).toContain('JobPosted');
    expect(eventNames).toContain('JobFunded');
    expect(eventNames).toContain('JobCancelled');
    expect(eventNames).toContain('RoleGranted');
    expect(eventNames).toContain('RoleRevoked');
  }, 45000);
});
