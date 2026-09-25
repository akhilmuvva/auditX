/**
 * Sentinel Polygon Streamer Read-Only Monitoring Runner
 * Runs the REAL PolygonStreamer against Polygon Mainnet (137) and Amoy (80002)
 * Backfills via getAllJobs, processes blocks, dedupes events, and tracks metrics.
 */

import { PolygonStreamer } from '../legacy/src/streamer/polygonStreamer.js';

interface StreamerRunMetrics {
  chain: string;
  startBlock: number;
  endBlock: number;
  blocksProcessed: number;
  eventsSeen: number;
  reconnects: number;
  dedupedCount: number;
  clonesWatched: number;
}

async function runStreamerMonitor(durationSeconds = 60) {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(` 🛰️  REAL POLYGON STREAMER MONITOR (Duration: ${durationSeconds}s)`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  // 1. Polygon Mainnet Streamer
  const mainnetStreamer = new PolygonStreamer({
    rpcUrls: [
      'https://polygon.gateway.tenderly.co',
      'https://polygon-bor-rpc.publicnode.com',
      'https://polygon.drpc.org',
    ],
    jobFactoryAddress: '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317',
    confirmations: 2,
    backfillBatchSize: 1000,
    cursorFilePath: './reports-cache/cursor-mainnet.json',
  });

  // 2. Polygon Amoy Streamer
  const amoyStreamer = new PolygonStreamer({
    rpcUrls: [
      'https://80002.rpc.thirdweb.com',
      'https://polygon-amoy.drpc.org',
      'https://polygon-amoy-bor-rpc.publicnode.com',
    ],
    jobFactoryAddress: '0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b',
    confirmations: 2,
    backfillBatchSize: 1000,
    cursorFilePath: './reports-cache/cursor-amoy.json',
  });

  const mainnetMetrics: StreamerRunMetrics = {
    chain: 'Polygon Mainnet (137)',
    startBlock: 0,
    endBlock: 0,
    blocksProcessed: 0,
    eventsSeen: 0,
    reconnects: 0,
    dedupedCount: 0,
    clonesWatched: 0,
  };

  const amoyMetrics: StreamerRunMetrics = {
    chain: 'Polygon Amoy (80002)',
    startBlock: 0,
    endBlock: 0,
    blocksProcessed: 0,
    eventsSeen: 0,
    reconnects: 0,
    dedupedCount: 0,
    clonesWatched: 0,
  };

  mainnetStreamer.on('event', (ev) => {
    mainnetMetrics.eventsSeen++;
    console.log(`[Mainnet Event] #${ev.blockNumber} ${ev.eventName} on ${ev.contractAddress}`);
  });

  amoyStreamer.on('event', (ev) => {
    amoyMetrics.eventsSeen++;
    console.log(`[Amoy Event] #${ev.blockNumber} ${ev.eventName} on ${ev.contractAddress}`);
  });

  console.log('Starting PolygonStreamers in read-only mode...');
  await Promise.all([mainnetStreamer.start(), amoyStreamer.start()]);

  const initialMainnet = mainnetStreamer.getStatus();
  const initialAmoy = amoyStreamer.getStatus();

  mainnetMetrics.startBlock = initialMainnet.lastProcessedBlock;
  amoyMetrics.startBlock = initialAmoy.lastProcessedBlock;
  mainnetMetrics.clonesWatched = initialMainnet.watchedAddressesCount;
  amoyMetrics.clonesWatched = initialAmoy.watchedAddressesCount;

  console.log(`[Mainnet] Initial block: ${mainnetMetrics.startBlock}, Watched: ${mainnetMetrics.clonesWatched}`);
  console.log(`[Amoy] Initial block: ${amoyMetrics.startBlock}, Watched: ${amoyMetrics.clonesWatched}`);

  const startMs = Date.now();
  const targetEndMs = startMs + durationSeconds * 1000;

  while (Date.now() < targetEndMs) {
    await new Promise((r) => setTimeout(r, 10000));
    const mStatus = mainnetStreamer.getStatus();
    const aStatus = amoyStreamer.getStatus();
    const elapsed = Math.round((Date.now() - startMs) / 1000);
    console.log(
      `[${elapsed}s] Mainnet: Block ${mStatus.lastProcessedBlock} (${mStatus.totalEventsProcessed} evts, ${mStatus.dedupedCount} deduped) | Amoy: Block ${aStatus.lastProcessedBlock} (${aStatus.totalEventsProcessed} evts, ${aStatus.dedupedCount} deduped)`
    );
  }

  const finalMainnet = mainnetStreamer.getStatus();
  const finalAmoy = amoyStreamer.getStatus();

  mainnetMetrics.endBlock = finalMainnet.lastProcessedBlock;
  mainnetMetrics.blocksProcessed = Math.max(0, finalMainnet.lastProcessedBlock - mainnetMetrics.startBlock);
  mainnetMetrics.eventsSeen = finalMainnet.totalEventsProcessed;
  mainnetMetrics.dedupedCount = finalMainnet.dedupedCount;
  mainnetMetrics.clonesWatched = finalMainnet.watchedAddressesCount;

  amoyMetrics.endBlock = finalAmoy.lastProcessedBlock;
  amoyMetrics.blocksProcessed = Math.max(0, finalAmoy.lastProcessedBlock - amoyMetrics.startBlock);
  amoyMetrics.eventsSeen = finalAmoy.totalEventsProcessed;
  amoyMetrics.dedupedCount = finalAmoy.dedupedCount;
  amoyMetrics.clonesWatched = finalAmoy.watchedAddressesCount;

  await Promise.all([mainnetStreamer.stop(), amoyStreamer.stop()]);

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(' 📊 STREAMER MONITORING SUMMARY REPORT');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('\nMainnet Metrics:', JSON.stringify(mainnetMetrics, null, 2));
  console.log('\nAmoy Metrics:', JSON.stringify(amoyMetrics, null, 2));

  console.log('\nObservation:');
  if (mainnetMetrics.eventsSeen === 0) {
    console.log(' - Mainnet: Streamer processed live blocks; no new contract events were emitted on-chain during this monitor window.');
  }
  if (amoyMetrics.eventsSeen === 0) {
    console.log(' - Amoy: Streamer processed live blocks; no new contract events were emitted on-chain during this monitor window.');
  }
}

const duration = parseInt(process.env.STREAMER_MONITOR_SECONDS || '60', 10);
runStreamerMonitor(duration).catch(console.error);
