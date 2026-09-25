/**
 * Sentinel Live End-to-End Proof on Polygon Amoy Testnet (80002)
 *
 * 1. Initializes PolygonStreamer on Amoy JobFactory (0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b)
 * 2. Starts EventClassifier and webhook / alert listener
 * 3. Transacts postJob on Amoy using the funded signer
 * 4. Verifies live detection of JobDeployed, event classification, and alert generation
 */

import fs from 'fs';
import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { PolygonStreamer } from '../legacy/src/streamer/polygonStreamer.js';
import { EventClassifier } from '../legacy/src/siem/EventClassifier.js';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

async function runLiveProof() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(' 🛡️  SENTINEL LIVE ON-CHAIN PROOF (Polygon Amoy 80002)');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // 1. Resolve Amoy signer from environment
  let pk = process.env.PRIVATE_KEY || process.env.CLIENT_PRIVATE_KEY;
  if (!pk && fs.existsSync('D:/Polylance/.env')) {
    const envConfig = dotenv.parse(fs.readFileSync('D:/Polylance/.env'));
    pk = envConfig.PRIVATE_KEY || envConfig.CLIENT_PRIVATE_KEY;
  }

  if (!pk) {
    throw new Error('No Amoy signer private key available in environment.');
  }

  const rpcUrl = 'https://polygon-amoy-bor-rpc.publicnode.com';
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(pk.startsWith('0x') ? pk : '0x' + pk, provider);

  console.log(`1. Amoy Signer: ${signer.address}`);
  const balance = await provider.getBalance(signer.address);
  console.log(`   Signer Balance: ${ethers.formatEther(balance)} POL\n`);

  const factoryAddress = '0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b';
  const factory = new ethers.Contract(factoryAddress, JOB_FACTORY_ABI, signer);

  // 2. Setup PolygonStreamer & EventClassifier
  const classifier = new EventClassifier();
  const liveEventsSeen: ChainEvent[] = [];
  const liveAlerts: any[] = [];

  const streamer = new PolygonStreamer({
    rpcUrls: [
      'https://polygon-amoy-bor-rpc.publicnode.com',
      'https://80002.rpc.thirdweb.com',
      'https://polygon-amoy.drpc.org',
    ],
    jobFactoryAddress: factoryAddress,
    confirmations: 1,
    backfillBatchSize: 1000,
    cursorFilePath: './reports-cache/cursor-amoy-live-proof.json',
  });

  streamer.on('event', (ev: ChainEvent) => {
    liveEventsSeen.push(ev);
    const classified = classifier.classify(ev);
    liveAlerts.push(classified);
    console.log(`\n🔔 [LIVE STREAMER EVENT DETECTED]`);
    console.log(`   Block: #${ev.blockNumber} | Tx: ${ev.txHash}`);
    console.log(`   Event: ${ev.eventName} on ${ev.contractAddress}`);
    console.log(`   Category: ${classified.category} | Severity: ${classified.ruleSeverity}`);
    console.log(`   Reason: ${classified.reason}`);
  });

  console.log('2. Starting PolygonStreamer on Amoy...');
  await streamer.start();
  const initialStatus = streamer.getStatus();
  console.log(`   Streamer active at block #${initialStatus.lastProcessedBlock}`);
  console.log(`   Initial watched clones: ${initialStatus.watchedAddressesCount}\n`);

  // 3. Post a new Job on Amoy JobFactory
  const ipfsHash = `QmSentinelProof_${Date.now()}`;
  console.log(`3. Sending postJob('${ipfsHash}', address(0)) on-chain...`);

  const tx = await factory.postJob(ipfsHash, ethers.ZeroAddress, {
    maxFeePerGas: ethers.parseUnits('15', 'gwei'),
    maxPriorityFeePerGas: ethers.parseUnits('15', 'gwei'),
    gasLimit: 300000,
  });

  console.log(`   Transaction broadcasted: ${tx.hash}`);
  console.log('   Waiting for confirmation...');
  const receipt = await tx.wait(1);
  console.log(`   ✓ Confirmed in block #${receipt.blockNumber} (Gas Used: ${receipt.gasUsed.toString()})\n`);

  // 4. Wait for PolygonStreamer to poll/detect the block and process the event
  console.log('4. Awaiting PolygonStreamer live event detection and rule classification...');
  const startWait = Date.now();
  while (liveEventsSeen.length === 0 && Date.now() - startWait < 60000) {
    await new Promise((r) => setTimeout(r, 2000));
  }

  streamer.stop();

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(' 📊 LIVE PROOF RESULTS');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`Total Live Events Seen: ${liveEventsSeen.length}`);
  console.log(`Total Classified Alerts: ${liveAlerts.length}`);

  if (liveEventsSeen.length === 0) {
    throw new Error('FAILED: Live streamer did not capture the postJob event within timeout.');
  }

  console.log('\nCaptured Events:');
  for (const ev of liveEventsSeen) {
    console.log(` - ${ev.eventName} (${ev.contractAddress}) in block ${ev.blockNumber}`);
  }

  console.log('\n✅ Sentinel live on-chain end-to-end event proof PASSED.');
}

runLiveProof().catch((err) => {
  console.error('\n❌ Live Proof Exception:', err);
  process.exit(1);
});
