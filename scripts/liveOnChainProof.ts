/**
 * Sentinel Live On-Chain Proof (Polygon Amoy Testnet 80002)
 *
 * Requirements:
 * 1. Reads AMOY_PROOF_PRIVATE_KEY strictly from .env.amoy-proof (inside this repo only).
 * 2. Starts the REAL PolygonStreamer on Amoy JobFactory (0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b).
 * 3. Sends a real on-chain postJob transaction using the funded throwaway key.
 * 4. Captures the live subscription event emitted by PolygonStreamer (asserts eventsSeen > 0).
 * 5. Optionally sweeps remaining testnet POL back to AMOY_SWEEP_ADDRESS.
 */

import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { PolygonStreamer } from '../legacy/src/streamer/polygonStreamer.js';
import { JOB_FACTORY_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(' 🛡️  SENTINEL REAL ON-CHAIN AMOY PROOF');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const envFile = path.resolve(process.cwd(), '.env.amoy-proof');
  if (!fs.existsSync(envFile)) {
    console.error(`❌ .env.amoy-proof not found at ${envFile}`);
    console.error('Please create .env.amoy-proof containing:\n  AMOY_PROOF_PRIVATE_KEY=<your_funded_key>\n  AMOY_SWEEP_ADDRESS=<sweep_destination_address>\n');
    process.exit(1);
  }

  const envConfig = dotenv.parse(fs.readFileSync(envFile, 'utf8'));
  const privateKey = envConfig.AMOY_PROOF_PRIVATE_KEY;
  const sweepAddress = envConfig.AMOY_SWEEP_ADDRESS;

  if (!privateKey || privateKey.trim() === '') {
    console.error('❌ AMOY_PROOF_PRIVATE_KEY is empty in .env.amoy-proof');
    process.exit(1);
  }

  const rpcUrls = [
    'https://polygon-amoy-bor-rpc.publicnode.com',
    'https://80002.rpc.thirdweb.com',
    'https://polygon-amoy.drpc.org',
  ];

  const provider = new ethers.JsonRpcProvider(rpcUrls[0]);
  const wallet = new ethers.Wallet(privateKey.startsWith('0x') ? privateKey : '0x' + privateKey, provider);

  console.log(`1. Signer Address: ${wallet.address}`);
  const initialBalance = await provider.getBalance(wallet.address);
  console.log(`   Signer Balance: ${ethers.formatEther(initialBalance)} POL\n`);

  if (initialBalance === 0n) {
    console.error('❌ Signer has 0 POL balance on Amoy testnet. Please fund the address before running proof.');
    process.exit(1);
  }

  const factoryAddress = '0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b';
  const factory = new ethers.Contract(factoryAddress, JOB_FACTORY_ABI, wallet);

  // 2. Start real PolygonStreamer
  console.log('2. Starting real PolygonStreamer on Amoy JobFactory...');
  const streamer = new PolygonStreamer({
    rpcUrls,
    jobFactoryAddress: factoryAddress,
    confirmations: 0,
    cursorFilePath: './reports-cache/cursor-amoy-live-proof.json',
  });

  const capturedEvents: ChainEvent[] = [];
  const capturedDeploys: any[] = [];

  streamer.on('event', (ev: ChainEvent) => {
    capturedEvents.push(ev);
    console.log(`\n🔔 [REAL STREAMER LIVE EVENT DETECTED]`);
    console.log(`   Block Number: #${ev.blockNumber}`);
    console.log(`   Tx Hash:      ${ev.txHash}`);
    console.log(`   Event Name:   ${ev.eventName}`);
    console.log(`   Contract:     ${ev.contractAddress}`);
    console.log(`   Args:         ${JSON.stringify(ev.args)}`);
  });

  streamer.on('job-deployed', (deployData: any) => {
    capturedDeploys.push(deployData);
    console.log(`\n📦 [REAL STREAMER CLONE DISCOVERY]`);
    console.log(`   Job Clone:    ${deployData.jobContract}`);
    console.log(`   Client:       ${deployData.client}`);
    console.log(`   Tx Hash:      ${deployData.txHash}`);
  });

  await streamer.start();
  const startStatus = streamer.getStatus();
  console.log(`   Streamer connected to: ${startStatus.activeRpc}`);
  console.log(`   Streamer initial block: #${startStatus.lastProcessedBlock}`);
  console.log(`   Initial watched clones: ${startStatus.watchedAddressesCount}\n`);

  // 3. Send real on-chain transaction
  const ipfsHash = `QmSentinelLiveProof_${Date.now()}`;
  console.log(`3. Sending on-chain transaction: postJob('${ipfsHash}', address(0))...`);

  const feeData = await provider.getFeeData();
  const maxPriorityFee = feeData.maxPriorityFeePerGas && feeData.maxPriorityFeePerGas > ethers.parseUnits('25', 'gwei')
    ? feeData.maxPriorityFeePerGas
    : ethers.parseUnits('30', 'gwei');
  const maxFee = feeData.maxFeePerGas && feeData.maxFeePerGas > ethers.parseUnits('30', 'gwei')
    ? feeData.maxFeePerGas
    : ethers.parseUnits('35', 'gwei');

  const tx = await factory.postJob(ipfsHash, ethers.ZeroAddress, {
    maxPriorityFeePerGas: maxPriorityFee,
    maxFeePerGas: maxFee,
    gasLimit: 300000,
  });

  console.log(`   Tx Broadcasted: ${tx.hash}`);
  console.log('   Awaiting 1 on-chain confirmation...');
  const receipt = await tx.wait(1);

  console.log(`   ✓ Mined on-chain in Block #${receipt.blockNumber} (Gas Used: ${receipt.gasUsed.toString()})\n`);

  // 4. Await live detection from PolygonStreamer subscription
  console.log('4. Waiting for real PolygonStreamer subscription to process block and emit event (timeout 120s)...');
  const startWait = Date.now();
  while (capturedEvents.length === 0 && capturedDeploys.length === 0 && Date.now() - startWait < 120000) {
    await new Promise((r) => setTimeout(r, 2000));
  }

  await streamer.stop();

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(' 📊 REAL ON-CHAIN PROOF RESULTS');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`Mined Tx Hash:       ${receipt.hash}`);
  console.log(`Mined Block Number:  ${receipt.blockNumber}`);
  console.log(`Streamer Events:     ${capturedEvents.length}`);
  console.log(`Streamer Clones:     ${capturedDeploys.length}`);

  if (capturedEvents.length === 0 && capturedDeploys.length === 0) {
    throw new Error('FAILED: PolygonStreamer did not capture the on-chain JobDeployed event within 120 seconds.');
  }

  // 5. Sweep remaining funds if sweepAddress provided
  if (sweepAddress && ethers.isAddress(sweepAddress)) {
    console.log(`\n5. Sweeping remaining balance to ${sweepAddress}...`);
    try {
      const currentBal = await provider.getBalance(wallet.address);
      const sweepGas = 21000n;
      const sweepFeeData = await provider.getFeeData();
      const sweepGasPrice = sweepFeeData.gasPrice || ethers.parseUnits('30', 'gwei');
      const sweepCost = sweepGas * sweepGasPrice;

      if (currentBal > sweepCost) {
        const sweepAmount = currentBal - sweepCost;
        const sweepTx = await wallet.sendTransaction({
          to: sweepAddress,
          value: sweepAmount,
          gasLimit: sweepGas,
          gasPrice: sweepGasPrice,
        });
        await sweepTx.wait(1);
        console.log(`   ✓ Swept ${ethers.formatEther(sweepAmount)} POL back to ${sweepAddress} (Tx: ${sweepTx.hash})`);
      } else {
        console.log(`   ℹ️ Balance (${ethers.formatEther(currentBal)} POL) is below gas cost to sweep.`);
      }
    } catch (sweepErr: any) {
      console.warn(`   ⚠️ Sweep notice: ${sweepErr.message}`);
    }
  }

  console.log('\n✅ Real on-chain Amoy proof PASSED.');
}

main().catch((err) => {
  console.error('\n❌ Live On-Chain Proof Error:', err);
  process.exit(1);
});
