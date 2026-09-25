/**
 * Sentinel Balance Sweep Script
 * Sweeps all remaining POL from the testnet throwaway key to a specified destination address.
 * Usage: node --loader ts-node/esm scripts/sweepBalance.ts <destination_address>
 */

import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { ethers } from 'ethers';

async function main() {
  const destArg = process.argv[2];
  const envFile = path.resolve(process.cwd(), '.env.amoy-proof');

  let privateKey = process.env.AMOY_PROOF_PRIVATE_KEY;
  let sweepAddress = destArg || process.env.AMOY_SWEEP_ADDRESS;

  if (fs.existsSync(envFile)) {
    const config = dotenv.parse(fs.readFileSync(envFile, 'utf8'));
    if (!privateKey) privateKey = config.AMOY_PROOF_PRIVATE_KEY;
    if (!sweepAddress) sweepAddress = config.AMOY_SWEEP_ADDRESS;
  }

  if (!sweepAddress || !ethers.isAddress(sweepAddress)) {
    console.error('❌ Error: Valid sweep destination address required.');
    console.error('Usage: npm run sweep:amoy <destination_address>\n   or set AMOY_SWEEP_ADDRESS in .env.amoy-proof');
    process.exit(1);
  }

  if (!privateKey) {
    console.error('❌ Error: Private key not found in env or .env.amoy-proof');
    process.exit(1);
  }

  const rpcUrl = 'https://polygon-amoy-bor-rpc.publicnode.com';
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey.startsWith('0x') ? privateKey : '0x' + privateKey, provider);

  const balance = await provider.getBalance(wallet.address);
  console.log(`Signer Address: ${wallet.address}`);
  console.log(`Current Balance: ${ethers.formatEther(balance)} POL`);
  console.log(`Sweeping to:     ${sweepAddress}`);

  const sweepGas = 21000n;
  const maxPriorityFee = ethers.parseUnits('30', 'gwei');
  const maxFee = ethers.parseUnits('35', 'gwei');
  const maxCost = sweepGas * maxFee;

  if (balance <= maxCost) {
    console.error(`❌ Balance (${ethers.formatEther(balance)} POL) is below estimated transfer gas cost (${ethers.formatEther(maxCost)} POL)`);
    process.exit(1);
  }

  const sweepAmount = balance - maxCost;
  console.log(`Sending ${ethers.formatEther(sweepAmount)} POL...`);

  const tx = await wallet.sendTransaction({
    to: sweepAddress,
    value: sweepAmount,
    gasLimit: sweepGas,
    maxPriorityFeePerGas: maxPriorityFee,
    maxFeePerGas: maxFee,
  });

  console.log(`Transaction Broadcasted: ${tx.hash}`);
  const receipt = await tx.wait(1);
  console.log(`✓ Confirmed in Block #${receipt.blockNumber} (Gas Used: ${receipt.gasUsed})`);
  console.log(`✅ Successfully swept remaining funds to ${sweepAddress}`);
}

main().catch((err) => {
  console.error('Sweep execution failed:', err);
  process.exit(1);
});
