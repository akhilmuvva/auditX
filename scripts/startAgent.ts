import { AuditAgent } from '../src/network/agent.js';
import dotenv from 'dotenv';
import { ethers } from 'ethers';

dotenv.config();

async function main() {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    console.error("Missing PRIVATE_KEY in .env");
    process.exit(1);
  }

  const wallet = new ethers.Wallet(privateKey);
  const agentAddress = wallet.address;

  console.log(`Starting AuditX Libp2p Agent for address: ${agentAddress}`);

  const agent = new AuditAgent(agentAddress);
  
  // Start the agent on a random available port
  await agent.start(0);

  // Keep process alive
  process.on('SIGINT', async () => {
    console.log("\nShutting down agent...");
    await agent.stop();
    process.exit(0);
  });
}

main().catch(console.error);
