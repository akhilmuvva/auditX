/**
 * AuditX SIEM — Automated Blockchain Event Listener & SIEM Streamer
 *
 * Automatically monitors live EVM block transactions (via RPC) and streams
 * them directly to the running SIEM WebSocket server (ws://localhost:3000/ws/siem)
 * for real-time anomaly detection, threat matching, and dashboard updates.
 *
 * Usage:
 *   npx ts-node --esm scripts/siemStreamer.ts
 */

import { ethers } from 'ethers';
import WebSocket from 'ws';
import dotenv from 'dotenv';

dotenv.config();

// Configuration
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545'; // Defaults to local Hardhat node
const SIEM_WS_URL = process.env.SIEM_WS_URL || 'ws://localhost:3000/ws/siem';
const SIEM_API_KEY = process.env.SIEM_API_KEY;
const RECONNECT_DELAY_MS = 5000;

interface ChainEvent {
  id: string;
  contractAddress: string;
  eventName: string;
  gasUsed: number;
  callValue: string;
  args: Record<string, any>;
}

class SIEMAutomationStreamer {
  private provider!: ethers.JsonRpcProvider;
  private ws: WebSocket | null = null;
  private isConnecting = false;

  constructor() {
    console.log(`📡 Connecting to RPC node at: ${RPC_URL}`);
    this.provider = new ethers.JsonRpcProvider(RPC_URL);
  }

  /**
   * Connect to the SIEM server WebSocket with auto-reconnection logic.
   */
  public connectSIEM() {
    if (this.isConnecting) return;
    this.isConnecting = true;

    console.log(`🔌 Opening persistent connection to SIEM WebSocket: ${SIEM_WS_URL}`);
    
    this.ws = new WebSocket(SIEM_WS_URL, SIEM_API_KEY ? [`auditx-api-key.${SIEM_API_KEY}`] : undefined);

    this.ws.on('open', () => {
      console.log('✅ Connected to SIEM WebSocket server. Real-time streaming active!');
      this.isConnecting = false;
    });

    this.ws.on('close', () => {
      console.warn(`⚠️  SIEM WebSocket disconnected. Reconnecting in ${RECONNECT_DELAY_MS / 1000}s...`);
      this.isConnecting = false;
      this.ws = null;
      setTimeout(() => this.connectSIEM(), RECONNECT_DELAY_MS);
    });

    this.ws.on('error', (err) => {
      console.error('❌ WebSocket connection error:', err.message);
    });

    this.ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'processed') {
          console.log(`   ✓ Ingest Ack: classified=${msg.data.classified}, anomalies=${msg.data.anomalies}, threats=${msg.data.threatMatches}, alerts=${msg.data.alerts}`);
        }
      } catch {
        // Suppress non-JSON / debugging messages
      }
    });
  }

  /**
   * Start listening for live block headers and processing transactions.
   */
  public async start() {
    this.connectSIEM();

    console.log('👁  Listening for new blocks on the blockchain...');
    
    this.provider.on('block', async (blockNumber: number) => {
      try {
        console.log(`📦 New Block Minted: #${blockNumber}`);
        const block = await this.provider.getBlock(blockNumber, true);
        if (!block || !block.prefixedTransactions) return;

        const events: ChainEvent[] = [];

        for (const tx of block.prefixedTransactions) {
          // Skip if tx.to is null (contract deployment)
          if (!tx.to) continue;

          // Get receipt to get exact gasUsed
          const receipt = await this.provider.getTransactionReceipt(tx.hash);
          if (!receipt) continue;

          // Determine event name based on standard EVM signatures or default to transaction
          let eventName = 'Call';
          if (tx.data !== '0x') {
            if (tx.data.startsWith('0xa9059cbb')) eventName = 'Transfer';
            else if (tx.data.startsWith('0x095b1903')) eventName = 'Approval';
            else if (tx.data.startsWith('0x35975f4b')) eventName = 'Swap';
            else if (tx.data.startsWith('0x5c11d795')) eventName = 'Swap';
            else if (tx.data.toLowerCase().includes('withdraw')) eventName = 'Withdrawal';
            else eventName = 'ContractCall';
          } else if (BigInt(tx.value) > 0n) {
            eventName = 'Transfer';
          }

          const event: ChainEvent = {
            id: tx.hash,
            contractAddress: tx.to,
            eventName,
            gasUsed: Number(receipt.gasUsed),
            callValue: tx.value.toString(),
            args: {
              sender: tx.from,
              recipient: tx.to,
              data: tx.data,
              nonce: tx.nonce,
              gasPrice: tx.gasPrice?.toString() || '0',
            }
          };

          events.push(event);
        }

        if (events.length > 0) {
          this.streamToSIEM(events);
        }

      } catch (err: any) {
        console.error(`❌ Error parsing block #${blockNumber}:`, err.message);
      }
    });
  }

  /**
   * Send a batch of formatted ChainEvents to the SIEM server.
   */
  private streamToSIEM(events: ChainEvent[]) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn(`⚠️  Cannot stream ${events.length} events — WebSocket not connected.`);
      return;
    }

    console.log(`📤 Streaming ${events.length} transaction events to SIEM server...`);
    const payload = JSON.stringify({
      type: 'ingest',
      events
    });

    this.ws.send(payload);
  }
}

// Start the automated live streamer
const streamer = new SIEMAutomationStreamer();
streamer.start().catch((err) => {
  console.error('❌ Critical error in SIEM Automation Streamer:', err.message);
});
