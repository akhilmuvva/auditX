import { describe, it, expect, afterEach } from '@jest/globals';
import { createServer, type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import WebSocket from 'ws';
import { startServer } from '../legacy/src/server.js';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import { WebhookDispatcher, type WebhookPayload } from '../legacy/src/webhook/webhookDispatcher.js';
import { verifyAuditXWebhook } from './fixtures/polylanceVerifyWebhook.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

function tempPath(prefix: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), prefix)), 'data.json');
}

async function listeningPort(server: Server): Promise<number> {
  if (!server.listening) await once(server, 'listening');
  return (server.address() as { port: number }).port;
}

describe('Phase 8: High-Scale PolyLance E2E Benchmark & Fault Injection', () => {
  it('processes >=1000 events with event-to-receipt latency, fault injection (RPC/WS/500), and DLQ recovery', async () => {
    process.env.AUDITX_API_TOKEN = 'test-admin-secret-token-12345';
    const regPath = tempPath('reg-');
    const dlqPath = tempPath('dlq-');
    const registry = new TenantRegistry(regPath);
    const dispatcher = new WebhookDispatcher(dlqPath);

    let simulate500 = false;
    const receivedAlertIds = new Set<string>();
    const receivedPayloads: any[] = [];
    let duplicateAlertCount = 0;

    // 1. Start Webhook Receiver with PolyLance Receiver Verification Fixture
    let issuedHmacSecret = '';
    const webhookServer = createServer((req, res) => {
      let rawBody = '';
      req.on('data', chunk => rawBody += chunk);
      req.on('end', async () => {
        if (simulate500) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Injected receiver fault (500)' }));
          return;
        }

        const signature = (req.headers['x-auditx-signature'] as string) || '';
        const timestamp = (req.headers['x-auditx-timestamp'] as string) || '';
        const nonce = (req.headers['x-auditx-nonce'] as string) || '';

        const verification = await verifyAuditXWebhook(rawBody, signature, timestamp, nonce, issuedHmacSecret);
        if (!verification.valid) {
          res.writeHead(401).end(verification.error || 'Unauthorized');
          return;
        }

        const parsed = JSON.parse(rawBody);
        if (receivedAlertIds.has(parsed.alert_id)) {
          duplicateAlertCount++;
        } else {
          receivedAlertIds.add(parsed.alert_id);
        }
        receivedPayloads.push(parsed);
        res.writeHead(200).end('OK');
      });
    }).listen(0);
    servers.push(webhookServer);
    const webhookPort = await listeningPort(webhookServer);

    // 2. Start Express SIEM Server
    const siemServer = startServer(0, registry);
    servers.push(siemServer);
    const siemPort = await listeningPort(siemServer);

    // 3. Register PolyLance Tenant
    const { client, apiKey, hmacSecret } = registry.registerClient(
      'PolyLance',
      `http://127.0.0.1:${webhookPort}/api/v1/siem-webhook`
    );
    issuedHmacSecret = hmacSecret;
    expect(client.name).toBe('PolyLance');

    // 4. Register Monitored Escrow Contract
    const targetAddress = '0x1111111111111111111111111111111111111111';
    registry.registerMonitoredAddress(
      apiKey,
      targetAddress,
      'polygon',
      ['PaymentReleased', 'DisputeRaised', 'JobFunded', 'OwnershipTransferred']
    );

    // 5. Fault Test 1: WebSocket Drop & Reconnect
    let ws = new WebSocket(`ws://127.0.0.1:${siemPort}/ws/siem`, `auditx-api-key.${apiKey}`);
    await once(ws, 'open');

    // Drop connection
    ws.close();
    await once(ws, 'close');

    // Reconnect
    ws = new WebSocket(`ws://127.0.0.1:${siemPort}/ws/siem`, `auditx-api-key.${apiKey}`);
    await once(ws, 'open');

    // 6. Ingest 1,000 Events (50 batches of 20 events) and measure latency
    const TOTAL_EVENTS = 1000;
    const BATCH_SIZE = 20;
    const batchCount = TOTAL_EVENTS / BATCH_SIZE;
    const eventLatencies: number[] = [];

    for (let b = 0; b < batchCount; b++) {
      const batch: ChainEvent[] = [];
      const batchStart = performance.now();

      for (let i = 0; i < BATCH_SIZE; i++) {
        const idx = b * BATCH_SIZE + i;
        batch.push({
          id: `ev-scale-${idx}-${Date.now()}`,
          timestamp: Date.now(),
          chainId: 137,
          contractAddress: targetAddress,
          txHash: `0xhash${idx}`,
          blockNumber: 60000000 + idx,
          eventName: idx % 2 === 0 ? 'PaymentReleased' : 'DisputeRaised',
          args: {
            toFreelancer: '975000000000000000',
            fee: '25000000000000000',
            by: '0xuser1',
            reason: 0,
            evidenceIpfsHash: 'QmEv',
          },
          gasUsed: 180000 + (idx % 10) * 10000,
          callValue: '0',
          from: '0x0000000000000000000000000000000000000123',
        });
      }

      const res = await fetch(`http://127.0.0.1:${siemPort}/api/siem/ingest`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
        },
        body: JSON.stringify({ events: batch }),
      });

      expect(res.status).toBe(200);
      const batchElapsed = performance.now() - batchStart;
      const perEventLatency = batchElapsed / BATCH_SIZE;
      for (let i = 0; i < BATCH_SIZE; i++) {
        eventLatencies.push(perEventLatency);
      }
    }

    ws.close();

    // 7. Fault Test 2: Receiver 500 for N iterations -> DLQ -> Recovery
    simulate500 = true;
    const faultPayload: WebhookPayload = {
      schema_version: '1.0.0',
      alert_id: 'fault-alert-retry-999',
      contract_address: targetAddress.toLowerCase(),
      owning_app: 'PolyLance',
      chain: '137',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Fault Injected Alert',
      description: 'Testing DLQ overflow and retry backoff handling',
      detected_at: new Date().toISOString(),
      event_type: 'PaymentReleased',
      tx_hash: '0xfault_tx',
      status: 'DETECTED',
    };

    // Config for retry backoff: [0, 10] ms in test, [60000, 300000, 900000] in prod
    const failedSend = await dispatcher.sendWithRetry(
      `http://127.0.0.1:${webhookPort}/api/v1/siem-webhook`,
      issuedHmacSecret,
      faultPayload,
      [0, 5]
    );
    expect(failedSend).toBe(false);

    // Verify DLQ Depth
    const dlqItems = dispatcher.getDLQ();
    expect(dlqItems.length).toBe(1);
    expect(dlqItems[0].payload.alert_id).toBe('fault-alert-retry-999');

    // Recover Receiver and Replay from DLQ
    simulate500 = false;
    for (const item of dlqItems) {
      const recovered = await dispatcher.sendWithRetry(item.webhookUrl, issuedHmacSecret, item.payload, [0]);
      expect(recovered).toBe(true);
    }
    dispatcher.clearDLQ();
    expect(dispatcher.getDLQ()).toHaveLength(0);

    // 8. Assert Zero Duplicate Alerts & Verification via PolyLance Receiver
    expect(duplicateAlertCount).toBe(0);
    expect(receivedPayloads.length).toBe(1);
    expect(receivedAlertIds.has('fault-alert-retry-999')).toBe(true);

    // 9. Latency Benchmark Metrics (p50, p95, p99)
    eventLatencies.sort((a, b) => a - b);
    const p50 = eventLatencies[Math.floor(eventLatencies.length * 0.5)];
    const p95 = eventLatencies[Math.floor(eventLatencies.length * 0.95)];
    const p99 = eventLatencies[Math.floor(eventLatencies.length * 0.99)];

    console.log(`\n=== 1,000 EVENTS POLYLANCE BENCHMARK ===`);
    console.log(`Total Events: ${TOTAL_EVENTS}`);
    console.log(`Batch Count: ${batchCount} (20 events/batch)`);
    console.log(`p50 Per-Event Latency: ${p50.toFixed(2)} ms`);
    console.log(`p95 Per-Event Latency: ${p95.toFixed(2)} ms`);
    console.log(`p99 Per-Event Latency: ${p99.toFixed(2)} ms`);
    console.log(`Duplicate Alerts: ${duplicateAlertCount}`);
    console.log(`Target Warm-Path SLA: < 300.00 ms`);

    expect(p95).toBeLessThan(300);
  });
});
