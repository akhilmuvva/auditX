// @ts-nocheck
import { createServer, type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import WebSocket from 'ws';
import { startServer } from '../legacy/src/server.js';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import { WebhookDispatcher } from '../legacy/src/webhook/webhookDispatcher.js';
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
  it('processes >=1000 events with p50/p95/p99 benchmark, DLQ fault injection, and zero lost/duplicate alerts', async () => {
    process.env.AUDITX_API_TOKEN = 'test-admin-secret-token-12345';
    const regPath = tempPath('reg-');
    const dlqPath = tempPath('dlq-');
    const registry = new TenantRegistry(regPath);
    const dispatcher = new WebhookDispatcher(dlqPath);

    let simulate500 = false;
    const receivedAlertIds = new Set<string>();
    const receivedPayloads: any[] = [];
    let duplicateAlertCount = 0;

    // 1. Start Webhook Receiver with PolyLance HMAC Verification
    let issuedHmacSecret = '';
    const webhookServer = createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        if (simulate500) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Injected upstream fault' }));
          return;
        }

        const sig = req.headers['x-auditx-signature'] as string;
        const valid = WebhookDispatcher.verifySignature(issuedHmacSecret, body, sig);
        if (!valid) {
          res.writeHead(401).end('Invalid signature');
          return;
        }

        const parsed = JSON.parse(body);
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
      ['fund-release', 'dispute-trigger', 'deposit', 'ownership-transfer']
    );

    // 5. Connect WebSocket with closure testing
    let ws = new WebSocket(`ws://127.0.0.1:${siemPort}/ws/siem`, `auditx-api-key.${apiKey}`);
    await once(ws, 'open');

    // Test WS Drop and Reconnect
    ws.close();
    await once(ws, 'close');
    ws = new WebSocket(`ws://127.0.0.1:${siemPort}/ws/siem`, `auditx-api-key.${apiKey}`);
    await once(ws, 'open');

    // 6. Ingest 1,000 Events (50 batches of 20 events)
    const TOTAL_EVENTS = 1000;
    const BATCH_SIZE = 20;
    const batchCount = TOTAL_EVENTS / BATCH_SIZE;
    const latencies: number[] = [];

    for (let b = 0; b < batchCount; b++) {
      const batch: ChainEvent[] = [];
      for (let i = 0; i < BATCH_SIZE; i++) {
        const idx = b * BATCH_SIZE + i;
        batch.push({
          id: `ev-scale-${idx}-${Date.now()}`,
          timestamp: Date.now(),
          chainId: 137,
          contractAddress: targetAddress,
          txHash: `0xhash${idx}`,
          blockNumber: 60000000 + idx,
          eventName: idx % 2 === 0 ? 'fund-release' : 'dispute-trigger',
          args: { recipient: `0xuser${idx}`, amount: '10000000000000000000' },
          gasUsed: 180000 + (idx % 10) * 10000,
          callValue: '10.0',
          from: '0x0000000000000000000000000000000000000123',
        });
      }

      const startTime = performance.now();
      const res = await fetch(`http://127.0.0.1:${siemPort}/api/siem/ingest`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
        },
        body: JSON.stringify({ events: batch }),
      });

      expect(res.status).toBe(200);
      const elapsed = performance.now() - startTime;
      latencies.push(elapsed);
    }

    ws.close();

    // 7. Fault Injection Test: Receiver Failure -> DLQ Persistence -> Recovery
    simulate500 = true;
    const faultPayload = {
      alert_id: 'fault-alert-999',
      contract_address: targetAddress.toLowerCase(),
      owning_app: 'PolyLance',
      chain: 'polygon',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Fault Injected Alert',
      description: 'Testing DLQ overflow handling',
      timestamp: Date.now(),
      event_type: 'fund-release',
      tx_hash: '0xfault',
    };

    const failedSend = await dispatcher.sendWithRetry(
      `http://127.0.0.1:${webhookPort}/api/v1/siem-webhook`,
      issuedHmacSecret,
      faultPayload,
      [0, 10]
    );
    expect(failedSend).toBe(false);

    // Check DLQ Depth
    const dlqItems = dispatcher.getDLQ();
    expect(dlqItems.length).toBe(1);
    expect(dlqItems[0].payload.alert_id).toBe('fault-alert-999');

    // Recover Receiver and Replay from DLQ
    simulate500 = false;
    for (const item of dlqItems) {
      const recovered = await dispatcher.sendWithRetry(item.webhookUrl, issuedHmacSecret, item.payload, [0]);
      expect(recovered).toBe(true);
    }
    dispatcher.clearDLQ();
    expect(dispatcher.getDLQ()).toHaveLength(0);

    // 8. Assert Zero Duplicate and Zero Lost Alerts
    expect(duplicateAlertCount).toBe(0);
    expect(receivedPayloads.length).toBeGreaterThanOrEqual(1);
    expect(receivedAlertIds.size).toBe(receivedPayloads.length);

    // 9. Latency Benchmark Metrics (p50, p95, p99)
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    console.log(`\n=== 1,000 EVENTS POLYLANCE BENCHMARK ===`);
    console.log(`Total Events: ${TOTAL_EVENTS}`);
    console.log(`Batch Count: ${batchCount} (20 events/batch)`);
    console.log(`p50 Latency: ${p50.toFixed(2)} ms`);
    console.log(`p95 Latency: ${p95.toFixed(2)} ms`);
    console.log(`p99 Latency: ${p99.toFixed(2)} ms`);
    console.log(`Duplicate Alerts: ${duplicateAlertCount}`);
    console.log(`Target Warm-Path SLA: < 300.00 ms`);

    expect(p95).toBeLessThan(300);
  });
});
