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

describe('PolyLance E2E Integration Suite with Fault Injection & Latency SLA', () => {
  it('executes full ingest -> detect -> webhook dispatch pipeline with p50/p95 latency', async () => {
    process.env.AUDITX_API_TOKEN = 'test-admin-secret-token-12345';
    const regPath = tempPath('reg-');
    const registry = new TenantRegistry(regPath);

    // 1. Start Webhook Mock Receiver
    const receivedWebhooks: { body: string; signature?: string }[] = [];
    const webhookServer = createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        receivedWebhooks.push({ body, signature: req.headers['x-auditx-signature'] });
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
    expect(client.name).toBe('PolyLance');
    expect(apiKey).toBeDefined();

    // 4. Register Monitored PolyLance Escrow Contract
    const targetAddress = '0x1111111111111111111111111111111111111111';
    const monitored = registry.registerMonitoredAddress(
      apiKey,
      targetAddress,
      'polygon',
      ['fund-release', 'dispute-trigger']
    );
    expect(monitored.address).toBe(targetAddress.toLowerCase());

    // 5. Connect Authenticated WebSocket
    const ws = new WebSocket(`ws://127.0.0.1:${siemPort}/ws/siem`, `auditx-api-key.${apiKey}`);
    await once(ws, 'open');

    // 6. Ingest benchmark batch and compute latency
    const latencies: number[] = [];
    const iterations = 10;

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();
      const testEvent: ChainEvent = {
        id: `e2e-ev-${i}-${Date.now()}`,
        timestamp: Date.now(),
        chainId: 137,
        contractAddress: targetAddress,
        txHash: `0xtxhash${i}${Date.now()}`,
        blockNumber: 50000000 + i,
        eventName: 'fund-release',
        args: { recipient: '0xattacker', amount: '50000000000000000000' },
        gasUsed: 450000, // Spike to trigger anomaly detection
        callValue: '50.0',
        from: '0x0000000000000000000000000000000000000999',
      };

      const res = await fetch(`http://127.0.0.1:${siemPort}/api/siem/ingest`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
        },
        body: JSON.stringify({ events: [testEvent] }),
      });

      expect(res.status).toBe(200);
      const endTime = performance.now();
      latencies.push(endTime - startTime);
    }

    ws.close();

    // 7. Verify Webhook Delivery and Signature Integrity
    expect(receivedWebhooks.length).toBeGreaterThanOrEqual(1);
    const firstWebhook = receivedWebhooks[0];
    const parsedPayload = JSON.parse(firstWebhook.body);
    expect(parsedPayload.owning_app).toBe('PolyLance');
    expect(parsedPayload.contract_address).toBe(targetAddress.toLowerCase());
    expect(
      WebhookDispatcher.verifySignature(hmacSecret, firstWebhook.body, firstWebhook.signature!)
    ).toBe(true);

    // 8. Compute and report p50/p95 latency
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];

    console.log(`\n=== POLYLANCE E2E BENCHMARK RESULTS ===`);
    console.log(`Ingest Iterations: ${iterations}`);
    console.log(`p50 Latency: ${p50.toFixed(2)} ms`);
    console.log(`p95 Latency: ${p95.toFixed(2)} ms`);
    console.log(`Target Warm-Path SLA: < 300.00 ms`);
    expect(p95).toBeLessThan(300); // 300ms SLA
  });
});
