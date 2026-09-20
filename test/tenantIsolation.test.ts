// @ts-nocheck
import { type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import WebSocket from 'ws';
import { startServer } from '../legacy/src/server.js';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import type { ChainEvent } from '../legacy/src/siem/types.js';

const servers: Server[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

function tempRegistryPath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-iso-')), 'registry.json');
}

async function listeningPort(server: Server): Promise<number> {
  if (!server.listening) await once(server, 'listening');
  return (server.address() as { port: number }).port;
}

describe('Phase 7: Strict Multi-Tenant Isolation Verification', () => {
  it('guarantees Tenant A never sees Tenant B alerts or monitored contracts on REST or WS', async () => {
    process.env.AUDITX_API_TOKEN = 'admin-secret-isolation-token';
    const filePath = tempRegistryPath();
    process.env.AUDITX_REGISTRY_PATH = filePath;
    const registry = new TenantRegistry(filePath);

    // 1. Register Tenant A and Tenant B
    const tenantA = registry.registerClient('TenantA_PolyLance', 'https://polylance.codes/api/webhooks/auditx-alert');
    const tenantB = registry.registerClient('TenantB_Enterprise', 'https://enterprise.internal/webhooks/auditx');

    // 2. Register distinct contracts for each tenant
    const contractA = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const contractB = '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

    registry.registerMonitoredAddress(tenantA.apiKey, contractA, 'polygon', ['fund-release', 'PaymentReleased']);
    registry.registerMonitoredAddress(tenantB.apiKey, contractB, 'polygon', ['fund-release', 'PaymentReleased']);

    // 3. Verify registry isolation
    const listA = registry.listMonitoredAddresses(tenantA.apiKey);
    const listB = registry.listMonitoredAddresses(tenantB.apiKey);

    expect(listA).toHaveLength(1);
    expect(listA[0].address).toBe(contractA.toLowerCase());
    expect(listB).toHaveLength(1);
    expect(listB[0].address).toBe(contractB.toLowerCase());

    // Tenant A cannot deregister Tenant B's address
    const deregisterAttempt = registry.deregisterMonitoredAddress(tenantA.apiKey, contractB);
    expect(deregisterAttempt).toBe(false);

    // 4. Start Authoritative SIEM Server
    const server = startServer(0, registry);
    servers.push(server);
    const port = await listeningPort(server);

    // 5. Connect isolated WebSockets for Tenant A and Tenant B
    const wsA = new WebSocket(`ws://127.0.0.1:${port}/ws/siem`, `auditx-api-key.${tenantA.apiKey}`);
    const wsB = new WebSocket(`ws://127.0.0.1:${port}/ws/siem`, `auditx-api-key.${tenantB.apiKey}`);

    await Promise.all([once(wsA, 'open'), once(wsB, 'open')]);

    const messagesA: any[] = [];
    const messagesB: any[] = [];

    wsA.on('message', (data) => {
      try { messagesA.push(JSON.parse(data.toString())); } catch {}
    });
    wsB.on('message', (data) => {
      try { messagesB.push(JSON.parse(data.toString())); } catch {}
    });

    // 6. Ingest critical threat event on Contract A (Tenant A)
    const eventA: ChainEvent = {
      id: 'ev-tenant-a-1',
      timestamp: Date.now(),
      chainId: 137,
      contractAddress: contractA,
      txHash: '0xhashA',
      blockNumber: 100,
      eventName: 'PaymentReleased',
      args: { unfunded: true, toFreelancer: '1000000000000000000', fee: '25000000000000000' },
      gasUsed: 90000,
      callValue: '0',
      from: '0x1111111111111111111111111111111111111111',
    };

    const resA = await fetch(`http://127.0.0.1:${port}/api/siem/ingest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': tenantA.apiKey },
      body: JSON.stringify({ events: [eventA] }),
    });
    expect(resA.status).toBe(200);

    // Wait for event broadcast
    await new Promise(r => setTimeout(r, 200));

    // 7. Verify Isolation:
    // Tenant A's REST query returns alerts for Contract A
    const restResA = await fetch(`http://127.0.0.1:${port}/api/siem/alerts`, {
      headers: { 'x-api-key': tenantA.apiKey },
    });
    expect(restResA.status).toBe(200);
    const dataA = await restResA.json();
    const alertsA = Array.isArray(dataA) ? dataA : (dataA.alerts || []);
    expect(alertsA.length).toBeGreaterThanOrEqual(1);
    expect(alertsA.every((a: any) => a.event.contractAddress.toLowerCase() === contractA.toLowerCase())).toBe(true);

    // Tenant B's REST query returns NO alerts for Contract A
    const restResB = await fetch(`http://127.0.0.1:${port}/api/siem/alerts`, {
      headers: { 'x-api-key': tenantB.apiKey },
    });
    expect(restResB.status).toBe(200);
    const dataB = await restResB.json();
    const alertsB = Array.isArray(dataB) ? dataB : (dataB.alerts || []);
    expect(alertsB).toHaveLength(0);

    // WebSocket messages: Tenant A receives alert; Tenant B receives nothing
    const alertMessagesA = messagesA.filter((m: any) => m.type === 'alert');
    expect(alertMessagesA.length).toBeGreaterThanOrEqual(1);
    expect(
      alertMessagesA.some((m: any) => m.data?.event?.contractAddress?.toLowerCase() === contractA.toLowerCase())
    ).toBe(true);
    const alertMessagesB = messagesB.filter((m: any) => m.type === 'alert');
    expect(alertMessagesB).toHaveLength(0);

    wsA.close();
    wsB.close();
  });
});
