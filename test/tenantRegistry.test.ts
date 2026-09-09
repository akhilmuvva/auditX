// @ts-nocheck
import { createServer, request as httpRequest, type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import WebSocket from 'ws';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import type { Alert } from '../legacy/src/siem/types.js';


const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

function tempRegistryPath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-registry-')), 'registry.json');
}

async function listeningPort(server: Server): Promise<number> {
  if (!server.listening) await once(server, 'listening');
  return (server.address() as { port: number }).port;
}

function alertFor(address: string): Alert {
  return {
    id: 'alert-1',
    timestamp: Date.now(),
    title: 'Fund release anomaly',
    description: 'Escrow release requires review',
    severity: 'HIGH',
    status: 'OPEN',
    event: {
      id: 'tx-1',
      timestamp: Date.now(),
      chainId: 137,
      contractAddress: address,
      txHash: '0xtx',
      blockNumber: 1,
      eventName: 'fund-release',
      args: {},
      gasUsed: 100,
      callValue: '0',
      from: '0x0000000000000000000000000000000000000001',
      category: 'GOVERNANCE',
      reason: 'test',
      ruleSeverity: 'HIGH',
      anomaly: { gasZScore: 0, valueZScore: 0, score: 0, isAnomaly: false },
      finalSeverity: 'HIGH',
      threatMatches: [],
      escalatedSeverity: 'HIGH',
    },
  };
}

describe('TenantRegistry', () => {
  it('persists tenant isolation and delivers a signed alert webhook', async () => {
    const received: { body: string; signature?: string }[] = [];
    const webhook = createServer((request, response) => {
      let body = '';
      request.on('data', (chunk) => { body += chunk; });
      request.on('end', () => {
        received.push({ body, signature: request.headers['x-auditx-signature'] });
        response.writeHead(202).end();
      });
    }).listen(0);
    servers.push(webhook);
    await once(webhook, 'listening');
    const port = (webhook.address() as { port: number }).port;

    const filePath = tempRegistryPath();
    const registry = new TenantRegistry(filePath);
    const issued = registry.registerClient('PolyLance', `http://127.0.0.1:${port}/webhook`);
    const monitored = registry.registerMonitoredAddress(
      issued.apiKey,
      '0x00000000000000000000000000000000000000AA',
      'polygon',
      ['fund-release', 'dispute-trigger'],
    );

    await registry.dispatchAlert(monitored, alertFor(monitored.address));
    expect(received).toHaveLength(1);
    expect(received[0].signature).toBe(
      TenantRegistry.signPayload(issued.hmacSecret, received[0].body),
    );
    expect(new TenantRegistry(filePath).authenticate(issued.apiKey)?.name).toBe('PolyLance');
    expect(new TenantRegistry(filePath).authenticate('ax_live_invalid')).toBeUndefined();
  });
});

describe('SIEM WebSocket authentication', () => {
  it('rejects unauthenticated SIEM REST requests', async () => {
    process.env.AUDITX_API_TOKEN = 'test-admin-token';
    process.env.AUDITX_REGISTRY_PATH = tempRegistryPath();
    const { startServer } = await import('../legacy/src/server.js');
    const server = startServer(0);
    servers.push(server);
    const port = await listeningPort(server);

    const response = await new Promise<{ statusCode?: number }>((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port, path: '/api/siem/alerts' }, (response) => {
        response.resume();
        response.on('end', () => resolve(response));
      });
      request.on('error', reject);
      request.end();
    });
    expect(response.statusCode).toBe(401);
  });

  it('closes unauthenticated handshakes', async () => {
    process.env.AUDITX_API_TOKEN = 'test-admin-token';
    process.env.AUDITX_REGISTRY_PATH = tempRegistryPath();
    const { startServer } = await import('../legacy/src/server.js');
    const server = startServer(0);
    servers.push(server);
    const port = await listeningPort(server);

    const socket = new WebSocket(`ws://127.0.0.1:${port}/ws/siem`);
    const [code] = await once(socket, 'close');
    expect(code).toBe(1008);
  });
});
