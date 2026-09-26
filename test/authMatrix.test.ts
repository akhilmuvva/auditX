// @ts-nocheck
import { startServer } from '../legacy/src/server.js';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import { request as httpRequest, type Server } from 'http';
import { once } from 'events';
import WebSocket from 'ws';
import fs from 'fs';
import os from 'os';
import path from 'path';

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

async function req(port: number, method: string, path: string, headers: Record<string, string> = {}, body: any = null): Promise<{ status?: number; body?: string }> {
  return new Promise((resolve) => {
    const r = httpRequest({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        'content-type': 'application/json',
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    r.on('error', (err) => resolve({ status: 500, body: err.message }));
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

async function testWs(port: number, protocol: string | null): Promise<number> {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/siem`, protocol ? [protocol] : undefined);
    let closed = false;
    ws.on('close', (code) => {
      closed = true;
      resolve(code);
    });
    ws.on('open', () => {
      // If server doesn't close it within 150ms, it is an accepted authenticated connection
      setTimeout(() => {
        if (!closed) {
          ws.close();
          resolve(1000); // 1000 = Accepted & open
        }
      }, 150);
    });
    ws.on('error', () => {});
  });
}

describe('Express REST & WebSocket Auth Verification Matrix (Static Admin Allowlist)', () => {
  it('measures status codes across no-token, invalid-token, allowlisted-admin-token, and non-allowlisted callers', async () => {
    const tempPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-auth-')), 'reg.json');
    const allowlistedAdminKey = 'ax_live_polylance_admin_static_secret_9988';
    process.env.AUDITX_API_TOKEN = 'test-admin-token-12345';
    process.env.AUDITX_ADMIN_API_KEYS = allowlistedAdminKey;
    process.env.AUDITX_REGISTRY_PATH = tempPath;
    const registry = new TenantRegistry(tempPath);
    const server = startServer(0, registry);
    servers.push(server);
    if (!server.listening) await once(server, 'listening');
    const port = (server.address() as { port: number }).port;

    const results: any[] = [];

    const endpoints = [
      { name: 'GET /api/siem/alerts', method: 'GET', path: '/api/siem/alerts', body: null },
      { name: 'GET /api/siem/baseline', method: 'GET', path: '/api/siem/baseline', body: null },
      { name: 'POST /api/siem/ingest', method: 'POST', path: '/api/siem/ingest', body: { events: [{ id: '1', timestamp: Date.now(), chainId: 137, contractAddress: '0x0000000000000000000000000000000000000001', txHash: '0x1', blockNumber: 1, eventName: 'test', args: {}, gasUsed: 100, callValue: '0', from: '0x1' }] } },
      { name: 'POST /api/siem/clients', method: 'POST', path: '/api/siem/clients', body: { name: 'TestApp', webhook_url: 'https://test.com/hook' } },
      { name: 'POST /api/siem/monitored-addresses', method: 'POST', path: '/api/siem/monitored-addresses', body: { address: '0x00000000000000000000000000000000000000aa', chain: 'polygon', watch_config: ['fund-release'] } },
      { name: 'POST /api/monitor/register', method: 'POST', path: '/api/monitor/register', body: { address: '0x00000000000000000000000000000000000000aa' } },
    ];

    for (const ep of endpoints) {
      // 1. No token
      const noToken = await req(port, ep.method, ep.path, {}, ep.body);
      // 2. Wrong token
      const wrongToken = await req(port, ep.method, ep.path, { authorization: 'Bearer wrong-token-xyz' }, ep.body);
      // 3. Valid Master Admin token
      const adminToken = await req(port, ep.method, ep.path, { authorization: 'Bearer test-admin-token-12345' }, ep.body);
      // 4. Allowlisted Admin API Key
      const allowlistedKey = await req(port, ep.method, ep.path, { 'x-api-key': allowlistedAdminKey }, ep.body);

      results.push({
        endpoint: ep.name,
        noToken: noToken.status,
        wrongToken: wrongToken.status,
        validAdmin: adminToken.status,
        allowlistedApiKey: allowlistedKey.status,
      });
    }

    // WS /ws/siem
    const wsNoToken = await testWs(port, null);
    const wsWrongToken = await testWs(port, 'auditx-api-key.invalid_key');
    const wsValidKey = await testWs(port, `auditx-api-key.${allowlistedAdminKey}`);

    console.log('=== AUTH VERIFICATION MATRIX ===');
    console.table(results);
    console.log('=== WEBSOCKET (/ws/siem) HANDSHAKE CLOSURE CODES ===');
    console.log({ wsNoToken, wsWrongToken, wsValidKey });

    // Assertions
    for (const r of results) {
      if (r.endpoint === 'POST /api/monitor/register') {
        // Removed endpoint returns 404 (or 401 unauthed)
        expect([401, 404]).toContain(r.noToken);
        expect([401, 404]).toContain(r.wrongToken);
        expect(r.validAdmin).toBe(404);
        expect(r.allowlistedApiKey).toBe(404);
      } else if (r.endpoint === 'POST /api/siem/clients') {
        // Client self-registration is disabled for all callers
        expect(r.noToken).toBe(401);
        expect(r.wrongToken).toBe(401);
        expect(r.validAdmin).toBe(403);
        expect(r.allowlistedApiKey).toBe(403);
      } else {
        expect(r.noToken).toBe(401);
        expect(r.wrongToken).toBe(401);
        if (r.endpoint === 'POST /api/siem/monitored-addresses') {
          expect(r.allowlistedApiKey).toBe(201);
        } else {
          expect(r.validAdmin).toBe(200);
          expect(r.allowlistedApiKey).toBe(200);
        }
      }
    }
    expect(wsNoToken).toBe(1008);
    expect(wsWrongToken).toBe(1008);
    expect(wsValidKey).toBe(1000);
  });
});
