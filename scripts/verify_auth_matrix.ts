import { startServer } from '../legacy/src/server.js';
import { TenantRegistry } from '../legacy/src/tenantRegistry.js';
import { request as httpRequest } from 'http';
import { once } from 'events';
import WebSocket from 'ws';
import fs from 'fs';
import os from 'os';
import path from 'path';

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
    ws.on('open', () => {
      ws.close();
      resolve(1000); // Successfully established and closed
    });
    ws.on('close', (code) => {
      resolve(code);
    });
    ws.on('error', () => {});
  });
}

async function main() {
  const tempPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-auth-')), 'reg.json');
  process.env.AUDITX_API_TOKEN = 'test-admin-token-12345';
  process.env.AUDITX_REGISTRY_PATH = tempPath;
  const registry = new TenantRegistry(tempPath);
  const issued = registry.registerClient('PolyLance', 'https://polylance.codes/api/webhooks/auditx-alert');
  const server = startServer(0, registry);
  if (!server.listening) await once(server, 'listening');
  const port = (server.address() as { port: number }).port;

  const results: any[] = [];

  const endpoints = [
    { name: 'GET /api/siem/alerts', method: 'GET', path: '/api/siem/alerts', body: null },
    { name: 'GET /api/siem/baseline', method: 'GET', path: '/api/siem/baseline', body: null },
    { name: 'POST /api/siem/ingest', method: 'POST', path: '/api/siem/ingest', body: { events: [{ id: '1', timestamp: Date.now(), chainId: 137, contractAddress: '0x0000000000000000000000000000000000000001', txHash: '0x1', blockNumber: 1, eventName: 'test', args: {}, gasUsed: 100, callValue: '0', from: '0x1' }] } },
    { name: 'POST /api/siem/clients', method: 'POST', path: '/api/siem/clients', body: { name: 'TestApp', webhook_url: 'https://test.com/hook' } },
    { name: 'POST /api/siem/monitored-addresses', method: 'POST', path: '/api/siem/monitored-addresses', body: { address: '0x00000000000000000000000000000000000000aa', chain: 'polygon', watch_config: ['fund-release'] } },
  ];

  for (const ep of endpoints) {
    // 1. No token
    const noToken = await req(port, ep.method, ep.path, {}, ep.body);
    // 2. Wrong token
    const wrongToken = await req(port, ep.method, ep.path, { authorization: 'Bearer wrong-token-xyz' }, ep.body);
    // 3. Valid Admin token
    const adminToken = await req(port, ep.method, ep.path, { authorization: 'Bearer test-admin-token-12345' }, ep.body);
    // 4. Valid Client API Key
    const clientKey = await req(port, ep.method, ep.path, { 'x-api-key': issued.apiKey }, ep.body);

    results.push({
      endpoint: ep.name,
      noToken: noToken.status,
      wrongToken: wrongToken.status,
      validAdmin: adminToken.status,
      validApiKey: clientKey.status,
    });
  }

  // WS /ws/siem
  const wsNoToken = await testWs(port, null);
  const wsWrongToken = await testWs(port, 'auditx-api-key.invalid_key');
  const wsValidKey = await testWs(port, `auditx-api-key.${issued.apiKey}`);

  server.close();

  console.log('=== AUTH VERIFICATION MATRIX ===');
  console.table(results);
  console.log('WebSocket /ws/siem:');
  console.log({ wsNoToken, wsWrongToken, wsValidKey });
  console.log('=== RAW JSON ===');
  console.log(JSON.stringify({ http: results, ws: { wsNoToken, wsWrongToken, wsValidKey } }, null, 2));
}

main().catch(console.error);
