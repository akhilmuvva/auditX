// @ts-nocheck
import { createServer, type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import { WebhookDispatcher } from '../legacy/src/webhook/webhookDispatcher.js';
import type { Alert } from '../legacy/src/siem/types.js';

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

function tempDlqPath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-dlq-')), 'dlq.json');
}

describe('WebhookDispatcher & Contract Compliance', () => {
  it('matches exactly the test vector in docs/auditx-webhook-contract.md', () => {
    const secret = 'sec_0123456789abcdef0123456789abcdef';
    const payload = '{"alert_id":"test-1","contract_address":"0x00000000000000000000000000000000000000aa","owning_app":"PolyLance","chain":"polygon","severity":"HIGH","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert","timestamp":1700000000000,"event_type":"fund-release","tx_hash":"0xtest"}';
    const signature = WebhookDispatcher.signPayload(secret, payload);
    expect(signature).toBe('sha256=157186cd40465c7e63904242627ec690d23edf424e4c4cb41cd830f14c222bcc');
    expect(WebhookDispatcher.verifySignature(secret, payload, signature)).toBe(true);
    expect(WebhookDispatcher.verifySignature('wrong_secret', payload, signature)).toBe(false);
  });

  it('delivers signed payload to mock receiver', async () => {
    const received: { body: string; signature?: string }[] = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        received.push({ body, signature: req.headers['x-auditx-signature'] });
        res.writeHead(200).end('OK');
      });
    }).listen(0);
    servers.push(server);
    await once(server, 'listening');
    const port = (server.address() as { port: number }).port;

    const dispatcher = new WebhookDispatcher(tempDlqPath());
    const secret = 'sec_test_secret_12345';
    const payload = {
      alert_id: 'alt-1',
      contract_address: '0x1234567890123456789012345678901234567890',
      owning_app: 'PolyLance',
      chain: 'polygon',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Dispute Anomaly',
      description: 'Dispute raised anomalously',
      timestamp: 1700000000000,
      event_type: 'dispute-trigger',
      tx_hash: '0xabc',
    };

    const success = await dispatcher.sendWithRetry(`http://127.0.0.1:${port}/webhook`, secret, payload, [0]);
    expect(success).toBe(true);
    expect(received).toHaveLength(1);
    expect(WebhookDispatcher.verifySignature(secret, received[0].body, received[0].signature!)).toBe(true);
    expect(dispatcher.getDLQ()).toHaveLength(0);
  });

  it('records failed webhook into DLQ on terminal failure', async () => {
    const dlqFile = tempDlqPath();
    const dispatcher = new WebhookDispatcher(dlqFile);
    const secret = 'sec_test_secret_12345';
    const payload = {
      alert_id: 'alt-failed-1',
      contract_address: '0x1234567890123456789012345678901234567890',
      owning_app: 'PolyLance',
      chain: 'polygon',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Dead Target',
      description: 'Target unreachable',
      timestamp: 1700000000000,
      event_type: 'fund-release',
      tx_hash: '0xdead',
    };

    // Attempt delivery to a port that is guaranteed not open
    const success = await dispatcher.sendWithRetry('http://127.0.0.1:49999/unreachable', secret, payload, [0, 10]);
    expect(success).toBe(false);
    const dlq = dispatcher.getDLQ();
    expect(dlq).toHaveLength(1);
    expect(dlq[0].payload.alert_id).toBe('alt-failed-1');
    expect(fs.existsSync(dlqFile)).toBe(true);
  });
});
