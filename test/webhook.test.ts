// @ts-nocheck
import { createServer, type Server } from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import { WebhookDispatcher, type WebhookPayload } from '../legacy/src/webhook/webhookDispatcher.js';

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

function tempDlqPath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'auditx-dlq-')), 'dlq.json');
}

describe('WebhookDispatcher & Contract Compliance', () => {
  it('matches exactly the test vector in docs/auditx-webhook-contract.md', () => {
    const secret = 'TEST_MOCK_SECRET_KEY_AUDITX_999';
    const timestamp = '1700000000000';
    const nonce = 'nonce_test_vector_abc123';
    const payload = '{"schema_version":"1.0.0","alert_id":"test-vec-1","contract_address":"0x00000000000000000000000000000000000000aa","chain":"137","severity":"CRITICAL","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert vector","detected_at":"2023-11-14T22:13:20.000Z","tx_hash":"0xtest","event_type":"DisputeResolved","status":"DETECTED"}';
    const signature = WebhookDispatcher.signPayload(secret, payload, timestamp, nonce);
    expect(signature).toBe('4da428c8bb7ba4e17d30805129e26a27bde0ad8cbbbf198857e174d083711cd4');
    expect(WebhookDispatcher.verifySignature(secret, payload, signature, timestamp, nonce)).toBe(true);
    expect(WebhookDispatcher.verifySignature('wrong_secret', payload, signature, timestamp, nonce)).toBe(false);
  });

  it('delivers signed payload to mock receiver with 3-header contract', async () => {
    const received: { body: string; signature?: string; timestamp?: string; nonce?: string }[] = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        received.push({
          body,
          signature: req.headers['x-auditx-signature'] as string,
          timestamp: req.headers['x-auditx-timestamp'] as string,
          nonce: req.headers['x-auditx-nonce'] as string,
        });
        res.writeHead(200).end('OK');
      });
    }).listen(0);
    servers.push(server);
    await once(server, 'listening');
    const port = (server.address() as { port: number }).port;

    const dispatcher = new WebhookDispatcher(tempDlqPath());
    const secret = 'test_webhook_secret_xyz123';
    const payload: WebhookPayload = {
      schema_version: '1.0.0',
      alert_id: 'alt-1',
      contract_address: '0x1234567890123456789012345678901234567890',
      owning_app: 'PolyLance',
      chain: '137',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Dispute Anomaly',
      description: 'Dispute raised anomalously',
      detected_at: new Date().toISOString(),
      timestamp: 1700000000000,
      event_type: 'DisputeRaised',
      tx_hash: '0xabc',
      status: 'DETECTED',
    };

    const success = await dispatcher.sendWithRetry(`http://127.0.0.1:${port}/webhook`, secret, payload, [0]);
    expect(success).toBe(true);
    expect(received).toHaveLength(1);
    expect(received[0].signature).toBeDefined();
    expect(received[0].timestamp).toBeDefined();
    expect(received[0].nonce).toBeDefined();
    expect(
      WebhookDispatcher.verifySignature(
        secret,
        received[0].body,
        received[0].signature!,
        received[0].timestamp!,
        received[0].nonce!
      )
    ).toBe(true);
    expect(dispatcher.getDLQ()).toHaveLength(0);
  });

  it('records failed webhook into DLQ on terminal failure', async () => {
    const dlqFile = tempDlqPath();
    const dispatcher = new WebhookDispatcher(dlqFile);
    const secret = 'test_webhook_secret_xyz123';
    const payload: WebhookPayload = {
      schema_version: '1.0.0',
      alert_id: 'alt-failed-1',
      contract_address: '0x1234567890123456789012345678901234567890',
      owning_app: 'PolyLance',
      chain: '137',
      severity: 'CRITICAL',
      category: 'GOVERNANCE',
      title: 'Dead Target',
      description: 'Target unreachable',
      detected_at: new Date().toISOString(),
      timestamp: 1700000000000,
      event_type: 'PaymentReleased',
      tx_hash: '0xdead',
      status: 'DETECTED',
    };

    const success = await dispatcher.sendWithRetry('http://127.0.0.1:49999/unreachable', secret, payload, [0, 10]);
    expect(success).toBe(false);
    const dlq = dispatcher.getDLQ();
    expect(dlq).toHaveLength(1);
    expect(dlq[0].payload.alert_id).toBe('alt-failed-1');
    expect(fs.existsSync(dlqFile)).toBe(true);
  });
});
