// @ts-nocheck
import { createServer, type Server } from 'http';
import { once } from 'events';
import { WebhookDispatcher, type WebhookPayload } from '../legacy/src/webhook/webhookDispatcher.js';
import { verifyAuditXWebhook } from './fixtures/polylanceVerifyWebhook.js';

const servers: Server[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

describe('Cross-Repo Webhook Reconciliation (AuditX <-> PolyLance Chat Service)', () => {
  const secret = 'MOCK_INTEGRATION_SECRET_9999999';

  const validPayload: WebhookPayload = {
    schema_version: '1.0.0',
    alert_id: 'alt-cross-repo-1',
    contract_address: '0xbe74923bbfd72d400a681915dbcf6e6adc72c317',
    owning_app: 'PolyLance',
    chain: '137',
    severity: 'CRITICAL',
    category: 'SECURITY',
    title: 'Unauthorized Milestone Release Attempt',
    description: 'Caller not designated client or arbitrator attempted fund-release',
    detected_at: new Date().toISOString(),
    event_type: 'PaymentReleased',
    tx_hash: '0x4f8a12bc90de45f678901234567890abcdef1234567890abcdef1234567890ab',
    status: 'DETECTED',
  };

  it('matches exactly the test vector from docs/auditx-webhook-contract.md', () => {
    const vectorSecret = 'TEST_MOCK_SECRET_KEY_AUDITX_999';
    const timestamp = '1700000000000';
    const nonce = 'nonce_test_vector_abc123';
    const rawBody = '{"schema_version":"1.0.0","alert_id":"test-vec-1","contract_address":"0x00000000000000000000000000000000000000aa","chain":"137","severity":"CRITICAL","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert vector","detected_at":"2023-11-14T22:13:20.000Z","tx_hash":"0xtest","event_type":"DisputeResolved","status":"DETECTED"}';
    const sig = WebhookDispatcher.signPayload(vectorSecret, rawBody, timestamp, nonce);
    expect(sig).toBe('4da428c8bb7ba4e17d30805129e26a27bde0ad8cbbbf198857e174d083711cd4');
    expect(WebhookDispatcher.verifySignature(vectorSecret, rawBody, sig, timestamp, nonce)).toBe(true);
  });

  it('PolyLance verifyWebhook accepts payload generated and dispatched by AuditX WebhookDispatcher', async () => {
    let receiverResult: any = null;

    const server = createServer(async (req, res) => {
      let rawBody = '';
      req.on('data', chunk => rawBody += chunk);
      req.on('end', async () => {
        const sig = req.headers['x-auditx-signature'] as string;
        const ts = req.headers['x-auditx-timestamp'] as string;
        const nonce = req.headers['x-auditx-nonce'] as string;

        receiverResult = await verifyAuditXWebhook(rawBody, sig, ts, nonce, secret);
        if (receiverResult.valid) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok' }));
        } else {
          res.writeHead(receiverResult.code || 401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: receiverResult.error }));
        }
      });
    }).listen(0);
    servers.push(server);
    await once(server, 'listening');
    const port = (server.address() as { port: number }).port;

    const dispatcher = new WebhookDispatcher();
    const success = await dispatcher.sendWithRetry(`http://127.0.0.1:${port}/api/webhooks/auditx-alert`, secret, validPayload, [0]);
    expect(success).toBe(true);
    expect(receiverResult).not.toBeNull();
    expect(receiverResult.valid).toBe(true);
  });

  it('PolyLance verifyWebhook rejects tampered payload', async () => {
    const rawBody = JSON.stringify(validPayload);
    const ts = Date.now().toString();
    const nonce = 'unique_nonce_1';
    const sig = WebhookDispatcher.signPayload(secret, rawBody, ts, nonce);

    const tamperedBody = JSON.stringify({ ...validPayload, severity: 'LOW' });
    const result = await verifyAuditXWebhook(tamperedBody, sig, ts, nonce, secret);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid signature digest mismatch');
  });

  it('PolyLance verifyWebhook rejects expired timestamp (> 5 minutes)', async () => {
    const rawBody = JSON.stringify(validPayload);
    const expiredTs = (Date.now() - 6 * 60 * 1000).toString(); // 6 minutes ago
    const nonce = 'unique_nonce_2';
    const sig = WebhookDispatcher.signPayload(secret, rawBody, expiredTs, nonce);

    const result = await verifyAuditXWebhook(rawBody, sig, expiredTs, nonce, secret);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Timestamp expired');
  });

  it('PolyLance verifyWebhook rejects replayed nonce', async () => {
    const rawBody = JSON.stringify(validPayload);
    const ts = Date.now().toString();
    const nonce = 'replay_nonce_test_99';
    const sig = WebhookDispatcher.signPayload(secret, rawBody, ts, nonce);

    const first = await verifyAuditXWebhook(rawBody, sig, ts, nonce, secret);
    expect(first.valid).toBe(true);

    const second = await verifyAuditXWebhook(rawBody, sig, ts, nonce, secret);
    expect(second.valid).toBe(false);
    expect(second.error).toContain('Invalid or replayed nonce');
  });

  it('PolyLance verifyWebhook rejects missing or malformed signature', async () => {
    const rawBody = JSON.stringify(validPayload);
    const ts = Date.now().toString();
    const nonce = 'unique_nonce_3';

    const missing = await verifyAuditXWebhook(rawBody, null, ts, nonce, secret);
    expect(missing.valid).toBe(false);
    expect(missing.error).toContain('Missing x-auditx-signature header');

    const malformed = await verifyAuditXWebhook(rawBody, 'not-a-64-char-hex', ts, nonce, secret);
    expect(malformed.valid).toBe(false);
    expect(malformed.error).toContain('Invalid signature format: expected 64 hex characters');
  });
});
