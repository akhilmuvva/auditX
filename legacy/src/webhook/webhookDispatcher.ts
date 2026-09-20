import { createHmac, timingSafeEqual, randomBytes } from 'crypto';
import fs from 'fs';
import path from 'path';
import { setTimeout as sleep } from 'timers/promises';
import type { Alert } from '../siem/types.js';
import type { MonitoredAddress, ClientApp } from '../storage/tenantStore.js';

export interface WebhookPayload {
  schema_version: string;
  alert_id: string;
  contract_address: string;
  owning_app?: string;
  chain: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  category: string;
  title: string;
  description: string;
  detected_at: string;
  timestamp?: number;
  event_type: string;
  tx_hash: string;
  status?: string;
  metadata?: Record<string, unknown>;
}

export interface DLQItem {
  id: string;
  webhookUrl: string;
  payload: WebhookPayload;
  attempts: number;
  lastError: string;
  failedAt: string;
}

export class WebhookDispatcher {
  private dlqPath: string;
  private dlq: DLQItem[] = [];

  constructor(dlqPath = path.join(process.cwd(), 'reports-cache', 'webhook-dlq.json')) {
    this.dlqPath = dlqPath;
    this.loadDLQ();
  }

  /**
   * Computes HMAC-SHA256 signature over `${timestamp}.${nonce}.${rawBody}`.
   * Returns a 64-character lowercase hex string.
   */
  static signPayload(secret: string, rawBody: string, timestamp: string | number, nonce: string): string {
    const messageToSign = `${timestamp}.${nonce}.${rawBody}`;
    return createHmac('sha256', secret).update(messageToSign, 'utf8').digest('hex');
  }

  /**
   * Verifies an incoming HMAC-SHA256 signature in constant time.
   */
  static verifySignature(
    secret: string,
    rawBody: string,
    signatureHeader: string,
    timestamp: string | number,
    nonce: string
  ): boolean {
    if (!signatureHeader || !secret || !timestamp || !nonce) return false;
    const cleanSig = signatureHeader.startsWith('0x') ? signatureHeader.slice(2) : signatureHeader;
    if (!/^[0-9a-fA-F]{64}$/.test(cleanSig)) return false;

    const computed = WebhookDispatcher.signPayload(secret, rawBody, timestamp, nonce);
    const left = Buffer.from(computed, 'hex');
    const right = Buffer.from(cleanSig, 'hex');
    return left.length === 32 && right.length === 32 && timingSafeEqual(left, right);
  }

  createPayload(monitored: MonitoredAddress, alert: Alert): WebhookPayload {
    const detectedIso = new Date(alert.timestamp || Date.now()).toISOString();
    return {
      schema_version: '1.0.0',
      alert_id: alert.id,
      contract_address: alert.event.contractAddress.toLowerCase(),
      owning_app: monitored.owningApp,
      chain: monitored.chain || '137',
      severity: alert.severity,
      category: alert.event.category || 'SECURITY',
      title: alert.title,
      description: alert.description,
      detected_at: detectedIso,
      timestamp: alert.timestamp,
      event_type: alert.event.eventName,
      tx_hash: alert.event.txHash,
      status: 'DETECTED',
      metadata: (alert.event as any).args ? { args: (alert.event as any).args } : undefined,
    };
  }

  async sendWithRetry(
    webhookUrl: string,
    secret: string,
    payload: WebhookPayload,
    backoffDelaysMs: number[] = [0, 100, 200, 400],
    headersOverride?: { timestamp?: string; nonce?: string }
  ): Promise<boolean> {
    const rawBody = JSON.stringify(payload);
    const timestamp = headersOverride?.timestamp ?? Date.now().toString();
    const nonce = headersOverride?.nonce ?? randomBytes(16).toString('hex');
    const signature = WebhookDispatcher.signPayload(secret, rawBody, timestamp, nonce);
    let lastError = 'Unknown error';

    for (let attempt = 0; attempt < backoffDelaysMs.length; attempt++) {
      if (backoffDelaysMs[attempt] > 0) {
        await sleep(backoffDelaysMs[attempt]);
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      try {
        const res = await fetch(webhookUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-auditx-signature': signature,
            'x-auditx-timestamp': timestamp,
            'x-auditx-nonce': nonce,
          },
          body: rawBody,
          signal: controller.signal,
        });

        if (res.ok) {
          return true;
        }
        lastError = `HTTP status ${res.status}`;
      } catch (err: any) {
        lastError = err.message || 'Fetch error';
      } finally {
        clearTimeout(timeout);
      }
    }

    // Terminal failure: write to DLQ
    this.recordDLQ({
      id: `dlq-${Date.now()}-${randomBytes(4).toString('hex')}`,
      webhookUrl,
      payload,
      attempts: backoffDelaysMs.length,
      lastError,
      failedAt: new Date().toISOString(),
    });

    return false;
  }

  getDLQ(): DLQItem[] {
    return [...this.dlq];
  }

  clearDLQ(): void {
    this.dlq = [];
    this.saveDLQ();
  }

  private loadDLQ(): void {
    try {
      if (fs.existsSync(this.dlqPath)) {
        this.dlq = JSON.parse(fs.readFileSync(this.dlqPath, 'utf8'));
      }
    } catch {
      this.dlq = [];
    }
  }

  private recordDLQ(item: DLQItem): void {
    this.dlq.push(item);
    this.saveDLQ();
  }

  private saveDLQ(): void {
    try {
      fs.mkdirSync(path.dirname(this.dlqPath), { recursive: true });
      fs.writeFileSync(this.dlqPath, JSON.stringify(this.dlq, null, 2), 'utf8');
    } catch {
      // ignore
    }
  }
}
