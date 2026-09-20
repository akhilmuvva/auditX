import { createHmac, timingSafeEqual } from 'crypto';
import fs from 'fs';
import path from 'path';
import { setTimeout as sleep } from 'timers/promises';
import type { Alert } from '../siem/types.js';
import type { MonitoredAddress, ClientApp } from '../storage/tenantStore.js';

export interface WebhookPayload {
  alert_id: string;
  contract_address: string;
  owning_app: string;
  chain: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  timestamp: number;
  event_type: string;
  tx_hash: string;
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

  static signPayload(secret: string, payload: string): string {
    return `sha256=${createHmac('sha256', secret).update(payload, 'utf8').digest('hex')}`;
  }

  static verifySignature(secret: string, payload: string, signatureHeader: string): boolean {
    if (!signatureHeader || !secret) return false;
    const computed = WebhookDispatcher.signPayload(secret, payload);
    const left = Buffer.from(computed, 'utf8');
    const right = Buffer.from(signatureHeader, 'utf8');
    return left.length === right.length && timingSafeEqual(left, right);
  }

  createPayload(monitored: MonitoredAddress, alert: Alert): WebhookPayload {
    return {
      alert_id: alert.id,
      contract_address: alert.event.contractAddress.toLowerCase(),
      owning_app: monitored.owningApp,
      chain: monitored.chain,
      severity: alert.severity,
      category: alert.event.category,
      title: alert.title,
      description: alert.description,
      timestamp: alert.timestamp,
      event_type: alert.event.eventName,
      tx_hash: alert.event.txHash,
    };
  }

  async sendWithRetry(
    webhookUrl: string,
    secret: string,
    payload: WebhookPayload,
    backoffDelaysMs: number[] = [0, 100, 200, 400] // Fast backoff for testing, configurable for production
  ): Promise<boolean> {
    const rawBody = JSON.stringify(payload);
    const signature = WebhookDispatcher.signPayload(secret, rawBody);
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
      id: `dlq-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
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
