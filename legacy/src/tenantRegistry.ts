import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import fs from 'fs';
import path from 'path';
import { setTimeout as sleep } from 'timers/promises';
import type { Alert, ChainEvent } from './siem/types.js';

export interface ClientApp {
  id: string;
  name: string;
  webhookUrl: string;
  apiKeyHash: string;
  hmacSecret: string;
  createdAt: string;
}

export interface MonitoredAddress {
  id: string;
  address: string;
  chain: string;
  owningApp: string;
  webhookUrl: string;
  apiKeyHash: string;
  watchConfig: string[];
  registeredAt: string;
}

interface RegistryFile {
  clients: ClientApp[];
  monitored: MonitoredAddress[];
}

export interface IssuedClientCredentials {
  client: ClientApp;
  apiKey: string;
  hmacSecret: string;
}

const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const MAX_WATCH_CONFIG = 32;

export class TenantRegistry {
  private readonly filePath: string;
  private state: RegistryFile;

  constructor(filePath = process.env.AUDITX_REGISTRY_PATH || path.join(process.cwd(), 'auditx-tenant-registry.json')) {
    this.filePath = filePath;
    this.state = this.load();
  }

  static hashApiKey(apiKey: string): string {
    return createHash('sha256').update(apiKey, 'utf8').digest('hex');
  }

  static signPayload(secret: string, payload: string): string {
    return `sha256=${createHmac('sha256', secret).update(payload, 'utf8').digest('hex')}`;
  }

  authenticate(apiKey: string): ClientApp | undefined {
    const hash = TenantRegistry.hashApiKey(apiKey);
    return this.state.clients.find((client) => {
      const left = Buffer.from(client.apiKeyHash, 'hex');
      const right = Buffer.from(hash, 'hex');
      return left.length === right.length && timingSafeEqual(left, right);
    });
  }

  registerClient(name: string, webhookUrl: string): IssuedClientCredentials {
    if (!name.trim() || name.length > 128) throw new Error('Client name is invalid');
    this.validateWebhookUrl(webhookUrl);

    const apiKey = `ax_live_${randomBytes(24).toString('hex')}`;
    const hmacSecret = `sec_${randomBytes(32).toString('hex')}`;
    const client: ClientApp = {
      id: `client-${randomBytes(12).toString('hex')}`,
      name: name.trim(),
      webhookUrl,
      apiKeyHash: TenantRegistry.hashApiKey(apiKey),
      hmacSecret,
      createdAt: new Date().toISOString(),
    };
    this.state.clients.push(client);
    this.persist();
    return { client, apiKey, hmacSecret };
  }

  registerMonitoredAddress(
    apiKey: string,
    address: string,
    chain: string,
    watchConfig: string[],
  ): MonitoredAddress {
    const client = this.authenticate(apiKey);
    if (!client) throw new Error('Invalid API key');
    if (!ADDRESS_PATTERN.test(address)) throw new Error('Invalid monitored address');
    if (!chain.trim() || chain.length > 64) throw new Error('Invalid chain');
    if (!Array.isArray(watchConfig) || watchConfig.length === 0 || watchConfig.length > MAX_WATCH_CONFIG
      || watchConfig.some((eventType) => typeof eventType !== 'string' || !/^[a-z0-9-]{1,64}$/.test(eventType))) {
      throw new Error('Invalid watch configuration');
    }

    const monitored: MonitoredAddress = {
      id: `mon-${randomBytes(12).toString('hex')}`,
      address: address.toLowerCase(),
      chain,
      owningApp: client.name,
      webhookUrl: client.webhookUrl,
      apiKeyHash: client.apiKeyHash,
      watchConfig: [...watchConfig],
      registeredAt: new Date().toISOString(),
    };
    this.state.monitored.push(monitored);
    this.persist();
    return monitored;
  }

  lookupAddress(address: string): MonitoredAddress[] {
    return this.state.monitored.filter((monitored) => monitored.address === address.toLowerCase());
  }

  async dispatchAlert(monitored: MonitoredAddress, alert: Alert): Promise<void> {
    const client = this.state.clients.find((candidate) => candidate.apiKeyHash === monitored.apiKeyHash);
    if (!client) throw new Error(`No client credentials found for ${monitored.owningApp}`);

    const payload = JSON.stringify({
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
    });
    const signature = TenantRegistry.signPayload(client.hmacSecret, payload);
    let lastError = 'Webhook request failed';

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5_000);
      try {
        const response = await fetch(monitored.webhookUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-auditx-signature': signature,
          },
          body: payload,
          signal: controller.signal,
        });
        if (response.ok) return;
        lastError = `Webhook returned HTTP ${response.status}`;
      } catch (error) {
        lastError = error instanceof Error ? error.message : 'Webhook request failed';
      } finally {
        clearTimeout(timeout);
      }
      if (attempt < 2) await sleep(100 * (attempt + 1));
    }
    throw new Error(lastError);
  }

  private load(): RegistryFile {
    if (!fs.existsSync(this.filePath)) return { clients: [], monitored: [] };
    const parsed: unknown = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    if (!parsed || typeof parsed !== 'object') throw new Error('Invalid tenant registry');
    const value = parsed as Partial<RegistryFile>;
    if (!Array.isArray(value.clients) || !Array.isArray(value.monitored)) {
      throw new Error('Invalid tenant registry');
    }
    return { clients: value.clients as ClientApp[], monitored: value.monitored as MonitoredAddress[] };
  }

  private persist(): void {
    const tempPath = `${this.filePath}.${process.pid}.tmp`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(tempPath, JSON.stringify(this.state), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tempPath, this.filePath);
  }

  private validateWebhookUrl(webhookUrl: string): void {
    const parsed = new URL(webhookUrl);
    if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
      throw new Error('Webhook URL must use HTTPS');
    }
  }
}

export function bootstrapPolyLance(registry: TenantRegistry): void {
  const address = process.env.POLYLANCE_ESCROW_ADDRESS;
  const webhookUrl = process.env.POLYLANCE_WEBHOOK_URL;
  const apiKey = process.env.POLYLANCE_API_KEY;
  if (!address && !webhookUrl && !apiKey) return;
  if (!address || !webhookUrl || !apiKey) {
    throw new Error('PolyLance bootstrap requires POLYLANCE_ESCROW_ADDRESS, POLYLANCE_WEBHOOK_URL, and POLYLANCE_API_KEY');
  }
  if (!ADDRESS_PATTERN.test(address)) throw new Error('POLYLANCE_ESCROW_ADDRESS is invalid');
  if (!registry.authenticate(apiKey)) throw new Error('POLYLANCE_API_KEY is not registered');
  if (!registry.lookupAddress(address).some((monitored) => monitored.owningApp === 'PolyLance')) {
    registry.registerMonitoredAddress(apiKey, address, process.env.POLYLANCE_ESCROW_CHAIN || 'polygon', [
      'fund-release',
      'dispute-trigger',
    ]);
  }
}

export function eventMatchesMonitoredAddress(event: ChainEvent, monitored: MonitoredAddress): boolean {
  return event.contractAddress.toLowerCase() === monitored.address
    && (monitored.watchConfig.length === 0 || monitored.watchConfig.includes(event.eventName.toLowerCase()));
}
