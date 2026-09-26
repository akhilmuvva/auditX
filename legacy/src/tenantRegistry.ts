import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { EventEmitter } from 'events';
import path from 'path';
import { setTimeout as sleep } from 'timers/promises';
import type { Alert, ChainEvent } from './siem/types.js';
import {
  type ClientApp,
  type MonitoredAddress,
  type ITenantStore,
  FileTenantStore,
  MemoryTenantStore,
  SqliteTenantStore,
  PostgresTenantStore,
} from './storage/tenantStore.js';

export { ClientApp, MonitoredAddress, ITenantStore, FileTenantStore, MemoryTenantStore, SqliteTenantStore, PostgresTenantStore };

export interface IssuedClientCredentials {
  client: ClientApp;
  apiKey: string;
  hmacSecret: string;
}

const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const MAX_WATCH_CONFIG = 32;

export class TenantRegistry extends EventEmitter {
  private store: ITenantStore;
  private syncCache: { clients: ClientApp[]; monitored: MonitoredAddress[] } = {
    clients: [],
    monitored: [],
  };

  constructor(storeOrPath?: ITenantStore | string) {
    super();
    if (!storeOrPath) {
      const defaultPath = process.env.AUDITX_REGISTRY_PATH || path.join(process.cwd(), 'auditx-tenant-registry.json');
      this.store = new FileTenantStore(defaultPath);
    } else if (typeof storeOrPath === 'string') {
      if (storeOrPath.startsWith('postgres://') || storeOrPath.startsWith('postgresql://')) {
        this.store = new PostgresTenantStore(storeOrPath);
      } else if (storeOrPath.endsWith('.db') || storeOrPath.endsWith('.sqlite')) {
        this.store = new SqliteTenantStore(storeOrPath);
      } else {
        this.store = new FileTenantStore(storeOrPath);
      }
    } else {
      this.store = storeOrPath;
    }
    this.initSync();
  }

  private loadEnvAllowlist(): void {
    const rawKeys = process.env.AUDITX_ADMIN_API_KEYS;
    if (rawKeys) {
      const keys = rawKeys.split(',').map((k) => k.trim()).filter(Boolean);
      for (const key of keys) {
        const hash = TenantRegistry.hashApiKey(key);
        if (!this.syncCache.clients.some((c) => c.apiKeyHash === hash)) {
          this.syncCache.clients.push({
            id: `admin-${hash.slice(0, 8)}`,
            name: 'PolyLance_Admin',
            webhookUrl: process.env.POLYLANCE_WEBHOOK_URL || 'https://polylance.codes/api/webhooks/auditx-alert',
            apiKeyHash: hash,
            hmacSecret: process.env.AUDITX_WEBHOOK_SECRET || 'sec_static_admin_polylance',
            createdAt: new Date().toISOString(),
          });
        }
      }
    }
  }

  private initSync(): void {
    if (this.store.listClientsSync && this.store.listAllMonitoredAddressesSync) {
      this.syncCache = {
        clients: this.store.listClientsSync(),
        monitored: this.store.listAllMonitoredAddressesSync(),
      };
    }
    this.loadEnvAllowlist();
  }

  async refreshCache(): Promise<void> {
    const clients = await this.store.listClients();
    const monitored = await this.store.listAllMonitoredAddresses();
    this.syncCache = { clients, monitored };
    this.loadEnvAllowlist();
    this.emit('change', this.syncCache);
    this.emit('monitored-changed', monitored);
  }

  static hashApiKey(apiKey: string): string {
    return createHash('sha256').update(apiKey, 'utf8').digest('hex');
  }

  static signPayload(secret: string, payload: string): string {
    return `sha256=${createHmac('sha256', secret).update(payload, 'utf8').digest('hex')}`;
  }

  authenticate(apiKey: string): ClientApp | undefined {
    if (!apiKey || typeof apiKey !== 'string') return undefined;
    const hash = TenantRegistry.hashApiKey(apiKey);
    const target = Buffer.from(hash, 'hex');
    return this.syncCache.clients.find((client) => {
      const candidate = Buffer.from(client.apiKeyHash, 'hex');
      return candidate.length === target.length && timingSafeEqual(candidate, target);
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

    this.syncCache.clients.push(client);
    if (this.store.saveClientSync) {
      this.store.saveClientSync(client);
    } else {
      this.store.saveClient(client).catch(console.error);
    }
    this.emit('client-registered', client);
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
    if (
      !Array.isArray(watchConfig) ||
      watchConfig.length === 0 ||
      watchConfig.length > MAX_WATCH_CONFIG ||
      watchConfig.some((eventType) => typeof eventType !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(eventType))
    ) {
      throw new Error('Invalid watch configuration');
    }

    const normalizedAddr = address.toLowerCase();

    // Check unique (owningApp, chain, address)
    const existingIndex = this.syncCache.monitored.findIndex(
      (m) =>
        m.owningApp.toLowerCase() === client.name.toLowerCase() &&
        m.chain.toLowerCase() === chain.toLowerCase() &&
        m.address.toLowerCase() === normalizedAddr
    );

    if (existingIndex !== -1) {
      const existing = this.syncCache.monitored[existingIndex];
      existing.watchConfig = [...watchConfig];
      existing.webhookUrl = client.webhookUrl;
      if (this.store.saveMonitoredAddressSync) {
        this.store.saveMonitoredAddressSync(existing);
      } else {
        this.store.saveMonitoredAddress(existing).catch(console.error);
      }
      this.emit('monitored-changed', this.syncCache.monitored);
      return existing;
    }

    const monitored: MonitoredAddress = {
      id: `mon-${randomBytes(12).toString('hex')}`,
      address: normalizedAddr,
      chain,
      owningApp: client.name,
      webhookUrl: client.webhookUrl,
      apiKeyHash: client.apiKeyHash,
      watchConfig: [...watchConfig],
      registeredAt: new Date().toISOString(),
    };

    this.syncCache.monitored.push(monitored);
    if (this.store.saveMonitoredAddressSync) {
      this.store.saveMonitoredAddressSync(monitored);
    } else {
      this.store.saveMonitoredAddress(monitored).catch(console.error);
    }
    this.emit('monitored-registered', monitored);
    this.emit('monitored-changed', this.syncCache.monitored);
    return monitored;
  }

  listMonitoredAddresses(apiKey: string): MonitoredAddress[] {
    const client = this.authenticate(apiKey);
    if (!client) throw new Error('Invalid API key');
    return this.syncCache.monitored.filter((m) => m.apiKeyHash === client.apiKeyHash);
  }

  listAllMonitoredAddresses(): MonitoredAddress[] {
    return [...this.syncCache.monitored];
  }

  deregisterMonitoredAddress(apiKey: string, idOrAddress: string): boolean {
    const client = this.authenticate(apiKey);
    if (!client) throw new Error('Invalid API key');
    const target = idOrAddress.toLowerCase();
    const index = this.syncCache.monitored.findIndex(
      (m) => m.apiKeyHash === client.apiKeyHash && (m.id === idOrAddress || m.address === target),
    );
    if (index === -1) return false;
    this.syncCache.monitored.splice(index, 1);
    if (this.store.deleteMonitoredAddressSync) {
      this.store.deleteMonitoredAddressSync(client.apiKeyHash, target);
    } else {
      this.store.deleteMonitoredAddress(client.apiKeyHash, target).catch(console.error);
    }
    this.emit('monitored-deregistered', { apiKeyHash: client.apiKeyHash, target });
    this.emit('monitored-changed', this.syncCache.monitored);
    return true;
  }

  lookupAddress(address: string): MonitoredAddress[] {
    const target = address.toLowerCase();
    return this.syncCache.monitored.filter((monitored) => monitored.address === target);
  }

  async dispatchAlert(monitored: MonitoredAddress, alert: Alert): Promise<void> {
    const client = this.syncCache.clients.find((candidate) => candidate.apiKeyHash === monitored.apiKeyHash);
    if (!client) throw new Error(`No client credentials found for ${monitored.owningApp}`);

    const payload = JSON.stringify({
      schema_version: '1.0.0',
      alert_id: alert.id,
      contract_address: alert.event.contractAddress.toLowerCase(),
      owning_app: monitored.owningApp,
      chain: monitored.chain,
      severity: alert.severity,
      category: alert.event.category,
      title: alert.title,
      description: alert.description,
      detected_at: new Date(alert.timestamp || Date.now()).toISOString(),
      timestamp: alert.timestamp,
      event_type: alert.event.eventName,
      tx_hash: alert.event.txHash,
      status: 'DETECTED',
    });
    const timestamp = Date.now().toString();
    const nonce = randomBytes(16).toString('hex');
    const messageToSign = `${timestamp}.${nonce}.${payload}`;
    const signature = createHmac('sha256', client.hmacSecret).update(messageToSign, 'utf8').digest('hex');
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
            'x-auditx-timestamp': timestamp,
            'x-auditx-nonce': nonce,
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

  private validateWebhookUrl(webhookUrl: string): void {
    const parsed = new URL(webhookUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new Error('Webhook URL must use HTTPS');
    }
    const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1';
    if (process.env.NODE_ENV === 'production') {
      if (parsed.protocol !== 'https:') {
        throw new Error('Webhook URL must use HTTPS in production');
      }
      if (isLocalhost || this.isPrivateIp(parsed.hostname)) {
        throw new Error('Webhook URL cannot target private or loopback addresses in production');
      }
    } else {
      if (parsed.protocol !== 'https:' && !isLocalhost) {
        throw new Error('Webhook URL must use HTTPS unless targeting localhost for testing');
      }
    }
  }

  private isPrivateIp(host: string): boolean {
    const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
      const b0 = parseInt(ipv4Match[1], 10);
      const b1 = parseInt(ipv4Match[2], 10);
      if (b0 === 10) return true;
      if (b0 === 127) return true;
      if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
      if (b0 === 192 && b1 === 168) return true;
      if (b0 === 169 && b1 === 254) return true;
      if (b0 === 0) return true;
    }
    return host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal');
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
  return event.contractAddress.toLowerCase() === monitored.address.toLowerCase()
    && (monitored.watchConfig.length === 0 || monitored.watchConfig.includes(event.eventName.toLowerCase()));
}
