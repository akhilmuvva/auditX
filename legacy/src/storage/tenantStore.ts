import { createHash, timingSafeEqual } from 'crypto';
import fs from 'fs';
import path from 'path';

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

export interface ITenantStore {
  init(): Promise<void>;
  saveClient(client: ClientApp): Promise<void>;
  getClientByApiKeyHash(apiKeyHash: string): Promise<ClientApp | undefined>;
  listClients(): Promise<ClientApp[]>;
  saveMonitoredAddress(monitored: MonitoredAddress): Promise<void>;
  listMonitoredAddresses(apiKeyHash: string): Promise<MonitoredAddress[]>;
  listAllMonitoredAddresses(): Promise<MonitoredAddress[]>;
  deleteMonitoredAddress(apiKeyHash: string, idOrAddress: string): Promise<boolean>;
  lookupAddress(address: string): Promise<MonitoredAddress[]>;
  listClientsSync?(): ClientApp[];
  listAllMonitoredAddressesSync?(): MonitoredAddress[];
  saveClientSync?(client: ClientApp): void;
  saveMonitoredAddressSync?(monitored: MonitoredAddress): void;
  deleteMonitoredAddressSync?(apiKeyHash: string, idOrAddress: string): boolean;
}

export class MemoryTenantStore implements ITenantStore {
  private clients: Map<string, ClientApp> = new Map();
  private monitored: Map<string, MonitoredAddress> = new Map();

  async init(): Promise<void> {}

  saveClientSync(client: ClientApp): void {
    this.clients.set(client.apiKeyHash, { ...client });
  }

  async saveClient(client: ClientApp): Promise<void> {
    this.saveClientSync(client);
  }

  getClientByApiKeyHashSync(apiKeyHash: string): ClientApp | undefined {
    const target = Buffer.from(apiKeyHash, 'hex');
    for (const client of this.clients.values()) {
      const candidate = Buffer.from(client.apiKeyHash, 'hex');
      if (candidate.length === target.length && timingSafeEqual(candidate, target)) {
        return { ...client };
      }
    }
    return undefined;
  }

  async getClientByApiKeyHash(apiKeyHash: string): Promise<ClientApp | undefined> {
    return this.getClientByApiKeyHashSync(apiKeyHash);
  }

  listClientsSync(): ClientApp[] {
    return Array.from(this.clients.values()).map(c => ({ ...c }));
  }

  async listClients(): Promise<ClientApp[]> {
    return this.listClientsSync();
  }

  saveMonitoredAddressSync(monitored: MonitoredAddress): void {
    const normalizedAddr = monitored.address.toLowerCase();
    for (const [id, m] of this.monitored.entries()) {
      if (
        m.owningApp.toLowerCase() === monitored.owningApp.toLowerCase() &&
        m.chain.toLowerCase() === monitored.chain.toLowerCase() &&
        m.address.toLowerCase() === normalizedAddr
      ) {
        this.monitored.set(id, { ...monitored, id: m.id });
        return;
      }
    }
    this.monitored.set(monitored.id, { ...monitored, address: normalizedAddr });
  }

  async saveMonitoredAddress(monitored: MonitoredAddress): Promise<void> {
    this.saveMonitoredAddressSync(monitored);
  }

  listMonitoredAddressesSync(apiKeyHash: string): MonitoredAddress[] {
    const client = this.getClientByApiKeyHashSync(apiKeyHash);
    if (!client) return [];
    return Array.from(this.monitored.values())
      .filter(m => m.apiKeyHash === client.apiKeyHash)
      .map(m => ({ ...m }));
  }

  async listMonitoredAddresses(apiKeyHash: string): Promise<MonitoredAddress[]> {
    return this.listMonitoredAddressesSync(apiKeyHash);
  }

  listAllMonitoredAddressesSync(): MonitoredAddress[] {
    return Array.from(this.monitored.values()).map(m => ({ ...m }));
  }

  async listAllMonitoredAddresses(): Promise<MonitoredAddress[]> {
    return this.listAllMonitoredAddressesSync();
  }

  deleteMonitoredAddressSync(apiKeyHash: string, idOrAddress: string): boolean {
    const client = this.getClientByApiKeyHashSync(apiKeyHash);
    if (!client) return false;
    const target = idOrAddress.toLowerCase();
    for (const [id, m] of this.monitored.entries()) {
      if (m.apiKeyHash === client.apiKeyHash && (m.id === idOrAddress || m.address === target)) {
        this.monitored.delete(id);
        return true;
      }
    }
    return false;
  }

  async deleteMonitoredAddress(apiKeyHash: string, idOrAddress: string): Promise<boolean> {
    return this.deleteMonitoredAddressSync(apiKeyHash, idOrAddress);
  }

  lookupAddressSync(address: string): MonitoredAddress[] {
    const target = address.toLowerCase();
    return Array.from(this.monitored.values())
      .filter(m => m.address === target)
      .map(m => ({ ...m }));
  }

  async lookupAddress(address: string): Promise<MonitoredAddress[]> {
    return this.lookupAddressSync(address);
  }
}

export class FileTenantStore implements ITenantStore {
  private memory = new MemoryTenantStore();
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.loadSync();
  }

  loadSync(): void {
    if (!fs.existsSync(this.filePath)) return;
    try {
      const data = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      if (Array.isArray(data.clients)) {
        for (const client of data.clients) {
          this.memory.saveClientSync(client);
        }
      }
      if (Array.isArray(data.monitored)) {
        for (const mon of data.monitored) {
          this.memory.saveMonitoredAddressSync(mon);
        }
      }
    } catch {
      // ignore parse error on fresh start
    }
  }

  async init(): Promise<void> {
    this.loadSync();
  }

  private persistSync(): void {
    const clients = this.memory.listClientsSync();
    const monitored = this.memory.listAllMonitoredAddressesSync();
    const tempPath = `${this.filePath}.${process.pid}.tmp`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(tempPath, JSON.stringify({ clients, monitored }, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.renameSync(tempPath, this.filePath);
  }

  saveClientSync(client: ClientApp): void {
    this.memory.saveClientSync(client);
    this.persistSync();
  }

  async saveClient(client: ClientApp): Promise<void> {
    this.saveClientSync(client);
  }

  async getClientByApiKeyHash(apiKeyHash: string): Promise<ClientApp | undefined> {
    return this.memory.getClientByApiKeyHash(apiKeyHash);
  }

  listClientsSync(): ClientApp[] {
    return this.memory.listClientsSync();
  }

  async listClients(): Promise<ClientApp[]> {
    return this.listClientsSync();
  }

  saveMonitoredAddressSync(monitored: MonitoredAddress): void {
    this.memory.saveMonitoredAddressSync(monitored);
    this.persistSync();
  }

  async saveMonitoredAddress(monitored: MonitoredAddress): Promise<void> {
    this.saveMonitoredAddressSync(monitored);
  }

  listMonitoredAddressesSync(apiKeyHash: string): MonitoredAddress[] {
    return this.memory.listMonitoredAddressesSync(apiKeyHash);
  }

  async listMonitoredAddresses(apiKeyHash: string): Promise<MonitoredAddress[]> {
    return this.listMonitoredAddressesSync(apiKeyHash);
  }

  listAllMonitoredAddressesSync(): MonitoredAddress[] {
    return this.memory.listAllMonitoredAddressesSync();
  }

  async listAllMonitoredAddresses(): Promise<MonitoredAddress[]> {
    return this.listAllMonitoredAddressesSync();
  }

  deleteMonitoredAddressSync(apiKeyHash: string, idOrAddress: string): boolean {
    const deleted = this.memory.deleteMonitoredAddressSync(apiKeyHash, idOrAddress);
    if (deleted) this.persistSync();
    return deleted;
  }

  async deleteMonitoredAddress(apiKeyHash: string, idOrAddress: string): Promise<boolean> {
    return this.deleteMonitoredAddressSync(apiKeyHash, idOrAddress);
  }

  lookupAddressSync(address: string): MonitoredAddress[] {
    return this.memory.lookupAddressSync(address);
  }

  async lookupAddress(address: string): Promise<MonitoredAddress[]> {
    return this.lookupAddressSync(address);
  }
}

export class SqliteTenantStore implements ITenantStore {
  private fallback: FileTenantStore;
  private readonly dbPath: string;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.fallback = new FileTenantStore(dbPath.endsWith('.json') ? dbPath : `${dbPath}.json`);
  }

  async init(): Promise<void> {
    await this.fallback.init();
  }

  async saveClient(client: ClientApp): Promise<void> {
    await this.fallback.saveClient(client);
  }

  saveClientSync(client: ClientApp): void {
    this.fallback.saveClientSync(client);
  }

  async getClientByApiKeyHash(apiKeyHash: string): Promise<ClientApp | undefined> {
    return this.fallback.getClientByApiKeyHash(apiKeyHash);
  }

  async listClients(): Promise<ClientApp[]> {
    return this.fallback.listClients();
  }

  listClientsSync(): ClientApp[] {
    return this.fallback.listClientsSync();
  }

  async saveMonitoredAddress(monitored: MonitoredAddress): Promise<void> {
    await this.fallback.saveMonitoredAddress(monitored);
  }

  saveMonitoredAddressSync(monitored: MonitoredAddress): void {
    this.fallback.saveMonitoredAddressSync(monitored);
  }

  async listMonitoredAddresses(apiKeyHash: string): Promise<MonitoredAddress[]> {
    return this.fallback.listMonitoredAddresses(apiKeyHash);
  }

  listMonitoredAddressesSync(apiKeyHash: string): MonitoredAddress[] {
    return this.fallback.listMonitoredAddressesSync(apiKeyHash);
  }

  async listAllMonitoredAddresses(): Promise<MonitoredAddress[]> {
    return this.fallback.listAllMonitoredAddresses();
  }

  listAllMonitoredAddressesSync(): MonitoredAddress[] {
    return this.fallback.listAllMonitoredAddressesSync();
  }

  async deleteMonitoredAddress(apiKeyHash: string, idOrAddress: string): Promise<boolean> {
    return this.fallback.deleteMonitoredAddress(apiKeyHash, idOrAddress);
  }

  deleteMonitoredAddressSync(apiKeyHash: string, idOrAddress: string): boolean {
    return this.fallback.deleteMonitoredAddressSync(apiKeyHash, idOrAddress);
  }

  async lookupAddress(address: string): Promise<MonitoredAddress[]> {
    return this.fallback.lookupAddress(address);
  }

  lookupAddressSync(address: string): MonitoredAddress[] {
    return this.fallback.lookupAddressSync(address);
  }
}

export class PostgresTenantStore implements ITenantStore {
  private fallback: MemoryTenantStore;
  private readonly connectionString: string;

  constructor(connectionString: string) {
    this.connectionString = connectionString;
    this.fallback = new MemoryTenantStore();
  }

  async init(): Promise<void> {
    await this.fallback.init();
  }

  async saveClient(client: ClientApp): Promise<void> {
    await this.fallback.saveClient(client);
  }

  saveClientSync(client: ClientApp): void {
    this.fallback.saveClientSync(client);
  }

  async getClientByApiKeyHash(apiKeyHash: string): Promise<ClientApp | undefined> {
    return this.fallback.getClientByApiKeyHash(apiKeyHash);
  }

  async listClients(): Promise<ClientApp[]> {
    return this.fallback.listClients();
  }

  listClientsSync(): ClientApp[] {
    return this.fallback.listClientsSync();
  }

  async saveMonitoredAddress(monitored: MonitoredAddress): Promise<void> {
    await this.fallback.saveMonitoredAddress(monitored);
  }

  saveMonitoredAddressSync(monitored: MonitoredAddress): void {
    this.fallback.saveMonitoredAddressSync(monitored);
  }

  async listMonitoredAddresses(apiKeyHash: string): Promise<MonitoredAddress[]> {
    return this.fallback.listMonitoredAddresses(apiKeyHash);
  }

  listMonitoredAddressesSync(apiKeyHash: string): MonitoredAddress[] {
    return this.fallback.listMonitoredAddressesSync(apiKeyHash);
  }

  async listAllMonitoredAddresses(): Promise<MonitoredAddress[]> {
    return this.fallback.listAllMonitoredAddresses();
  }

  listAllMonitoredAddressesSync(): MonitoredAddress[] {
    return this.fallback.listAllMonitoredAddressesSync();
  }

  async deleteMonitoredAddress(apiKeyHash: string, idOrAddress: string): Promise<boolean> {
    return this.fallback.deleteMonitoredAddress(apiKeyHash, idOrAddress);
  }

  deleteMonitoredAddressSync(apiKeyHash: string, idOrAddress: string): boolean {
    return this.fallback.deleteMonitoredAddressSync(apiKeyHash, idOrAddress);
  }

  async lookupAddress(address: string): Promise<MonitoredAddress[]> {
    return this.fallback.lookupAddress(address);
  }

  lookupAddressSync(address: string): MonitoredAddress[] {
    return this.fallback.lookupAddressSync(address);
  }
}
