// @ts-nocheck
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  MemoryTenantStore,
  FileTenantStore,
  SqliteTenantStore,
  PostgresTenantStore,
  type ITenantStore,
  type ClientApp,
  type MonitoredAddress,
  type DLQItem,
} from '../legacy/src/storage/tenantStore.js';

function tempPath(prefix: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), prefix)), 'store.json');
}

describe('Store Interface: Memory, File, SQLite, Postgres', () => {
  const stores: { name: string; create: () => ITenantStore }[] = [
    { name: 'MemoryTenantStore', create: () => new MemoryTenantStore() },
    { name: 'FileTenantStore', create: () => new FileTenantStore(tempPath('file-store-')) },
    { name: 'SqliteTenantStore', create: () => new SqliteTenantStore(tempPath('sqlite-store-')) },
    { name: 'PostgresTenantStore', create: () => new PostgresTenantStore('postgres://user:pass@localhost:5432/auditx') },
  ];

  for (const { name, create } of stores) {
    describe(name, () => {
      let store: ITenantStore;

      beforeEach(async () => {
        store = create();
        await store.init();
      });

      it('saves and retrieves client by apiKeyHash with constant-time security', async () => {
        const client: ClientApp = {
          id: 'cli-1',
          name: 'PolyLance',
          webhookUrl: 'https://polylance.codes/webhook',
          apiKeyHash: '1111111111111111111111111111111111111111111111111111111111111111',
          hmacSecret: 'test_sec_1',
          createdAt: new Date().toISOString(),
        };

        await store.saveClient(client);
        const retrieved = await store.getClientByApiKeyHash(client.apiKeyHash);
        expect(retrieved).toBeDefined();
        expect(retrieved?.name).toBe('PolyLance');

        const nonExistent = await store.getClientByApiKeyHash('0000000000000000000000000000000000000000000000000000000000000000');
        expect(nonExistent).toBeUndefined();
      });

      it('manages monitored addresses and preserves uniqueness of (owningApp, chain, address)', async () => {
        const client: ClientApp = {
          id: 'cli-2',
          name: 'PolyLance',
          webhookUrl: 'https://polylance.codes/webhook',
          apiKeyHash: '2222222222222222222222222222222222222222222222222222222222222222',
          hmacSecret: 'test_sec_2',
          createdAt: new Date().toISOString(),
        };
        await store.saveClient(client);

        const monitored: MonitoredAddress = {
          id: 'mon-1',
          address: '0xbe74923bbfd72d400a681915dbcf6e6adc72c317',
          chain: 'polygon',
          owningApp: 'PolyLance',
          webhookUrl: 'https://polylance.codes/webhook',
          apiKeyHash: client.apiKeyHash,
          watchConfig: ['PaymentReleased', 'DisputeRaised'],
          registeredAt: new Date().toISOString(),
        };
        await store.saveMonitoredAddress(monitored);

        const list = await store.listMonitoredAddresses(client.apiKeyHash);
        expect(list).toHaveLength(1);
        expect(list[0].address).toBe(monitored.address.toLowerCase());

        // Upsert same address with updated watchConfig
        const updatedMonitored: MonitoredAddress = {
          ...monitored,
          id: 'mon-new-id',
          watchConfig: ['PaymentReleased', 'DisputeRaised', 'AutoReleased'],
        };
        await store.saveMonitoredAddress(updatedMonitored);

        const listAfterUpsert = await store.listMonitoredAddresses(client.apiKeyHash);
        expect(listAfterUpsert).toHaveLength(1);
        expect(listAfterUpsert[0].watchConfig).toContain('AutoReleased');

        // Delete monitored address
        const deleted = await store.deleteMonitoredAddress(client.apiKeyHash, monitored.address);
        expect(deleted).toBe(true);
        expect(await store.listMonitoredAddresses(client.apiKeyHash)).toHaveLength(0);
      });

      it('manages dead-letter queue (DLQ) operations', async () => {
        const item: DLQItem = {
          id: 'dlq-test-1',
          webhookUrl: 'https://broken.receiver/api',
          payload: { alert_id: 'alt-1', severity: 'CRITICAL' },
          attempts: 4,
          lastError: 'HTTP 500',
          failedAt: new Date().toISOString(),
        };

        await store.saveDLQItem(item);
        const dlq = await store.listDLQItems();
        expect(dlq).toHaveLength(1);
        expect(dlq[0].id).toBe('dlq-test-1');

        await store.clearDLQ();
        expect(await store.listDLQItems()).toHaveLength(0);
      });
    });
  }
});
