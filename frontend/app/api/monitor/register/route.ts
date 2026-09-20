import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// Multi-tenant registration in-memory store for Web API
const REGISTRATION_DB: Map<string, {
  id: string;
  address: string;
  chain: string;
  owning_app: string;
  webhook_url: string;
  watch_config: string[];
  registered_at: string;
}> = new Map();

function findTenantByApiKey(apiKey: string): { name: string; webhookUrl: string } | null {
  try {
    const registryPath = path.join(process.cwd(), 'auditx-tenant-registry.json');
    if (fs.existsSync(registryPath)) {
      const data = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      const hash = crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');
      const client = data.clients?.find((c: any) => c.apiKeyHash === hash);
      if (client) {
        return { name: client.name, webhookUrl: client.webhookUrl };
      }
    }
  } catch {}
  return null;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { api_key, address, chain, watch_config } = body;

    if (!api_key || !address) {
      return NextResponse.json(
        { error: 'Missing required parameters: api_key and address' },
        { status: 400 }
      );
    }

    const tenant = findTenantByApiKey(api_key);
    const normAddr = address.toLowerCase();
    const owningApp = tenant?.name || (api_key.includes('polylance') ? 'PolyLance' : 'client-app');
    const webhookUrl = tenant?.webhookUrl || body.webhook_url || `https://${owningApp.toLowerCase()}.app/api/webhooks/auditx-alert`;

    const record = {
      id: `mon-${Math.random().toString(36).substring(2, 11)}`,
      address: normAddr,
      chain: chain || 'polygon-mainnet',
      owning_app: owningApp,
      webhook_url: webhookUrl,
      watch_config: watch_config || ['reentrancy', 'flashloan', 'threat-address'],
      registered_at: new Date().toISOString(),
    };

    REGISTRATION_DB.set(normAddr, record);

    return NextResponse.json({
      status: 'SUCCESS',
      message: 'Address registered successfully for real-time SIEM monitoring',
      registration: record,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function GET() {
  const registrations = Array.from(REGISTRATION_DB.values());
  return NextResponse.json({
    total_monitored_addresses: registrations.length,
    registrations,
  });
}
