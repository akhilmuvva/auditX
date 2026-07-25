import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

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

    const normAddr = address.toLowerCase();
    const owningApp = api_key.includes('polylance') ? 'polylance' : 'client-app';
    const webhookUrl = body.webhook_url || `https://${owningApp}.app/api/webhooks/auditx-alert`;

    const record = {
      id: `mon-${Math.random().toString(36).substring(2, 11)}`,
      address: normAddr,
      chain: chain || 'polygon-amoy',
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
