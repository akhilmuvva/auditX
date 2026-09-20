import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

/**
 * 410 Stub - Frontend uses static export (`output: "export"` for GitHub Pages).
 * The authoritative registration and monitor API is hosted on the Express server (`legacy/src/server.ts`).
 */
export async function POST() {
  return NextResponse.json(
    {
      error: 'Next.js dynamic API routes are deprecated on static export. Please point requests directly to the AuditX Express API endpoint at /api/monitor/register or /api/siem/monitored-addresses.',
      status: 410,
    },
    { status: 410 }
  );
}

export async function GET() {
  return NextResponse.json(
    {
      error: 'Endpoint migrated to Express server (/api/siem/monitored-addresses).',
      status: 410,
    },
    { status: 410 }
  );
}
