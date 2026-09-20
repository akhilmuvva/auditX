import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

/**
 * 410 Stub - Frontend uses static export (`output: "export"` for GitHub Pages).
 * The authoritative SIEM engine & alert stream API is hosted on the Express server (`legacy/src/server.ts`).
 */
export async function GET() {
  return NextResponse.json(
    {
      error: 'Next.js dynamic API routes are deprecated on static export. Connect directly to AuditX Express server at /api/siem/alerts or WebSocket /ws/siem.',
      status: 410,
    },
    { status: 410 }
  );
}

export async function POST() {
  return NextResponse.json(
    {
      error: 'Endpoint migrated to Express server (/api/siem/ingest).',
      status: 410,
    },
    { status: 410 }
  );
}
