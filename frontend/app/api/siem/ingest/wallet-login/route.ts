import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

/**
 * 410 Stub - Frontend uses static export (`output: "export"` for GitHub Pages).
 * The authoritative SIWE wallet login assessment API is hosted directly on the Rust auditx-identity-http service (:8088/assess-wallet-login).
 */
export async function POST() {
  return NextResponse.json(
    {
      error: 'Next.js dynamic API routes are deprecated on static export. Connect directly to auditx-identity-http at /assess-wallet-login.',
      status: 410,
    },
    { status: 410 }
  );
}

export async function GET() {
  return NextResponse.json(
    {
      error: 'Endpoint migrated to auditx-identity-http (:8088).',
      status: 410,
    },
    { status: 410 }
  );
}
