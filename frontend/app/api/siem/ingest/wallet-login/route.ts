import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

const IDENTITY_SERVICE_URL = process.env.IDENTITY_SERVICE_URL || 'http://127.0.0.1:8088/assess-wallet-login';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { message, signature, device_fingerprint, geo_hint } = body;

    if (!message || !signature) {
      return NextResponse.json(
        { error: 'Missing required parameters: message and signature' },
        { status: 400 }
      );
    }

    // Extract client IP (or fallback to localhost)
    const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';

    const payload = {
      message,
      signature,
      ip_address: ipAddress,
      device_fingerprint: device_fingerprint || 'browser-standard-fp',
      geo_hint: geo_hint || null,
    };

    // Forward to Rust auditx-identity-http service with 280ms timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 280);

    try {
      const rustResponse = await fetch(IDENTITY_SERVICE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (rustResponse.ok) {
        const assessment = await rustResponse.json();
        return NextResponse.json(assessment);
      } else {
        const errorData = await rustResponse.json().catch(() => ({}));
        return NextResponse.json(
          { error: errorData.error || 'Rust Identity Service error', status: 'ERROR' },
          { status: rustResponse.status }
        );
      }
    } catch (networkError: any) {
      clearTimeout(timeoutId);

      // SECURITY-DECISION:
      // If the Rust Identity service is unreachable or times out, fail open with StepUp
      // (trust_score: 50, StepUp challenge) rather than hard Deny (which locks out users
      // during network blips) or silent Allow (which bypasses security checks).
      return NextResponse.json({
        wallet_addr: '0x0000000000000000000000000000000000000000',
        trust_score: 50,
        risk_flags: [
          {
            type: 'ServiceFallback',
            details: 'Identity service temporarily unreachable - requiring StepUp verification',
          },
        ],
        decision: 'STEP_UP',
        assessed_at: new Date().toISOString(),
        _fail_open_fallback: true,
      });
    }
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    status: 'READY',
    service: 'auditx-identity-proxy',
    endpoint: '/api/siem/ingest/wallet-login',
  });
}
