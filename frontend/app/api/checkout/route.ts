import { NextResponse } from 'next/server';
import crypto from 'crypto';

export async function POST(request: Request) {
  try {
    const text = await request.text();
    
    // Verify Lemon Squeezy webhook signature
    const signature = request.headers.get('x-signature') || '';
    const secret = process.env.LEMON_SQUEEZY_WEBHOOK_SECRET || 'dummy_webhook_secret';
    
    const hmac = crypto.createHmac('sha256', secret);
    const digest = hmac.update(text).digest('hex');
    
    if (signature !== digest) {
      return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 });
    }

    const payload = JSON.parse(text);
    const eventName = payload.meta?.event_name;
    const userId = payload.data?.attributes?.custom_data?.user_id;

    if (eventName === 'subscription_created' || eventName === 'subscription_payment_success') {
      console.log(`Upgrading user ${userId} to Pro Tier via Lemon Squeezy subscription`);
      // Update database user tier here (e.g. prisma.user.update({ where: { id: userId }, data: { tier: 'PRO' } }))
    }

    return NextResponse.json({ received: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
