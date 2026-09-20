/**
 * Copied from PolyLance Chat Service: D:\Polylance\polylance-chat-service\src\auditx\verifyWebhook.ts
 * Source: PolyLance Production SIEM Webhook Receiver
 * Used for cross-repo contract reconciliation testing.
 */

import crypto from "crypto";

export interface WebhookVerificationResult {
  valid: boolean;
  code?: number;
  error?: string;
}

const memoryNonceCache = new Map<string, number>();

export function validateTimestampFreshness(timestamp: string | number): boolean {
  let tsMs = Number(timestamp);
  if (isNaN(tsMs)) {
    tsMs = Date.parse(String(timestamp));
  } else if (tsMs < 1e11) {
    tsMs = tsMs * 1000;
  }

  if (isNaN(tsMs)) {
    return false;
  }

  const delta = Math.abs(Date.now() - tsMs);
  return delta <= 5 * 60 * 1000; // 5 minutes max skew
}

export async function verifyAndRecordNonce(nonce: string): Promise<{ ok: boolean; error?: string }> {
  if (!nonce || typeof nonce !== "string" || nonce.trim().length === 0) {
    return { ok: false, error: "Missing or invalid nonce format" };
  }

  const now = Date.now();
  const ttlSeconds = 600; // 10 minutes

  const existingExpiry = memoryNonceCache.get(nonce);
  if (existingExpiry && existingExpiry > now) {
    return { ok: false, error: "Invalid or replayed nonce (Memory)" };
  }

  if (memoryNonceCache.size > 5000) {
    for (const [k, exp] of memoryNonceCache.entries()) {
      if (exp <= now) memoryNonceCache.delete(k);
    }
  }
  memoryNonceCache.set(nonce, now + ttlSeconds * 1000);
  return { ok: true };
}

export async function verifyAuditXWebhook(
  rawBody: string,
  signatureHeader: string | null | undefined,
  timestampHeader: string | null | undefined,
  nonceHeader: string | null | undefined,
  secretOverride?: string
): Promise<WebhookVerificationResult> {
  const secret = secretOverride || process.env.AUDITX_WEBHOOK_SECRET;
  if (!secret) {
    return { valid: false, code: 500, error: "Server configuration error: webhook secret not set" };
  }

  if (!signatureHeader || typeof signatureHeader !== "string") {
    return { valid: false, code: 401, error: "Missing x-auditx-signature header" };
  }

  if (!timestampHeader) {
    return { valid: false, code: 400, error: "Missing x-auditx-timestamp header" };
  }

  if (!nonceHeader) {
    return { valid: false, code: 400, error: "Missing x-auditx-nonce header" };
  }

  const cleanSig = signatureHeader.startsWith("0x") ? signatureHeader.slice(2) : signatureHeader;
  const isHex64 = /^[0-9a-fA-F]{64}$/.test(cleanSig);
  if (!isHex64) {
    return { valid: false, code: 401, error: "Invalid signature format: expected 64 hex characters" };
  }

  if (!validateTimestampFreshness(timestampHeader)) {
    return { valid: false, code: 401, error: "Timestamp expired or out of bounds (max 5 minutes window)" };
  }

  const nonceResult = await verifyAndRecordNonce(nonceHeader);
  if (!nonceResult.ok) {
    return { valid: false, code: 401, error: nonceResult.error || "Invalid or replayed nonce" };
  }

  const messageToSign = `${timestampHeader}.${nonceHeader}.${rawBody}`;
  const expectedHmac = crypto
    .createHmac("sha256", secret)
    .update(messageToSign)
    .digest("hex");

  const expectedBuf = Buffer.from(expectedHmac, "hex");
  const receivedBuf = Buffer.from(cleanSig, "hex");

  if (expectedBuf.length !== 32 || receivedBuf.length !== 32 || expectedBuf.length !== receivedBuf.length) {
    return { valid: false, code: 401, error: "Invalid signature buffer length" };
  }

  if (!crypto.timingSafeEqual(expectedBuf, receivedBuf)) {
    return { valid: false, code: 401, error: "Invalid signature digest mismatch" };
  }

  return { valid: true };
}
