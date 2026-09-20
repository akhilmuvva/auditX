# PolyLance & AuditX SIEM Webhook Contract Specification

> **Version**: 1.0.0  
> **Protocol**: HTTPS POST with HMAC SHA-256 Signature over `timestamp.nonce.body`  
> **Status**: APPROVED & RECONCILED WITH POLYLANCE PRODUCTION RECEIVER  

---

## 1. Webhook Payload Schema (`AuditXAlertPayload`)

The payload emitted by AuditX SIEM and accepted by PolyLance webhook receiver:

```json
{
  "schema_version": "1.0.0",
  "alert_id": "ALT-171829001928-9102",
  "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
  "owning_app": "PolyLance",
  "chain": "137",
  "severity": "CRITICAL",
  "category": "SECURITY",
  "title": "Unauthorized Dispute Resolution Attempt",
  "description": "Caller not designated arbitrator attempted to resolve escrow dispute",
  "detected_at": "2026-09-21T00:00:00.000Z",
  "event_type": "DisputeResolved",
  "tx_hash": "0x4f8a12bc90de45f678901234567890abcdef1234567890abcdef1234567890ab",
  "status": "DETECTED",
  "metadata": {}
}
```

### Required Payload Fields:
- `schema_version`: String, e.g. `"1.0.0"`
- `alert_id`: Unique identifier string for deduplication (e.g. `"ALT-..."`)
- `contract_address`: Hex string (lowercase 0x address)
- `severity`: Uppercase string enum (`"INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"`)
- `description`: Human-readable threat explanation
- `detected_at`: ISO 8601 UTC timestamp string
- `category`: String category (e.g. `"SECURITY"`, `"GOVERNANCE"`, `"ESCROW"`)
- `title`: Short summary title
- `chain`: Network identifier string (e.g. `"137"`, `"80002"`, `"polygon"`)
- `tx_hash`: Transaction hash hex string
- `event_type`: Event name string

---

## 2. Authentication & Verification

Each webhook dispatch contains three required HTTP headers:
```http
x-auditx-signature: <64-character lowercase hex digest>
x-auditx-timestamp: <epoch milliseconds or ISO timestamp>
x-auditx-nonce: <unique cryptographic random nonce string>
```

### Signature Computation:
```
messageToSign = `${x-auditx-timestamp}.${x-auditx-nonce}.${raw_utf8_json_body}`
signature = HMAC_SHA256(AUDITX_WEBHOOK_SECRET, messageToSign).digest('hex')
```

### Receiver Security Guarantees:
1. **Hex Length Check**: `x-auditx-signature` must be exactly 64 hex characters (32 bytes).
2. **Timing-Safe Equality**: Constant-time byte-by-byte comparison (`timingSafeEqual`) prevents timing attacks.
3. **Timestamp Skew Window**: Timestamps older than 5 minutes (300 seconds) are rejected.
4. **Replay Defense (Nonce)**: Nonce tracked in Upstash Redis / DB / Memory for 10 minutes (600s TTL). Replayed nonces are rejected. Fail-closed on cache error.

---

## 3. Retries & Dead-Letter Queue (DLQ)

- **Attempt 1**: Immediate
- **Attempt 2**: 100ms / 1m backoff
- **Attempt 3**: 200ms / 2m backoff
- **Attempt 4**: 400ms / 5m backoff
- **Terminal Failure**: Stored into DLQ (`reports-cache/webhook-dlq.json`) for manual triage / alert forwarding.

---

## 4. Test Vectors

### Vector 1:
- **Secret**: `TEST_MOCK_SECRET_KEY_AUDITX_999`
- **Timestamp**: `1700000000000`
- **Nonce**: `nonce_test_vector_abc123`
- **Payload**: `{"schema_version":"1.0.0","alert_id":"test-vec-1","contract_address":"0x00000000000000000000000000000000000000aa","chain":"137","severity":"CRITICAL","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert vector","detected_at":"2023-11-14T22:13:20.000Z","tx_hash":"0xtest","event_type":"DisputeResolved","status":"DETECTED"}`
- **Message to Sign**: `1700000000000.nonce_test_vector_abc123.{"schema_version":"1.0.0","alert_id":"test-vec-1","contract_address":"0x00000000000000000000000000000000000000aa","chain":"137","severity":"CRITICAL","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert vector","detected_at":"2023-11-14T22:13:20.000Z","tx_hash":"0xtest","event_type":"DisputeResolved","status":"DETECTED"}`
- **Expected `x-auditx-signature`**: `4da428c8bb7ba4e17d30805129e26a27bde0ad8cbbbf198857e174d083711cd4`
