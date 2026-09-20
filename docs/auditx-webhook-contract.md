# PolyLance & AuditX SIEM Webhook Contract Specification

> **Version**: 1.0.0  
> **Protocol**: HTTPS POST with HMAC SHA-256 Signature  
> **Status**: APPROVED  

---

## 1. Webhook Payload Schema

```json
{
  "alert_id": "ALT-171829001928-9102",
  "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
  "owning_app": "PolyLance",
  "chain": "polygon",
  "severity": "CRITICAL",
  "category": "GOVERNANCE",
  "title": "Unauthorized Milestone Release Attempt",
  "description": "Caller not designated client or arbitrator attempted fund-release",
  "timestamp": 1718290019280,
  "event_type": "fund-release",
  "tx_hash": "0x4f8a12bc90de45f678901234567890abcdef1234567890abcdef1234567890ab"
}
```

---

## 2. Authentication & Verification

Each webhook dispatch contains an HTTP header:
```http
x-auditx-signature: sha256=<hex_digest>
```

### Signature Computation:
```
signature = "sha256=" + HMAC_SHA256(secret_key, raw_utf8_json_payload)
```

The receiver MUST verify the signature using constant-time comparison (`crypto.timingSafeEqual`) prior to parsing or processing the body.

---

## 3. Retries & Dead-Letter Queue (DLQ)

- **Attempt 1**: Immediate
- **Attempt 2**: 1 minute backoff
- **Attempt 3**: 2 minutes backoff
- **Attempt 4**: 5 minutes backoff
- **Terminal Failure**: Payload persisted to DLQ (`reports-cache/webhook-dlq.json`) for manual triage and alarm triggering.

---

## 4. Test Vectors

### Vector 1:
- **Secret**: `sec_0123456789abcdef0123456789abcdef`
- **Payload**: `{"alert_id":"test-1","contract_address":"0x00000000000000000000000000000000000000aa","owning_app":"PolyLance","chain":"polygon","severity":"HIGH","category":"GOVERNANCE","title":"Test Anomaly","description":"Test alert","timestamp":1700000000000,"event_type":"fund-release","tx_hash":"0xtest"}`
- **Expected Header**: `x-auditx-signature: sha256=157186cd40465c7e63904242627ec690d23edf424e4c4cb41cd830f14c222bcc`
