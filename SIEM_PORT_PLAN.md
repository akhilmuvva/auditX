# AuditX SIEM — Rust Porting & Multi-Tenant Architecture Plan

## Phase 0: Scope & Responsibility Audit

| Class | TypeScript File | Lines | Primary Responsibility | Rust Port Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **`EventClassifier`** | `legacy/src/siem/EventClassifier.ts` | 283 | Deterministic rule matching engine (Governance speedrun, FlashLoan, Reentrancy, Upgrades, Oracle manipulation, etc.). | **Ports Cleanly 1:1**. Pure function rules mapping `ChainEvent` -> `ClassifiedEvent` with category & severity. |
| **`AnomalyDetector`** | `legacy/src/siem/AnomalyDetector.ts` | 208 | Welford online running mean/variance & Box-Muller PRNG cold-start baseline generator. | **Ports Cleanly 1:1**. Welford state (`n`, `mean`, `M2`) and Box-Muller normal distribution require no heavy ML dependencies and run natively in Rust with high precision `f64`. |
| **`ThreatIntelligence`** | `legacy/src/siem/ThreatIntelligence.ts` | 210 | Curated feed of known malicious addresses (Tornado Cash, Lazarus, Euler, etc.) & event enrichment. | **Ports Cleanly 1:1**. Uses `HashMap<String, ThreatFeed>` with normalized lowercase keys. Includes IPFS feed sync capabilities. |
| **`AlertManager`** | `legacy/src/siem/AlertManager.ts` | 258 | Deduplication window (60s), threshold filtering, alert lifecycle (Open/Ack/Resolve/Suppress). | **Ports Cleanly 1:1**. Replaced JS `EventEmitter` with Rust thread-safe `SIEMAlertManager` using `std::sync::Arc<tokio::sync::RwLock<...>>` and HMAC signature generation. |

## Multi-Tenant & API Key Architectural Additions

1. **`ClientApp` Registration & API Key Management**:
   - `auditx-cli client register --name polylance --webhook-url ...`
   - Generates raw API key (`ax_live_...`), SHA-256 hash, and HMAC secret (`sec_...`).

2. **`MonitoredAddress` Multi-Tenant Scoping**:
   - Stores `address`, `chain`, `owning_app`, `webhook_url`, `api_key_hash`, `watch_config`.
   - Events matching a monitored contract address are isolated strictly to the owning client app to prevent cross-tenant alert leaks.

3. **HMAC Webhook Dispatch**:
   - When an alert triggers, an HTTP POST payload is dispatched to `webhook_url` signed with `X-AuditX-Signature: sha256=<hmac_hex>`.
