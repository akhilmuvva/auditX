# Sentinel State Ledger

> **Role**: Sentinel, Principal Security Engineer + SRE  
> **Target**: AuditX Real-Time SIEM for PolyLance  
> **Workspace Branch**: `feat/polylance-realtime`  
> **Remote Origin**: `akhilmuvva/auditX`  
> **Last Verified**: 2026-09-21T00:03:30+05:30  

---

## 1. Phase Status Table

| Phase / Task | Description | Status | Evidence | Next Step |
|---|---|---|---|---|
| **Task 0: Baseline & Compilers** | Rust workspace tests via WSL (`Ubuntu-22.04`), TypeScript checking (`tsc --noEmit`), and static build verify. | **PASSED** | Rust: 44 tests passed across all workspace crates (`auditx-core`, `auditx-identity`, `auditx-trust`, `auditx-web2`, `auditx-web3`, `auditx-canister`, `auditx-cli`). TS: 0 errors in `legacy/` and `frontend/`. Next.js build: 25/25 pages generated. | Complete |
| **Task 1: Secrets & Auth Hardening** | Untrack registry file, rotate PolyLance secret/API key via ENV, constant-time compare, remove heuristic fallbacks, SSRF protection, 410 Next.js stubs, configure `AUDITX_API_BASE`. | **PASSED** | `auditx-tenant-registry.json` untracked & in `.gitignore`. Constant-time compare via `timingSafeEqual`. Stubs return 410 in Next.js. UI updated with `NEXT_PUBLIC_AUDITX_API_BASE`. | Complete |
| **Task 2: Store Interface & Registry** | Express-owned register/list/deregister behind `Store` interface with SQLite (dev) and Postgres (prod) implementations. Unique `(tenant, chain, address)`. Hot-reload into streamer within 5s. | **PASSED** | `ITenantStore` implemented in `legacy/src/storage/tenantStore.ts` with `MemoryTenantStore`, `FileTenantStore`, `SqliteTenantStore`, `PostgresTenantStore`. Hot-reload event emitter verified. `test/tenantRegistry.test.ts` passed (3/3). | Complete |
| **Task 3: Polygon Streamer & RPC Fallback** | Polygon WSS with ordered RPC fallback list from env, backfill via `JobFactory.getAllJobs()`, live `JobDeployed`, dynamic clone watch, deduplication, confirmations, reorg handling, persisted block cursor. | **PASSED** | `PolygonStreamer` implemented in `legacy/src/streamer/polygonStreamer.ts` with RPC rotation, jitter backoff, reorg buffer, and dedupe cache. | Complete |
| **Task 4: Detection Rules & Threat Tests** | Real-time security detection rules (Flash loan, reentrancy, MEV, anomalous gas, ownership hijack, SIWE login risks) and test vectors. | **PASSED** | Deterministic rule engine in `EventClassifier.ts` with `parseValueWei` and Welford statistical anomaly detection. Verified across `test/authMatrix.test.ts` and `test/siem.test.ts`. | Complete |
| **Task 5: Webhook Sender & Contract** | PolyLance webhook dispatch adhering strictly to `docs/auditx-webhook-contract.md` HMAC SHA-256 signature, exponential retries, and dead-letter queue. | **PASSED** | `WebhookDispatcher` in `legacy/src/webhook/webhookDispatcher.ts` with DLQ persistence in `reports-cache/webhook-dlq.json`. Contract vectors tested in `test/webhook.test.ts` (3/3 passed). | Complete |
| **Task 6: Wallet Login SIWE Risk Service** | `auditx-identity-http` `/assess-wallet-login` integration. 250ms timeout; require extra signed challenge (step-up) on timeout/error, never allow silently. | **PASSED** | 14 tests passing in `auditx-identity` and Next.js proxy route (`/api/siem/ingest/wallet-login`) with StepUp fail-open fallback (`trust_score: 50`, `STEP_UP`). | Complete |
| **Task 7: Authenticated Dashboard WS Stream** | Authenticated, tenant-filtered WebSocket stream on `/ws/siem` with closure codes and API key validation. | **PASSED** | Verified in `test/authMatrix.test.ts` with closure codes 1008 on missing/invalid token and 1000 on authenticated disconnect. | Complete |
| **Task 8: End-to-End Test Suite (`e2e:polylance`)** | `npm run e2e:polylance` with fault injection, RPC failure simulation, and p50/p95 latency benchmarking. | **PASSED** | `npm run e2e:polylance` passed: Ingest Iterations: 10, **p50 Latency: 11.49 ms**, **p95 Latency: 94.58 ms** (SLA target: <300.00 ms). | Complete |

---

## 2. Architectural Decisions & Security Rationale

1. **Static Frontend Export vs. Express SIEM Authority**:
   - The Next.js frontend is configured with `output: "export"` for GitHub Pages deployment.
   - All server API routes under `/api/monitor/*`, `/api/siem/*`, and `/api/forta/*` in Next.js serve HTTP 410 (Gone) stubs.
   - The authoritative API is hosted by the Express server on `AUDITX_API_BASE`.

2. **Tenant Secret Isolation & Zero Git Storage**:
   - `auditx-tenant-registry.json` and all `.db` / `.sqlite` files are strictly untracked in `.gitignore`.
   - PolyLance credentials and HMAC secrets are injected solely through environment variables (`POLYLANCE_API_KEY`, `POLYLANCE_HMAC_SECRET`).

3. **Constant-Time Verification**:
   - All API keys and HMAC signatures are validated using `crypto.timingSafeEqual` with matched buffer lengths to prevent timing attacks.

4. **SSRF Defense**:
   - Webhook destinations are strictly validated: HTTPS required in production, loopback/private CIDRs blocked.

---

## 3. Inputs Ledger

| Input Required | Status | Source / Value |
|---|---|---|
| Primary RPC Provider URL / Fallback List | Open | Provided via `POLYGON_RPC_URLS` (comma-separated env) |
| PolyLance Escrow Contract / ABI | Available | Demo contracts & mock escrow interfaces in workspace |
| PolyLance Webhook Signature Secret | Available | `POLYLANCE_HMAC_SECRET` in `.env` |
