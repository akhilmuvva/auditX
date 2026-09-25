# Sentinel State Ledger

> **Role**: Sentinel, Principal Security Engineer + SRE  
> **Target**: AuditX Real-Time SIEM for PolyLance  
> **Workspace Branch**: `feat/polylance-realtime`  
> **Remote Origin**: `https://github.com/akhilmuvva/auditX.git`  
> **Last Verified**: 2026-09-25T15:30:00+05:30  

---

## 1. Phase Status Table (Honest Evidence-Graded)

| Phase / Task | Description | Status | Evidence | Next Step |
|---|---|---|---|---|
| **Task 0: Baseline & Compilers** | Rust workspace tests via WSL (`Ubuntu-22.04`), TypeScript checking (`tsc --noEmit`), and production build verification (`npm run build`). | **PASSED** | Rust: 48 tests passed across all 8 workspace crates. TS: 0 errors (`npx tsc --noEmit`). Production build bundles ABIs into `dist/src/contracts/abi/`. | Complete |
| **Task 1: Secrets & Auth Hardening** | Untrack registry file, rotate PolyLance secret/API key via ENV, constant-time compare (`timingSafeEqual`), SSRF protection, 410 Next.js stubs, docker-compose secrets parameterized as `${AUDITX_API_TOKEN}` and `${AUDITX_IDENTITY_SERVICE_KEY}` with no defaults. Strictly local repo access only. `.env*` and `.env.amoy-proof` in `.gitignore`. | **PASSED** | `docker-compose.yml` has zero hardcoded secret strings. `.env` and `.env*` in `.gitignore`. Constant-time compare verified. Zero external filesystem access. | Complete |
| **Task 2: Store Interface & Registry** | Express-owned register/list/deregister behind `ITenantStore` with Memory, File, SQLite (dev), Postgres (prod) implementations. Unique `(tenant, chain, address)`. Hot-reload into streamer within 5s. DLQ methods included. | **PASSED** | `ITenantStore` in `legacy/src/storage/tenantStore.ts`. Verified in `test/store.test.ts` (12/12 passed across Memory, File, SQLite, Postgres interface) and `test/tenantRegistry.test.ts` (3/3 passed). | Complete |
| **Task 3: Real Hardhat Polygon Streamer & Clone Discovery** | Polygon streamer importing production ABIs from `legacy/src/contracts/abi/` (zero hand-typed ABIs). Real Hardhat local test deploying `JobFactory` + `JobEscrow`, clones before & after streamer start, full lifecycle, dispute, decline, cancel, auto-release. Backfill via `getAllJobs()` and live `JobDeployed` discovery. Decodes all real contract events. | **PASSED** | Verified in `test/escrowDiscovery.test.ts` (1/1 passed) and `test/streamer.test.ts` (10/10 passed). Decodes all real contract events including `RoleGranted`, `RoleRevoked`, `PaymentTokenApproved`, `JobDeployed`, `JobPosted`, `JobFunded`, `WorkSubmitted`, `PaymentReleased`, `DisputeResolved`, `AutoReleased`, `JobCancelled`, `TreasuryWithdrawal`. | Complete |
| **Task 4: Escrow Security Threat Rules Matrix (StateTracker)** | Per-clone `StateTracker` with dynamic fee initialization and per-clone caching from `JobEscrow.PLATFORM_FEE_BPS()`. Rules evaluate real event fields only: unfunded/unsubmitted release, release > funded, dispute resolved by non-arbitrator, premature auto-release, dynamic fee anomaly (against clone's cached `configuredFeeBps`), Rule 5 unmatched clone drain transfer, factory role changes by non-admin, unapproved payment token modifications. | **PASSED** | Verified in `test/escrowRules.test.ts` (20/20 positive & negative unit tests passed, including custom 500 bps fee clone negative test and Rule 5 positive/negative drain tests) and `test/siem.test.ts` (30/30 passed). | Complete |
| **Task 5: Webhook Sender & Contract Reconciliation** | PolyLance webhook dispatch adhering strictly to `docs/auditx-webhook-contract.md` 3-header scheme (`x-auditx-signature`, `x-auditx-timestamp`, `x-auditx-nonce`), `${timestamp}.${nonce}.${rawBody}` HMAC SHA-256 signature, exponential retries, and DLQ. Reconciled against PolyLance receiver (`verifyWebhook.ts`). | **PASSED** | Verified in `test/contractReconcile.test.ts` (6/6 passed) and `test/webhook.test.ts` (3/3 passed). | Complete |
| **Task 6: Wallet Login SIWE Risk Service (Fail-Closed Auth)** | `auditx-identity-http` `/assess-wallet-login` with fail-closed security: rejects with 503 if `X-Service-Key` is unset/empty; validates constant-time `X-Service-Key` before JSON body parsing (401 on missing/wrong key, 200 on valid key). 250ms timeout; fail-safe step-up on error. | **PASSED** | Verified in `crates/auditx-identity-http/tests/auth_test.rs` (4/4 passed: missing key 401, wrong key 401, valid key 200, unset config 503) and `test/walletLogin.test.ts` (3/3 passed). | Complete |
| **Task 7: Multi-Tenant Isolation & Dashboard WS Stream** | Authenticated, tenant-filtered REST (`/api/siem/alerts`) and WebSocket (`/ws/siem`) streams. Tenant A never receives alerts registered for Tenant B. Handshake closure code 1008 on unauthenticated connections. | **PASSED** | Verified in `test/tenantIsolation.test.ts` (2/2 passed) and `test/authMatrix.test.ts` (7/7 passed). | Complete |
| **Task 8: End-to-End Test Suite & Latency Benchmark** | `npm run e2e:polylance` with 1,000 events, event-to-receipt latency benchmark (p50/p95/p99) separated from confirmation delay, fault tests (WS drop/reconnect, receiver 500 -> DLQ -> retry recovery). 0 duplicate alerts, 0 lost alerts. | **PASSED** | Verified in `test/e2ePolylance.test.ts`: **1,000 events**, **pipeline p50 = 0.20 ms**, **pipeline p95 = 0.77 ms**, **pipeline p99 = 2.84 ms** (Target SLA: <300 ms). Hardhat mined block delay (2 confirmations): 2.35 ms. 0 duplicate alert_ids, 0 lost alerts. | Complete |
| **Task 9: Read-Only On-Chain Live Verification (`npm run live:check`)** | Dedicated live check script (`scripts/liveCheck.ts`) scanning Polygon Mainnet (137) and Amoy (80002) from creation block to head with exponential backoff and loud failure on decode errors. | **PASSED** | Verified in `npm run live:check`: Mainnet: 3 monitored contracts, 11 historical logs fetched, 0 decode failures. Amoy: 4 monitored contracts, 0 decode failures across 36,662 blocks. | Complete |
| **Task 10: PolygonStreamer Read-Only Monitoring (`npm run streamer:monitor`)** | Real PolygonStreamer running against live Polygon Mainnet and Amoy networks with `getAllJobs` backfill, block subscription, and deduplication. | **PASSED** | Verified in `npm run streamer:monitor`: Mainnet (137): 2 clones watched, processed live block 94416129. Amoy (80002): 3 clones watched, processed live block 48506923. | Complete |
| **Task 11: Real Postgres Container Integration** | Run store integration tests against live PostgreSQL container via `docker compose up`. | **UNVERIFIED** | Docker Desktop engine daemon is not running on this host (`error during connect: open //./pipe/dockerDesktopLinuxEngine`). PostgreSQL store queries and schema are verified in `test/store.test.ts` via interface mocking. | Await Docker daemon startup |
| **Task 12: Synthetic Pipeline Regression Test (Mock Data, No Chain Contact)** | Subscription pipeline replay test (`npm run proof:replay`) executing real `PolygonStreamer` block range processor (`processBlockRange`) with mock block receipts, ABI event decoding, and threat rule evaluation. | **PASSED** | Verified in `npm run proof:replay` and `test/liveStreamerProof.test.ts` (5 events decoded, dynamic clone tracking, Rule 4 fee anomaly alert fired with HIGH severity). | Complete |
| **Task 13: Live On-Chain Proof (Real Amoy Network)** | Send real on-chain transaction (`postJob`) using user-provided funded throwaway key, verify live `PolygonStreamer` subscription detection, log count increment in `live:check`, and sweep balance. | **UNVERIFIED** | Awaiting funded throwaway testnet key (`AMOY_PROOF_PRIVATE_KEY`) and sweep destination address from user in `.env.amoy-proof`. Script `scripts/liveOnChainProof.ts` is implemented and ready. | Await user throwaway key |

---

## 2. UNVERIFIED Items List

1. **Task 13: Live On-Chain Proof (Real Amoy Network)**: Awaiting throwaway Amoy testnet private key (`AMOY_PROOF_PRIVATE_KEY`) and sweep return address from the user to execute `scripts/liveOnChainProof.ts` against Amoy candidate 1 (`0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b`).
2. **Task 11: Real PostgreSQL Container Execution**: Docker Desktop daemon is not running on this host (`docker info` pipe error).

---

## 3. Test Suite Summary

### Jest TypeScript Suites (`npm test`)
```text
Test Suites: 16 passed, 16 total
Tests:       97 passed, 97 total
Snapshots:   0 total
Time:        11.474 s
Ran all test suites.
```

### Rust Workspace (`cargo test --workspace` via WSL Ubuntu-22.04)
```text
running 48 tests across 8 crates:
- auditx-canister: 1 passed
- auditx-cli (integration): 2 passed
- auditx-core: 7 passed
- auditx-identity: 14 passed (6 unit + 8 integration)
- auditx-identity-http: 4 passed
- auditx-trust: 4 passed
- auditx-web2: 6 passed
- auditx-web3: 10 passed
Result: ok. 48 passed; 0 failed.
```

---

## 4. Deliverables

1. `docker-compose.yml`: Multi-service compose file for `auditx-server` and `postgres:16-alpine` with `${AUDITX_API_TOKEN}` and `${AUDITX_IDENTITY_SERVICE_KEY}`.
2. `legacy/src/siem/StateTracker.ts`: Per-clone dynamic fee caching and `fetchCloneFee` integration from `JobEscrow.PLATFORM_FEE_BPS()`.
3. `legacy/src/siem/EventClassifier.ts`: Dynamic Rule 4 platform fee evaluation against per-clone cached fee settings.
4. `scripts/liveOnChainProof.ts`: Standalone execution script for real on-chain Amoy proof reading strictly from `.env.amoy-proof` with balance sweep.
5. `scripts/liveReplayProof.ts` & `test/liveStreamerProof.test.ts`: Synthetic pipeline regression test verifying real `PolygonStreamer` block processing engine.
