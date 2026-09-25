# AuditX v2.0

> Full-stack Web3+Web2 security scanner. On-chain audit attestation via EAS. Written in Rust.

---

## Installation

```bash
cargo install auditx
```

## Quick Start

```bash
# 1. Run a clean audit demo
auditx audit --demo clean

# 2. Audit a single Solidity contract with on-chain proofs
auditx audit --file ./MyToken.sol --ipfs --eas

# 3. Scan a fullstack dApp directory with CI exit codes
auditx audit --dir ./my-dapp --ci
```

---

## What It Detects

### Web3 (Solidity)
| Threat / Vulnerability | Source / Detection Method | SWC ID | Severity |
|---|---|---|---|
| Reentrancy Checks | Slither, Mythril, Custom AST | SWC-107 | Critical/High |
| Oracle Price Manipulation | Custom AST (missing TWAP) | N/A | High |
| Signature Replay (Missing Nonces) | Custom AST (`ecrecover` pattern) | SWC-121 | High |
| Weak Randomness (Timestamp dependency) | Custom AST (`block.timestamp` pattern) | SWC-120 | Medium |

### Web2 (Infrastructure & Configs)
| Defect / Vulnerability | Source / Detection Method | OWASP ID | Severity |
|---|---|---|---|
| Command / SQL Injection | Semgrep, Config Checker | OWASP A03 | Critical/High |
| Hardcoded Credentials | Gitleaks, Shannon Entropy fallback | OWASP A02 | Critical |
| Vulnerable Dependencies | cargo-audit, npm-audit | OWASP A06 | High/Medium |
| Permissive CORS / Missing Rate Limiting | Config Checker | OWASP A05 | Medium |

---

## Architecture

```text
               +----------------------------------------+
               |          Next.js Web Frontend          |
               +-------------------+--------------------+
                                   |
                                   v  (JSON POST / SSE)
               +-------------------+--------------------+
               |           AuditX Rust Orchestrator     |
               +--------+----------------------+--------+
                        |                      |
                        v                      v
             +----------+----------+  +--------+----------+
             | Web3 Engine (alloy) |  |   Web2 Engine     |
             +----------+----------+  +--------+----------+
                        |                      |
                        v                      v
             +----------+----------+  +--------+----------+
             | Slither, Mythril,   |  | Semgrep, Gitleaks |
             | Custom AST Checks   |  | Dependency Audit  |
             +----------+----------+  +--------+----------+
                        |                      |
                        +-----------+----------+
                                    |
                                    v
                       +------------+------------+
                       |   AI Fusion (Gemini 2.5) |
                       +------------+------------+
                                    |
                                    v
                       +------------+------------+
                       | Trust Layer (IPFS/EAS)  |
                       +-------------------------+
```

---

## Workspace Structure

- `crates/auditx-core`: Common data models, CVSS aggregators, project detector.
- `crates/auditx-web3`: Solidity compilers, subprocess launchers, AST rules.
- `crates/auditx-web2`: Semgrep wrappers, entropy parsers, dependency auditors.
- `crates/auditx-ai`: Google Gemini integration, attack-chain synthesizers.
- `crates/auditx-trust`: IPFS CIDs, alloy-rs transaction builders.
- `crates/auditx-cli`: Command-line shell dispatcher.
- `crates/auditx-canister`: Internet Computer (ICP) Audit Ledger registry.

---

## ICP Canister Deployment

```bash
# 1. Start local replica
dfx start --background

# 2. Build target WebAssembly
cargo build --target wasm32-unknown-unknown --release -p auditx-canister

# 3. Deploy canister
dfx deploy auditx-canister
```

---

## Performance Benchmarks

| Metric | Legacy TypeScript Pipeline | AuditX v2.0 (Rust) | Performance Gain |
|---|---|---|---|
| Boot & Setup Duration | 4.8s | 0.05s | ~96x Speedup |
| Custom AST Scanner | 18.2s | 0.12s | ~150x Speedup |
| Offline CID Generator | 840ms | 0.015ms | ~56,000x Speedup |

---

## Badge Embedding Guide

Copy and paste this markdown/HTML badge directly into your repository's README to show your certified AuditX CVSS score:

```markdown
[![AuditX Score](https://auditx.codes/api/badge/YOUR_AUDIT_ID.svg)](https://auditx.codes/report/YOUR_AUDIT_ID)
```

---

## Real-Time SIEM & PolyLance Escrow Monitor

AuditX includes a production real-time SIEM engine tailored for decentralized escrows (such as PolyLance).

### Key Features
- **Contract Threat Rules Matrix (StateTracker)**: Zero synthetic fields; all invariants evaluated directly from verified EVM events (`PaymentReleased`, `DisputeResolved`, `AutoReleased`, `RoleGranted`, `RoleRevoked`, `PaymentTokenApproved`, `Transfer`).
- **PolygonStreamer**: Live block polling and WSS subscriptions with automatic deduplication, confirmation lag, and reorg detection.
- **Fail-Closed Identity SIWE Service**: Constant-time `X-Service-Key` verification rejecting unconfigured services with HTTP 503 and unauthorized requests with HTTP 401.
- **PolyLance Webhook Dispatcher**: Signed HMAC SHA-256 webhooks adhering to the 3-header scheme (`x-auditx-signature`, `x-auditx-timestamp`, `x-auditx-nonce`) with exponential retry backoff and Dead Letter Queue (DLQ).

### CLI Scripts & Verification

```bash
# 1. Run Complete TypeScript Test Suite (Unit + Integration + Discovery + E2E)
npm test

# 2. Run High-Scale 1,000+ Event Benchmark with Fault Injection
npm run e2e:polylance

# 3. Live On-Chain Verification (Scans Polygon Mainnet 137 & Amoy 80002)
npm run live:check

# 4. Run Live Polygon Streamer in Read-Only Mode
npm run streamer:monitor
```

### Docker Deployment

```bash
# 1. Configure environment
cp .env.example .env

# 2. Build and start services (AuditX Server + PostgreSQL)
docker compose up --build -d

# 3. Check container logs
docker compose logs -f auditx-server
```

---

## Deployed Registry Contracts

| Network | Contract / Interface | Address |
|---|---|---|
| Base Sepolia | EAS Attestation Registrar | `0x4200000000000000000000000000000000000021` |
| Base Sepolia | AuditBadgeNFT (ERC-721) | `0x5FbDB2315678afecb367f032d93F642f64180aa3` |
| Polygon Mainnet (137) | PolyLance JobFactory | `0xbE74923BBfd72d400a681915dBcf6e6Adc72C317` |
| Polygon Mainnet (137) | JobEscrow Master Implementation | `0x88dd19df1b6dBA8D2c53b3976f4ec39B75f17FbB` |
| Polygon Amoy (80002) | PolyLance JobFactory | `0x01467075D5BB3dFa09CbBDBE60275Ec38f75a70b` |
| Polygon Amoy (80002) | JobEscrow Master Implementation | `0xfDC15e8261677C41e8e872A8fb05D2369753F8a7` |

