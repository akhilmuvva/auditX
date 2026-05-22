# AuditX — Architecture Overview

AuditX is a **fully decentralized, production-grade Smart Contract SIEM toolkit**.  
It covers the full security lifecycle: pre-deploy static analysis, post-deploy real-time monitoring, threat intelligence, and incident response — all running without a central server.

---

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  USER                                                                │
│  ┌────────────┐   upload .sol    ┌───────────────────────────────┐  │
│  │ Browser UI ├──────────────────► AuditX Dashboard (React+Vite) │  │
│  │ (Wallet)   │◄─────────────────┤ /audit  tab — LiveAuditSim    │  │
│  └────────────┘  findings/badge  │ /siem   tab — SIEMPanel       │  │
│                                  └──────────┬────────────────────┘  │
└─────────────────────────────────────────────┼────────────────────────┘
                                              │ REST + SSE + WebSocket
┌─────────────────────────────────────────────▼────────────────────────┐
│  AuditX Node (TypeScript / Node.js)                                  │
│                                                                      │
│  ┌─────────────────────┐    ┌───────────────────────────────────┐   │
│  │  Audit Pipeline      │    │  SIEM Engine (src/siem/)          │   │
│  │  runPipeline()       │    │                                   │   │
│  │  ├─ Slither          │    │  ChainEvent                       │   │
│  │  ├─ Mythril          │    │    → EventClassifier (9 rules)    │   │
│  │  ├─ Surya            │    │    → AnomalyDetector (Welford)    │   │
│  │  ├─ ZK Checks        │    │    → ThreatIntelligence (feeds)   │   │
│  │  └─ Claude AI        │    │    → AlertManager (lifecycle)     │   │
│  └──────────┬───────────┘    └──────────────┬────────────────────┘  │
│             │                               │                        │
│  ┌──────────▼───────────────────────────────▼────────────────────┐  │
│  │  Express HTTP + WebSocket Server (src/server.ts)               │  │
│  │  POST /api/audit          → triggers pipeline                  │  │
│  │  GET  /stream             → SSE audit step events              │  │
│  │  POST /api/siem/ingest    → SIEM event ingestion               │  │
│  │  GET  /api/siem/alerts    → open alert list                    │  │
│  │  WS   /ws/siem            → real-time alert push               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                │                          │
┌───────────────▼──────────────┐  ┌───────▼───────────────────────────┐
│  Decentralized Storage        │  │  On-Chain Layer (Base Sepolia)     │
│  IPFS (reports)               │  │  AuditJobQueue.sol — job coord.    │
│  Ceramic (user profiles)      │  │  ResumeRegistry.sol — ZK proofs    │
│  Lit Protocol (access ctrl)   │  │  AuditBadgeNFT.sol — ERC-721       │
│  TheGraph (EAS indexing)      │  │  AgentRegistry.sol — agents        │
└───────────────────────────────┘  │  StakeManager.sol — staking        │
                                   │  DisputeResolver.sol — disputes    │
                                   └───────────────────────────────────┘
```

---

## Component Reference

### `src/siem/` — SIEM Core Engine

| Module | Description |
|---|---|
| `types.ts` | All shared interfaces: `ChainEvent`, `Alert`, `ThreatFeed`, `SIEMOptions` |
| `EventClassifier.ts` | 9-rule deterministic classifier (FLASH_LOAN, REENTRANCY_SIGNAL, UPGRADE, etc.) |
| `AnomalyDetector.ts` | Welford online z-score with cold-start synthetic baseline (μ=65k gas) |
| `ThreatIntelligence.ts` | Built-in + IPFS-synced threat feeds; enriches events with known-bad address data |
| `AlertManager.ts` | Alert lifecycle (OPEN→ACK→RESOLVED), 1-min deduplication, IPFS/EAS hooks |
| `index.ts` | `SIEMEngine` — unified API wiring all 4 subsystems |

### `src/analysis/` — ZK Static Analysis

| Module | Description |
|---|---|
| `zkChecks.ts` | AST-level checks for 5 ZK security rules (REPLAY, QUALIFIED, THRESHOLD, DOMAIN SEP, TIMELOCK) |

### `src/runners/` — Security Tools

| Module | Description |
|---|---|
| `slither.ts` | Runs Slither static analyzer; parses findings JSON |
| `mythril.ts` | Runs Mythril symbolic execution; parses SWC findings |
| `surya.ts` | Generates call graph and inheritance diagram |
| `ai.ts` | Claude API triage with enriched SIEM-aware prompt |
| `onchain.ts` | IPFS upload, EAS attestation, NFT badge minting |

### `src/storage/` — Decentralized Storage

| Module | Description |
|---|---|
| `ipfs.ts` | Helia-based IPFS upload |
| `ceramic.ts` | Ceramic Network user profile storage |
| `lit.ts` | Lit Protocol access-controlled encryption |
| `theGraph.ts` | Apollo + TheGraph EAS attestation indexer |

### `src/network/` — libp2p P2P Layer

| Module | Description |
|---|---|
| `node.ts` | Creates libp2p node with TCP + Noise + Yamux + GossipSub |
| `agent.ts` | Worker agent that subscribes to audit job events |
| `jobQueue.ts` | Job queue management over libp2p |
| `consensus.ts` | Multi-agent result consensus logic |

### `contracts/` — On-Chain Layer

| Contract | Description |
|---|---|
| `AuditJobQueue.sol` | On-chain job coordinator for Akash workers |
| `ResumeRegistry.sol` | ZK-proof resume verification with 5 security rules |
| `AuditBadgeNFT.sol` | ERC-721 badge (EMERALD/AMBER/RED tiers) |
| `AgentRegistry.sol` | Registers authorized audit agents |
| `AuditRegistry.sol` | Stores audit result hashes on-chain |
| `StakeManager.sol` | Staking for worker nodes |
| `DisputeResolver.sol` | On-chain dispute resolution |

---

## SIEM Pipeline

```
ChainEvent (from block indexer / RPC)
   │
   ▼ EventClassifier
   ClassifiedEvent  (category + ruleSeverity)
   │
   ▼ AnomalyDetector (Welford online z-score)
   ScoredEvent  (anomaly score + finalSeverity)
   │
   ▼ ThreatIntelligence (seed + IPFS feeds)
   EnrichedEvent  (threatMatches + escalatedSeverity)
   │
   ▼ AlertManager (dedup + lifecycle + hooks)
   Alert[]  → WebSocket push → Dashboard SIEM tab
```

### Cold-Start Handling

When fewer than 100 historical events are available, `AnomalyDetector.train()` auto-generates synthetic baseline samples using Box-Muller normal distribution centered around typical ERC-20 transfer parameters (gasUsed μ=65,000 σ=5,000, callValue μ=0). This ensures meaningful z-scores from the very first real event.

---

## Badge Tiers

| Badge | CVSS | Meaning |
|---|---|---|
| 🔴 **RED** | ≥ 9.0 | Critical — do not deploy |
| 🟡 **AMBER** | 4.0 – 8.9 | High/Medium risk — fixes required |
| 🟢 **EMERALD** | < 4.0 | Low risk — safe to deploy |

Each failed ZK check adds +1.5 to the CVSS score: `finalCvss = min(10.0, baseCvss + failedChecks × 1.5)`

---

## CLI Reference

```bash
# Run static analysis on a contract
npm run audit -- -t ./contracts/MyContract.sol

# Run with Mythril (slower)
npm run audit -- -t ./contracts/MyContract.sol --mythril

# Start SIEM monitor (stdin mode)
npm run siem:monitor

# Start SIEM monitor watching a JSONL event file
npm run siem:monitor -- --file ./events.jsonl --watch --threshold MEDIUM

# Start API + SIEM WebSocket server
npm run dev

# Run all Jest tests
npm test

# Run SIEM tests only
npm run test:siem

# Run contract tests
npm run test:contracts

# TypeScript type check
npm run lint
```

---

## WebSocket Protocol (`/ws/siem`)

**Client → Server messages:**

```json
{ "type": "ingest",      "events": [ChainEvent, ...] }
{ "type": "acknowledge", "alertId": "abc123" }
{ "type": "resolve",     "alertId": "abc123" }
{ "type": "get_baseline" }
```

**Server → Client messages:**

```json
{ "type": "init",      "data": { "openAlerts": [...], "baseline": {...} } }
{ "type": "alert",     "data": Alert }
{ "type": "baseline",  "data": { "gasUsed": { "mean": 65000, "stdDev": 4800, "n": 100 }, ... } }
{ "type": "processed", "data": { "classified": 5, "anomalies": 1, "threatMatches": 0, "alerts": 2 } }
{ "type": "error",     "message": "..." }
```

---

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Description |
|---|---|
| `PRIVATE_KEY` | Wallet private key for contract deployment |
| `BASE_SEPOLIA_RPC` | Base Sepolia RPC endpoint |
| `ANTHROPIC_API_KEY` | Claude API key for AI triage |
| `THE_GRAPH_API_KEY` | TheGraph API key for EAS indexing |
| `CERAMIC_NODE_URL` | Ceramic Network node URL |

---

## Testing

| Suite | Command | Count |
|---|---|---|
| SIEM Engine (Jest) | `npm run test:siem` | 27 tests |
| Contract suite (Hardhat) | `npm run test:contracts` | ~40 tests |
| TypeScript types | `npm run lint` | 0 errors |
