# AuditX Architecture Specification

This document provides a technical overview of the architecture, design patterns, and cryptographic trust systems that power **AuditX**—the autonomous smart contract security agent.

---

## 🏗️ Core Architectural Blueprint

AuditX operates as a multi-tier pipeline divided into **Security Engines**, **AI Synthesis**, and a **Decentralized Trust Protocol**.

```
┌────────────────────────────────────────────────────────┐
│                    User Interface                      │
│      CLI Tool (commander)  /  3D HTML5 Dashboard       │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                    Execution Layer                     │
│    Orchestrates: Slither, Mythril, Surya parallel runs │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                   AI Synthesis Layer                   │
│   Claude Sonnet CVSS scoring, deduplication & analysis │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│               Decentralized Trust Layer                │
│    IPFS Cryptographic CIDs  /  L2 EAS Attestation      │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                  On-Chain Badging                      │
│     Dynamic On-Chain SVG rendering (AuditBadgeNFT)     │
└────────────────────────────────────────────────────────┘
```

---

## ⚡ The 8-Step Security Pipeline

AuditX guarantees trust and repeatability by executing a strict, structured pipeline in chronological order:

### 1. Parsing & Source Extraction
The agent parses CLI inputs, resolves paths (single files, local Hardhat/Foundry project roots, or GitHub repository clones), and extracts `.sol` paths, compiler configurations, and target interfaces.

### 2. Static Analysis (`Slither`)
Executes Traild of Bits' `slither` static analysis engine. Results are compiled as JSON mapping checks, AST findings, file line bounds, vulnerability impact ratings, and confidence intervals.

### 3. Symbolic Execution (`Mythril`)
Fires up ConsenSys' `mythril` symbolic execution scanner for deeper transaction-fuzzing analysis (e.g., detecting SWC-107 Reentrancy or SWC-101 Integer Overflow).

### 4. Code Structuring & Call Graphs (`Surya`)
Invokes `surya` to output linear inheritance trees, describe function scopes (public, external, modifiers), and construct `.dot` call-graph maps representing function execution pathways.

### 5. AI Synthesis & CVSS Scoring (`Claude`)
Aggregates all findings from Slither and Mythril. Runs a structured prompt through `Claude Sonnet` using the Anthropic API to:
* Deduplicate findings matching identical file locations and types.
* Grade vulnerabilities with precise CVSS severity ratings.
* Detail exact remediations alongside actionable Solidity patch snippets.
* Output structured, valid JSON matching the system's strict schemas.

### 6. Decentralized Storage (`IPFS Upload`)
Gathers the full audit dataset, markdown reports, and JSON metrics, and pushes them to decentralized storage.
* **Online Mode**: Integrates with Pinata API using pin credentials.
* **Offline Mode**: Operates a cryptographic Base58 SHA-256 multihash CID generator to establish authentic `Qm...` IPFS v0 hashes locally, guaranteeing offline execution integrity.

### 7. L2 Attestation (`EAS Seal`)
Authenticates the security state on-chain by registering a formal EAS attestation.
* Registers the schema: `AuditX-v1(string targetContract, uint8 severityScore, string ipfsCid, uint256 timestamp)`.
* Triggers an L2 JSON-RPC call using `ethers.js` via the user's signing key, sealing the cryptographic claim on-chain.

### 8. Dynamic Badge Minting (`AuditBadgeNFT`)
If the calculated CVSS score is strictly **`< 7.0` (Safe to Medium risk)**, the pipeline triggers a mint call on `AuditBadgeNFT.sol`. 
* Passes the developer wallet address and the authenticated IPFS report CID.
* The badge is strictly bypassed for high/critical security scores to safeguard the certification's value.

---

## 🔒 Decentralized trust & Cryptography

### 1. Pure On-Chain SVG NFT badge
Standard NFTs point to centralized HTTP JSON metadata or centralized image assets. If the server goes down, the badge is lost.

`AuditBadgeNFT.sol` resolves this by writing and generating **everything on-chain**:
* **Vector Shimmer Shields**: The Solidity code constructs raw SVG elements entirely on the EVM. It dynamically switches attributes (`shieldColor`, `badgeGrade`, `badgeText`) depending on the score.
* **EVM Base64 Encoder**: Features a custom, highly gas-optimized Solidity base64 encoder that packs the raw SVG into data URLs (`data:image/svg+xml;base64,...`) and combines them with attributes to output standard ERC-721 base64 metadata (`data:application/json;base64,...`).

### 2. High-Fidelity Simulations
To ensure the pipeline can be integrated into local continuous integration pipelines (CI/CD) and locally validated without spending real gas or requiring private keys, the trust layers deploy authentic fallbacks:
* **EAS Cryptographic Attestation simulator**: Utilizes cryptographic hashes of input data to output realistic L2 transaction hashes (`0x...`) and valid UUIDs.
* **IPFS Offline CID generator**: Converts raw files into authentic cryptographic SHA-256 Base58 multihashes locally, matching exact IPFS standards.

---

## 🎨 Interactive Dashboard Architecture

The dashboard at [audit-dashboard.html](file:///C:/Users/akhil/.gemini/antigravity/scratch/auditx/dashboard/index.html) features a premium dark cyber theme utilizing:
* **3D Mouse Glare Tilt**: Implements CSS 3D perspectives coupled with mouse coordinates to tilt the dynamic badge card in a physical-like shimmer model.
* **Force-Directed Call Graph Canvas**: Combines vectors, node coordinates, and gentle drag-anchor algorithms on an HTML5 canvas to show Surya function dependencies in an alive, floating graph.
* **Typewriter Terminal**: An asynchronous javascript typewriter engine that prints compilation logs, security engine events, and Web3 mint confirmations in real time.
