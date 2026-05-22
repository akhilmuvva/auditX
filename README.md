# AuditX 🛡️

AuditX is an autonomous, decentralized smart contract security agent that combines static analysis, symbolic execution, call-graph visualization, and AI-assisted triage into a single unified workspace. 

Beyond scanning, AuditX seals audit declarations on-chain using the **Ethereum Attestation Service (EAS)** and dynamically mints **fully on-chain SVG Security Badges** for clean, low-risk contracts.

---

## ✨ Features

- **Multi-Tool Pipeline**: Orchestrates Trail of Bits' **Slither**, ConsenSys' **Mythril**, and **Surya** in parallel for static analysis and symbolic execution.
- **AI Triage Layer**: Integrates advanced AI (Anthropic Claude Sonnet) to deduplicate, score CVSS, analyze business-logic risks, and suggest exact remediations.
- **Decentralized Sealing (EAS)**: Registers and attests the final contract audit parameters (target, risk score, IPFS report hash) on-chain on Layer 2 networks.
- **On-Chain SVG Badges**: Dynamically generates and mints unique physical-themed ERC-721 Security Badges (`Emerald Guard` for Safe, `Amber Guard` for Warning) directly on-chain based on the CVSS score.
- **Rich Visual Dashboard**: Includes an immersive 3D interactive Tech Stack blueprint and a live, dynamic audit execution simulator built inside a desktop web app.

---

## 🛠️ Tech Stack & Architecture

AuditX bridges high-performance off-chain analysis tools with secure on-chain Web3 trust frameworks.

```
       [ Solidity Smart Contract ]
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
┌──────────────────┐  ┌──────────────────┐
│ Static Analysis  │  │Symbolic Execution│
│    (Slither)     │  │    (Mythril)     │
└────────┬─────────┘  └────────┬─────────┘
         │                     │
         └──────────┬──────────┘
                    ▼
       ┌─────────────────────────┐
       │   Call-Graph & Description  │
       │         (Surya)         │
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │  AI Deduplication & CVSS│
       │    (Claude Sonnet)      │
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │ Decentralized Storage  │
       │     (IPFS Upload)       │
       └────────────┬────────────┘
         ┌──────────┴──────────┐
         ▼                     ▼
┌──────────────────┐  ┌──────────────────┐
│  L2 Attestation  │  │ On-Chain SVG NFT │
│    (EAS Seal)    │  │   (Badge Mint)   │
└──────────────────┘  └──────────────────┘
```

For an in-depth breakdown of the modular components, state engines, and protocol designs, check out the [ARCHITECTURE.md](./ARCHITECTURE.md) guide.

---

## 🚀 Quick Start

### 1. Installation

Clone the repository and install the dependencies:

```bash
npm install
```

Ensure you have Node.js (v18+) installed. To enable the local security tools, make sure `slither`, `myth`, and `surya` are available in your system path. If they are absent, AuditX will gracefully log warning fallbacks and proceed.

### 2. Basic Audit Run

Audit a single contract file:

```bash
node dist/cli.js --file ./contracts/VulnerableVault.sol
```

### 3. Full Decentralized Pipeline (Dry-Run Mode)

Run the full suite including IPFS hashing, Ethereum Attestation Service registry, and Badge NFT minting simulation:

```bash
node dist/cli.js --file ./contracts/VulnerableVault.sol --ipfs --eas --mint 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --no-mythril --no-ai
```

### 4. Mainnet / Testnet Deployment

To trigger real on-chain transactions on L2s (Base / Arbitrum Sepolia), set your `PRIVATE_KEY` and `RPC_URL` in the `.env` file first, then run:

```bash
node dist/cli.js --file ./contracts/VulnerableVault.sol --ipfs --eas --mint 0xRecipientAddress
```

---

## 📊 Outputs & Visual Dashboard

Every execution generates a dedicated timestamped folder inside `auditx-reports/` containing:
* **`audit-dashboard.html`**: A premium, interactive dashboard showing live-updating terminal logs, canvas-drift Surya Call Graphs, and 3D tilting Audit Badge previews.
* **`audit-report.md`**: A clean, readable markdown report summarizing the findings.
* **`audit-report.json`**: Highly detailed, structured machine-readable findings mapping locations and recommendations.

---

## 🛡️ Smart Contracts (`contracts/`)

- **`AuditBadgeNFT.sol`**: A self-contained, highly optimized ERC-721 contract. It encodes standard metadata schemas alongside a pure, base64-encoded SVG generator inside `tokenURI`. Badges are strictly locked for audits yielding a CVSS score `>= 7.0` to preserve the badge's status as a mark of safety.

---

## 👨‍💻 Author & Contributions

Built with 💻 by **Muvva Akhil Yadav**. Contributions, bug reports, and suggestions are welcome! Feel free to open issues or submit pull requests.

*Disclaimer: AuditX is an automated security scanner designed to speed up triage. It is a powerful assistant but does not replace a comprehensive, manual security audit by certified professionals.*
