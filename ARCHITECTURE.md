# AuditX V2 Architecture

AuditX V2 transitions from a centralized Web2 API to a fully decentralized Agent Network.

## The 6-Layer Architecture

### L1: Agent Orchestration Network
- Built on **libp2p** (TCP, GossipSub, Noise encryption).
- No central coordinator.
- Agents subscribe to `audit-jobs` and `audit-results` topics.

### L2: Analysis Pipeline
- **Static Analysis**: Slither & Mythril.
- **Topological Analysis**: Surya Call Graphs.
- **ZK Checks**: Custom `@solidity-parser/parser` rules enforcing 5 strict ZK verification patterns.
- **AI Triage**: Claude Sonnet refines findings into CVSS + Risk Level + Remediations.

### L3: Decentralized Storage & Consensus
- **Helia (IPFS)**: Content-addressed report storage.
- **Ceramic (DID)**: Mutable, decentralized state (Streams).
- **Lit Protocol**: Threshold encryption for encrypted reports.
- **The Graph**: Indexing engine via GraphQL Subgraph.

### L4: On-Chain Layer (Base L2)
- **AgentRegistry**: Staking (0.1 ETH minimum), slashing, deregistration (7-day timelock).
- **AuditRegistry**: Immutable log of submissions.
- **DisputeResolver**: Decentralized conflict resolution.
- **ResumeRegistry**: ZK proof verification with 48h verifier timelocks.
- **AuditBadgeNFT**: Dynamic on-chain SVG ERC-721 reflecting real-time security tiers.

### L5: Security Enforcements (The 5 ZK Checks)
1. **Replay Protection**: Nullifier must include `studentIdHash + jobId + chainid + address(this)`.
2. **Qualified First**: `require(_pubSignals[0] == 1)` as the first check.
3. **Threshold Second**: `require(_pubSignals[1] >= minimumThreshold)` as the second check.
4. **Domain Separation**: Baked into the nullifier.
5. **Timelock Upgrades**: `proposeVerifierUpdate` with a 48h delay.

### L6: Client Layer
- React Dashboard.
- Live Audit Simulator.
- Complete visual provenance and agent mesh monitoring.
