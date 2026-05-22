import fs from 'fs';
import path from 'path';

/**
 * Auto-generates a subgraph.yaml configuration based on deployed contracts.
 */
function generateSubgraphManifest() {
    const yaml = `
specVersion: 1.0.0
indexerHints:
  prune: auto
schema:
  file: ./schema.graphql
dataSources:
  - kind: ethereum
    name: AuditRegistry
    network: base-sepolia
    source:
      address: "0x0000000000000000000000000000000000000000"
      abi: AuditRegistry
      startBlock: 0
    mapping:
      kind: ethereum/events
      apiVersion: 0.0.7
      language: wasm/assemblyscript
      entities:
        - AuditSubmitted
        - DisputeRaised
        - DisputeResolved
      abis:
        - name: AuditRegistry
          file: ./abis/AuditRegistry.json
      eventHandlers:
        - event: AuditSubmitted(indexed bytes32,indexed address,string,uint8,uint8)
          handler: handleAuditSubmitted
        - event: DisputeRaised(indexed bytes32,indexed uint256,address,string)
          handler: handleDisputeRaised
        - event: DisputeResolved(indexed bytes32,indexed uint256,bool)
          handler: handleDisputeResolved
      file: ./src/mapping.ts
`;

    fs.writeFileSync(path.join(process.cwd(), 'subgraph.yaml'), yaml.trim());
    console.log("Generated subgraph.yaml configuration.");
}

generateSubgraphManifest();
