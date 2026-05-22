// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./AgentRegistry.sol";

/**
 * @title AuditRegistry
 * @dev Immutable audit result log — core of the decentralized network
 */
contract AuditRegistry {
    AgentRegistry public agentRegistry;
    address public disputeResolver;

    struct AuditRecord {
        address auditor;
        bytes32 contractHash;
        string ipfsCID;
        uint8 cvssScore;
        uint8 riskLevel;
        uint256 timestamp;
        bool disputed;
    }

    mapping(bytes32 => AuditRecord[]) public audits;
    mapping(address => uint256) public agentReputation; // Mirrors or tracks specific audit reputation
    mapping(bytes32 => mapping(uint256 => uint256)) public disputeTimestamps;

    event AuditSubmitted(bytes32 indexed contractHash, address indexed auditor, string ipfsCID, uint8 cvssScore, uint8 riskLevel);
    event DisputeRaised(bytes32 indexed contractHash, uint256 indexed index, address challenger, string evidenceCID);
    event DisputeResolved(bytes32 indexed contractHash, uint256 indexed index, bool fraudProven);

    modifier onlyRegisteredAgent() {
        require(agentRegistry.isAgentActive(msg.sender), "Not an active registered agent");
        _;
    }

    modifier onlyDisputeResolver() {
        require(msg.sender == disputeResolver, "Only DisputeResolver allowed");
        _;
    }

    constructor(address _agentRegistry, address _disputeResolver) {
        agentRegistry = AgentRegistry(_agentRegistry);
        disputeResolver = _disputeResolver;
    }

    function setDisputeResolver(address _disputeResolver) external {
        // In a real system, this would be behind a timelock DAO vote
        // Assuming deployer sets it once, but we'll use a simple check
        require(disputeResolver == address(0), "DisputeResolver already set");
        disputeResolver = _disputeResolver;
    }

    /**
     * @notice Submit a completed audit to the immutable registry
     */
    function submitAudit(
        bytes32 contractHash,
        string calldata ipfsCID,
        uint8 cvssScore,
        uint8 riskLevel
    ) external onlyRegisteredAgent {
        audits[contractHash].push(AuditRecord({
            auditor: msg.sender,
            contractHash: contractHash,
            ipfsCID: ipfsCID,
            cvssScore: cvssScore,
            riskLevel: riskLevel,
            timestamp: block.timestamp,
            disputed: false
        }));

        agentReputation[msg.sender] += 1; // +1 reputation for successful submission

        emit AuditSubmitted(contractHash, msg.sender, ipfsCID, cvssScore, riskLevel);
    }

    /**
     * @notice Raise a dispute against an existing audit record
     * @dev Freezes the record for 72 hours
     */
    function disputeAudit(
        bytes32 contractHash,
        uint256 index,
        string calldata evidenceCID
    ) external {
        require(index < audits[contractHash].length, "Audit does not exist");
        AuditRecord storage record = audits[contractHash][index];
        require(!record.disputed, "Already disputed");

        // 72h challenge window enforcement
        require(block.timestamp <= record.timestamp + 72 hours, "Challenge window expired");

        record.disputed = true;
        disputeTimestamps[contractHash][index] = block.timestamp;

        emit DisputeRaised(contractHash, index, msg.sender, evidenceCID);
    }

    /**
     * @notice Resolve a pending dispute (called by DisputeResolver)
     */
    function resolveDispute(bytes32 contractHash, uint256 index, bool fraudProven) external onlyDisputeResolver {
        require(index < audits[contractHash].length, "Audit does not exist");
        AuditRecord storage record = audits[contractHash][index];
        require(record.disputed, "Audit is not disputed");

        if (fraudProven) {
            // Flag record as permanently invalid by keeping it disputed
            // Reputation slashing handled in AgentRegistry via DisputeResolver
            agentReputation[record.auditor] = 0; 
        } else {
            // Restore record
            record.disputed = false;
        }

        emit DisputeResolved(contractHash, index, fraudProven);
    }

    /**
     * @notice View function to get audit count for a contract
     */
    function getAuditCount(bytes32 contractHash) external view returns (uint256) {
        return audits[contractHash].length;
    }
}
