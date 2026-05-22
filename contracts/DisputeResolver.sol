// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./AgentRegistry.sol";
import "./AuditRegistry.sol";

/**
 * @title DisputeResolver
 * @dev Optimistic fraud proof resolution
 */
contract DisputeResolver is Ownable, ReentrancyGuard {
    AgentRegistry public agentRegistry;
    AuditRegistry public auditRegistry;

    uint256 public constant DISPUTE_BOND = 0.05 ether;

    struct Dispute {
        address challenger;
        address auditor;
        uint256 bond;
        bool resolved;
    }

    // Mapping contractHash => auditIndex => Dispute
    mapping(bytes32 => mapping(uint256 => Dispute)) public disputes;

    event DisputeRaised(bytes32 indexed contractHash, uint256 indexed auditIndex, address indexed challenger, string evidenceCID);
    event DisputeResolved(bytes32 indexed contractHash, uint256 indexed auditIndex, bool fraudProven, address challenger, address auditor);

    /**
     * @param _agentRegistry Address of the AgentRegistry
     * @param _auditRegistry Address of the AuditRegistry
     */
    constructor(address _agentRegistry, address _auditRegistry) Ownable(msg.sender) {
        agentRegistry = AgentRegistry(_agentRegistry);
        auditRegistry = AuditRegistry(_auditRegistry);
    }

    /**
     * @notice Raise a dispute against an audit record
     * @param contractHash The hash of the audited contract
     * @param auditIndex The index of the audit in AuditRegistry
     * @param evidenceCID IPFS CID of the evidence
     */
    function raiseDispute(bytes32 contractHash, uint256 auditIndex, string calldata evidenceCID) external payable nonReentrant {
        require(msg.value == DISPUTE_BOND, "Incorrect dispute bond amount");
        require(disputes[contractHash][auditIndex].challenger == address(0), "Dispute already exists");

        // Use the low-level external call to fetch the auditor from the array (if supported) or 
        // we can assume the AuditRegistry keeps track. AuditRegistry disputeAudit checks bounds.
        // We call AuditRegistry to freeze the record for 72h
        auditRegistry.disputeAudit(contractHash, auditIndex, evidenceCID);

        // Fetch the auditor address from AuditRegistry
        (address auditor,,,,,,) = auditRegistry.audits(contractHash, auditIndex);

        disputes[contractHash][auditIndex] = Dispute({
            challenger: msg.sender,
            auditor: auditor,
            bond: msg.value,
            resolved: false
        });

        emit DisputeRaised(contractHash, auditIndex, msg.sender, evidenceCID);
    }

    /**
     * @notice Resolve a dispute (Callable by DAO/Owner)
     * @param contractHash The hash of the audited contract
     * @param auditIndex The index of the audit in AuditRegistry
     * @param fraudProven Whether fraud was proven
     */
    function resolveDispute(bytes32 contractHash, uint256 auditIndex, bool fraudProven) external onlyOwner nonReentrant {
        Dispute storage d = disputes[contractHash][auditIndex];
        require(d.challenger != address(0), "Dispute does not exist");
        require(!d.resolved, "Dispute already resolved");

        d.resolved = true;

        // Update AuditRegistry
        auditRegistry.resolveDispute(contractHash, auditIndex, fraudProven);

        if (fraudProven) {
            // Slash auditor via AgentRegistry (e.g. slash 0.1 ETH stake)
            // Reward challenger bond x 3 (meaning return 0.05 + 0.1 from slashed agent)
            agentRegistry.slash(d.auditor, 0.1 ether);
            
            // Note: In reality, slashing sends funds to Treasury in AgentRegistry.
            // If the DisputeResolver is the Treasury, we have the funds.
            // For now, we return the challenger's bond + reward from our own contract balance if we have it, 
            // but the prompt specifies "reward challenger bond x 3".
            // We'll just send 0.15 ETH if the contract has balance.
            uint256 reward = DISPUTE_BOND * 3;
            if (address(this).balance >= reward) {
                (bool success, ) = d.challenger.call{value: reward}("");
                require(success, "Challenger reward failed");
            } else {
                // Fallback to just returning bond if insufficient funds
                (bool success, ) = d.challenger.call{value: d.bond}("");
                require(success, "Challenger bond return failed");
            }

        } else {
            // Return challenger bond (they lose the dispute but keep bond? The prompt says: "return challenger bond, add reputation to auditor")
            // Wait, normally if you lose a dispute, you lose the bond. The prompt literally says:
            // "if not: return challenger bond, add reputation to auditor". This is a very friendly system.
            (bool success, ) = d.challenger.call{value: d.bond}("");
            require(success, "Challenger bond return failed");

            // Add reputation to auditor
            agentRegistry.addReputation(d.auditor, 5); // Add +5 rep
        }

        emit DisputeResolved(contractHash, auditIndex, fraudProven, d.challenger, d.auditor);
    }

    // Allow contract to receive funds from slashes
    receive() external payable {}
}
