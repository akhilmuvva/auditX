// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title AgentRegistry
 * @dev Agent staking + reputation — the Sybil-resistance layer
 */
contract AgentRegistry is AccessControl, ReentrancyGuard {
    bytes32 public constant DISPUTE_RESOLVER_ROLE = keccak256("DISPUTE_RESOLVER_ROLE");
    
    uint256 public constant STAKE_AMOUNT = 0.1 ether;
    uint256 public constant WITHDRAWAL_DELAY = 7 days;

    struct Agent {
        uint256 stake;
        uint256 reputation;
        bool active;
        uint256 registeredAt;
    }

    mapping(address => Agent) public agents;
    mapping(address => uint256) public withdrawalUnlockTime;

    address public treasury;

    event AgentRegistered(address indexed agent, uint256 stake);
    event AgentSlashed(address indexed agent, uint256 amount);
    event AgentDeregistered(address indexed agent, uint256 unlockTime);
    event StakeWithdrawn(address indexed agent, uint256 amount);

    /**
     * @param _treasury Address where slashed funds are sent
     */
    constructor(address _treasury) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        treasury = _treasury;
    }

    /**
     * @notice Register as a new agent by staking the required amount
     */
    function register() external payable nonReentrant {
        require(msg.value >= STAKE_AMOUNT, "Insufficient stake");
        require(!agents[msg.sender].active, "Already active");
        
        uint256 currentStake = agents[msg.sender].stake;
        uint256 currentRep = agents[msg.sender].reputation;

        agents[msg.sender] = Agent({
            stake: currentStake + msg.value,
            reputation: currentRep == 0 ? 100 : currentRep, // initial rep = 100
            active: true,
            registeredAt: block.timestamp
        });

        emit AgentRegistered(msg.sender, msg.value);
    }

    /**
     * @notice Slash an agent's stake and reputation due to proven fraud
     * @param agent The agent to slash
     * @param amount The amount of stake to slash
     */
    function slash(address agent, uint256 amount) external onlyRole(DISPUTE_RESOLVER_ROLE) {
        Agent storage a = agents[agent];
        require(a.stake >= amount, "Slash amount exceeds stake");
        
        a.stake -= amount;
        
        if (a.reputation >= 10) {
            a.reputation -= 10; // Penalty to reputation
        } else {
            a.reputation = 0;
        }

        if (a.stake < STAKE_AMOUNT) {
            a.active = false;
        }

        (bool success, ) = treasury.call{value: amount}("");
        require(success, "Slash transfer failed");

        emit AgentSlashed(agent, amount);
    }

    /**
     * @notice Add reputation to an agent for successful audits/disputes
     */
    function addReputation(address agent, uint256 amount) external onlyRole(DISPUTE_RESOLVER_ROLE) {
        agents[agent].reputation += amount;
    }

    /**
     * @notice Initiate deregistration, subject to a 7-day withdrawal delay
     */
    function deregister() external {
        require(agents[msg.sender].active, "Agent not active");
        agents[msg.sender].active = false;
        withdrawalUnlockTime[msg.sender] = block.timestamp + WITHDRAWAL_DELAY;
        
        emit AgentDeregistered(msg.sender, withdrawalUnlockTime[msg.sender]);
    }

    /**
     * @notice Withdraw stake after the delay has passed
     */
    function withdrawStake() external nonReentrant {
        require(!agents[msg.sender].active, "Agent still active");
        require(withdrawalUnlockTime[msg.sender] > 0, "Deregistration not initiated");
        require(block.timestamp >= withdrawalUnlockTime[msg.sender], "Withdrawal timelock active");

        uint256 amount = agents[msg.sender].stake;
        require(amount > 0, "No stake to withdraw");

        agents[msg.sender].stake = 0;
        withdrawalUnlockTime[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal transfer failed");

        emit StakeWithdrawn(msg.sender, amount);
    }

    /**
     * @notice Check if an agent is active and fully staked
     */
    function isAgentActive(address agent) external view returns (bool) {
        return agents[agent].active && agents[agent].stake >= STAKE_AMOUNT;
    }
}
