// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./AgentRegistry.sol";

/**
 * @title StakeManager
 * @dev ERC-20 $AuditX token staking wrapper
 */
contract StakeManager is ERC20, ReentrancyGuard {
    IERC20 public auditXToken;
    AgentRegistry public agentRegistry;

    uint256 public constant UNSTAKE_DELAY = 7 days;

    struct UnstakeRequest {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => UnstakeRequest) public unstakeRequests;
    mapping(address => uint256) public lastRewardClaim;

    uint256 public constant REWARD_RATE_PER_AUDIT = 10 * 10**18; // 10 $AuditX per day/audit equivalent

    event Staked(address indexed user, uint256 amount);
    event UnstakeRequested(address indexed user, uint256 amount, uint256 unlockTime);
    event Unstaked(address indexed user, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 amount);

    constructor(address _agentRegistry, address _auditXToken) ERC20("Staked AuditX", "sAUDITX") {
        agentRegistry = AgentRegistry(_agentRegistry);
        auditXToken = IERC20(_auditXToken);
    }

    /**
     * @notice Stake ETH to receive sAUDITX receipt tokens
     */
    function stake() external payable nonReentrant {
        require(msg.value > 0, "Cannot stake 0");
        _mint(msg.sender, msg.value);
        if (lastRewardClaim[msg.sender] == 0) {
            lastRewardClaim[msg.sender] = block.timestamp;
        }
        emit Staked(msg.sender, msg.value);
    }

    /**
     * @notice Initiate unstake process (7-day timelock)
     */
    function unstake(uint256 amount) external nonReentrant {
        require(balanceOf(msg.sender) >= amount, "Insufficient sAUDITX balance");
        
        // Burn the sAUDITX receipt tokens now to prevent trading while unlocking
        _burn(msg.sender, amount);

        unstakeRequests[msg.sender] = UnstakeRequest({
            amount: unstakeRequests[msg.sender].amount + amount,
            unlockTime: block.timestamp + UNSTAKE_DELAY
        });

        emit UnstakeRequested(msg.sender, amount, unstakeRequests[msg.sender].unlockTime);
    }

    /**
     * @notice Execute unstake after the 7-day timelock
     */
    function executeUnstake() external nonReentrant {
        UnstakeRequest storage req = unstakeRequests[msg.sender];
        require(req.amount > 0, "No pending unstake");
        require(block.timestamp >= req.unlockTime, "Timelock active");

        uint256 amount = req.amount;
        req.amount = 0;
        req.unlockTime = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit Unstaked(msg.sender, amount);
    }

    /**
     * @notice Claim $AuditX governance token rewards
     */
    function claimRewards() external nonReentrant {
        require(agentRegistry.isAgentActive(msg.sender), "Must be an active agent");

        uint256 timeStaked = block.timestamp - lastRewardClaim[msg.sender];
        require(timeStaked > 0, "No rewards accrued");

        // Basic reward distribution logic based on time and stake
        uint256 reward = (balanceOf(msg.sender) * timeStaked * REWARD_RATE_PER_AUDIT) / (1 days * 1 ether);
        require(reward > 0, "No rewards to claim");

        lastRewardClaim[msg.sender] = block.timestamp;
        
        require(auditXToken.transfer(msg.sender, reward), "Reward transfer failed");
        
        emit RewardsClaimed(msg.sender, reward);
    }
}
