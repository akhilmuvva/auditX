// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/IResumeVerifier.sol";

/**
 * @title ResumeRegistry
 * @dev Registry for verifying ZK proofs of resumes, featuring protection against 
 * replay attacks, threshold bypasses, and unauthorized verifier upgrades.
 */
contract ResumeRegistry is Ownable, ReentrancyGuard {
    IResumeVerifier public verifier;
    uint256 public minimumThreshold;

    mapping(bytes32 => bool) public usedNullifiers;

    struct VerificationRecord {
        address submitter;
        uint256 timestamp;
        string jobId;
    }

    mapping(bytes32 => VerificationRecord) public records;

    // Timelock state for verifier upgrades
    address public pendingVerifier;
    uint256 public verifierUpdateUnlockTime;
    uint256 public constant TIMELOCK_DELAY = 48 hours;

    event ProofVerified(address indexed submitter, bytes32 indexed nullifier, string jobId);
    event VerifierUpdateProposed(address indexed newVerifier, uint256 unlockTime);
    event VerifierUpdateExecuted(address indexed newVerifier);
    event VerifierUpdateCancelled();

    /**
     * @param _verifier The initial ZK proof verifier contract
     * @param _minimumThreshold The minimum required threshold score
     */
    constructor(address _verifier, uint256 _minimumThreshold) Ownable(msg.sender) {
        verifier = IResumeVerifier(_verifier);
        minimumThreshold = _minimumThreshold;
    }

    /**
     * @notice Submit a ZK proof for verification
     * @param _pA Proof array A
     * @param _pB Proof array B
     * @param _pC Proof array C
     * @param _pubSignals Public signals [isQualified, score, studentIdHash]
     * @param jobId The ID of the job being applied for
     */
    function submitProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[3] calldata _pubSignals,
        string calldata jobId
    ) external nonReentrant {
        // 1. require(pubSignals[0]==1, "Not qualified")
        require(_pubSignals[0] == 1, "Not qualified");

        // 2. require(pubSignals[1]>=minimumThreshold, "Below threshold")
        require(_pubSignals[1] >= minimumThreshold, "Below threshold");

        // 3. derive nullifier = keccak256(abi.encodePacked(pubSignals[2], jobId, block.chainid, address(this)))
        bytes32 nullifier = keccak256(abi.encodePacked(_pubSignals[2], jobId, block.chainid, address(this)));

        // 4. require(!usedNullifiers[nullifier], "Proof already used")
        require(!usedNullifiers[nullifier], "Proof already used");

        // 5. require(verifier.verifyProof(...), "Invalid ZK proof")
        require(verifier.verifyProof(_pA, _pB, _pC, _pubSignals), "Invalid ZK proof");

        // 6. usedNullifiers[nullifier] = true      ← CEI: state AFTER ext call
        usedNullifiers[nullifier] = true;

        // 7. store VerificationRecord
        records[nullifier] = VerificationRecord({
            submitter: msg.sender,
            timestamp: block.timestamp,
            jobId: jobId
        });

        // 8. emit ProofVerified
        emit ProofVerified(msg.sender, nullifier, jobId);
    }

    /**
     * @notice Propose a new verifier address, subject to a 48h timelock
     * @param _newVerifier The address of the proposed new verifier
     */
    function proposeVerifierUpdate(address _newVerifier) external onlyOwner {
        require(_newVerifier != address(0), "Invalid verifier address");
        pendingVerifier = _newVerifier;
        verifierUpdateUnlockTime = block.timestamp + TIMELOCK_DELAY;
        emit VerifierUpdateProposed(_newVerifier, verifierUpdateUnlockTime);
    }

    /**
     * @notice Execute a pending verifier update after the timelock has expired
     */
    function executeVerifierUpdate() external onlyOwner {
        require(pendingVerifier != address(0), "No verifier update proposed");
        require(block.timestamp >= verifierUpdateUnlockTime, "Timelock not expired");

        verifier = IResumeVerifier(pendingVerifier);
        emit VerifierUpdateExecuted(pendingVerifier);

        pendingVerifier = address(0);
        verifierUpdateUnlockTime = 0;
    }

    /**
     * @notice Cancel a pending verifier update
     */
    function cancelVerifierUpdate() external onlyOwner {
        require(pendingVerifier != address(0), "No verifier update proposed");
        pendingVerifier = address(0);
        verifierUpdateUnlockTime = 0;
        emit VerifierUpdateCancelled();
    }
}
