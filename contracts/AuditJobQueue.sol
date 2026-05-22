// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AuditJobQueue
 * @dev The on-chain coordination layer for Akash worker nodes.
 * Users submit audit requests (code via IPFS) here. Akash workers listen to 
 * the AuditRequested event, process the analysis in a decentralized Docker 
 * container, and report back the results.
 */
contract AuditJobQueue is AccessControl {
    bytes32 public constant WORKER_NODE_ROLE = keccak256("WORKER_NODE_ROLE");

    uint256 public auditFee;
    uint256 public nextJobId;

    enum JobStatus { PENDING, PROCESSING, COMPLETED, FAILED }

    struct AuditJob {
        uint256 id;
        address submitter;
        string sourceIpfsHash;
        string resultIpfsHash;
        JobStatus status;
        uint256 timestamp;
    }

    mapping(uint256 => AuditJob) public jobs;
    mapping(address => uint256[]) public userJobs;

    event AuditRequested(uint256 indexed jobId, address indexed submitter, string sourceIpfsHash);
    event JobStatusUpdated(uint256 indexed jobId, JobStatus status, string resultIpfsHash);
    event AuditFeeUpdated(uint256 newFee);

    constructor(uint256 _initialFee) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        auditFee = _initialFee;
        nextJobId = 1;
    }

    function setAuditFee(uint256 _newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        auditFee = _newFee;
        emit AuditFeeUpdated(_newFee);
    }

    /**
     * @dev User submits a smart contract for auditing.
     * @param _sourceIpfsHash IPFS hash of the raw Solidity file or project zip.
     */
    function submitJob(string calldata _sourceIpfsHash) external payable {
        require(msg.value >= auditFee, "AuditJobQueue: Insufficient fee paid");

        uint256 jobId = nextJobId++;
        
        jobs[jobId] = AuditJob({
            id: jobId,
            submitter: msg.sender,
            sourceIpfsHash: _sourceIpfsHash,
            resultIpfsHash: "",
            status: JobStatus.PENDING,
            timestamp: block.timestamp
        });

        userJobs[msg.sender].push(jobId);

        emit AuditRequested(jobId, msg.sender, _sourceIpfsHash);
    }

    /**
     * @dev Akash worker node updates the job status and final result hash.
     */
    function updateJobStatus(uint256 _jobId, JobStatus _status, string calldata _resultIpfsHash) 
        external 
        onlyRole(WORKER_NODE_ROLE) 
    {
        require(jobs[_jobId].id != 0, "AuditJobQueue: Job does not exist");
        require(jobs[_jobId].status != JobStatus.COMPLETED, "AuditJobQueue: Job already completed");

        jobs[_jobId].status = _status;
        jobs[_jobId].resultIpfsHash = _resultIpfsHash;

        emit JobStatusUpdated(_jobId, _status, _resultIpfsHash);
    }

    function getUserJobs(address _user) external view returns (uint256[] memory) {
        return userJobs[_user];
    }

    function withdrawFees(address payable _to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "AuditJobQueue: No funds to withdraw");
        _to.transfer(balance);
    }
}
