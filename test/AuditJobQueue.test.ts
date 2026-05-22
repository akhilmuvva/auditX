import { expect } from "chai";
import pkg from "hardhat";
const { ethers } = pkg;
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers.js";

describe("AuditJobQueue", () => {
  const AUDIT_FEE = ethers.parseEther("0.01");
  const WORKER_NODE_ROLE = ethers.keccak256(ethers.toUtf8Bytes("WORKER_NODE_ROLE"));

  let queue: any;
  let admin: HardhatEthersSigner;
  let user: HardhatEthersSigner;
  let worker: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  beforeEach(async () => {
    [admin, user, worker, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AuditJobQueue");
    queue = await Factory.deploy(AUDIT_FEE);
    await queue.waitForDeployment();

    // Grant WORKER_NODE_ROLE to worker account
    await queue.connect(admin).grantRole(WORKER_NODE_ROLE, worker.address);
  });

  // ─── Deployment ─────────────────────────────────────────────────────────────

  describe("Deployment", () => {
    it("sets initial audit fee", async () => {
      expect(await queue.auditFee()).to.equal(AUDIT_FEE);
    });

    it("starts nextJobId at 1", async () => {
      expect(await queue.nextJobId()).to.equal(1n);
    });

    it("grants DEFAULT_ADMIN_ROLE to deployer", async () => {
      const ADMIN_ROLE = await queue.DEFAULT_ADMIN_ROLE();
      expect(await queue.hasRole(ADMIN_ROLE, admin.address)).to.be.true;
    });
  });

  // ─── setAuditFee ────────────────────────────────────────────────────────────

  describe("setAuditFee()", () => {
    it("allows admin to update the fee", async () => {
      const newFee = ethers.parseEther("0.05");
      await queue.connect(admin).setAuditFee(newFee);
      expect(await queue.auditFee()).to.equal(newFee);
    });

    it("emits AuditFeeUpdated event", async () => {
      const newFee = ethers.parseEther("0.05");
      await expect(queue.connect(admin).setAuditFee(newFee))
        .to.emit(queue, "AuditFeeUpdated")
        .withArgs(newFee);
    });

    it("reverts if called by non-admin", async () => {
      await expect(
        queue.connect(other).setAuditFee(ethers.parseEther("0.1"))
      ).to.be.reverted;
    });
  });

  // ─── submitJob ──────────────────────────────────────────────────────────────

  describe("submitJob()", () => {
    const IPFS_HASH = "QmTestSourceHash123456789";

    it("creates a job with PENDING status", async () => {
      await queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      const job = await queue.jobs(1n);
      expect(job.submitter).to.equal(user.address);
      expect(job.sourceIpfsHash).to.equal(IPFS_HASH);
      expect(job.status).to.equal(0); // PENDING
      expect(job.resultIpfsHash).to.equal("");
    });

    it("increments nextJobId after each submission", async () => {
      await queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      await queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      expect(await queue.nextJobId()).to.equal(3n);
    });

    it("stores job in userJobs mapping", async () => {
      await queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      const userJobIds = await queue.getUserJobs(user.address);
      expect(userJobIds).to.deep.equal([1n]);
    });

    it("emits AuditRequested event with correct args", async () => {
      await expect(
        queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE })
      )
        .to.emit(queue, "AuditRequested")
        .withArgs(1n, user.address, IPFS_HASH);
    });

    it("accepts fee larger than minimum (overpayment ok)", async () => {
      const overpay = ethers.parseEther("1.0");
      await expect(
        queue.connect(user).submitJob(IPFS_HASH, { value: overpay })
      ).not.to.be.reverted;
    });

    it("reverts when fee is insufficient", async () => {
      const tooLow = ethers.parseEther("0.001");
      await expect(
        queue.connect(user).submitJob(IPFS_HASH, { value: tooLow })
      ).to.be.revertedWith("AuditJobQueue: Insufficient fee paid");
    });

    it("accumulates ETH balance in contract", async () => {
      await queue.connect(user).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      await queue.connect(other).submitJob(IPFS_HASH, { value: AUDIT_FEE });
      const balance = await ethers.provider.getBalance(await queue.getAddress());
      expect(balance).to.equal(AUDIT_FEE * 2n);
    });
  });

  // ─── updateJobStatus ────────────────────────────────────────────────────────

  describe("updateJobStatus()", () => {
    const SOURCE_HASH  = "QmSourceHash";
    const RESULT_HASH  = "QmResultHash";

    beforeEach(async () => {
      // Submit a job so we have jobId=1
      await queue.connect(user).submitJob(SOURCE_HASH, { value: AUDIT_FEE });
    });

    it("worker can set status to PROCESSING (1)", async () => {
      await queue.connect(worker).updateJobStatus(1n, 1, "");
      const job = await queue.jobs(1n);
      expect(job.status).to.equal(1); // PROCESSING
    });

    it("worker can set status to COMPLETED with result hash", async () => {
      await queue.connect(worker).updateJobStatus(1n, 2, RESULT_HASH);
      const job = await queue.jobs(1n);
      expect(job.status).to.equal(2); // COMPLETED
      expect(job.resultIpfsHash).to.equal(RESULT_HASH);
    });

    it("worker can set status to FAILED (3)", async () => {
      await queue.connect(worker).updateJobStatus(1n, 3, "");
      const job = await queue.jobs(1n);
      expect(job.status).to.equal(3); // FAILED
    });

    it("emits JobStatusUpdated event", async () => {
      await expect(queue.connect(worker).updateJobStatus(1n, 2, RESULT_HASH))
        .to.emit(queue, "JobStatusUpdated")
        .withArgs(1n, 2, RESULT_HASH);
    });

    it("reverts if job does not exist", async () => {
      await expect(
        queue.connect(worker).updateJobStatus(999n, 2, RESULT_HASH)
      ).to.be.revertedWith("AuditJobQueue: Job does not exist");
    });

    it("reverts if job is already COMPLETED", async () => {
      await queue.connect(worker).updateJobStatus(1n, 2, RESULT_HASH);
      await expect(
        queue.connect(worker).updateJobStatus(1n, 3, "")
      ).to.be.revertedWith("AuditJobQueue: Job already completed");
    });

    it("reverts if called by non-worker", async () => {
      await expect(
        queue.connect(other).updateJobStatus(1n, 2, RESULT_HASH)
      ).to.be.reverted;
    });
  });

  // ─── withdrawFees ────────────────────────────────────────────────────────────

  describe("withdrawFees()", () => {
    beforeEach(async () => {
      await queue.connect(user).submitJob("QmHash", { value: AUDIT_FEE });
    });

    it("transfers balance to recipient", async () => {
      const before = await ethers.provider.getBalance(admin.address);
      const tx = await queue.connect(admin).withdrawFees(admin.address);
      const receipt = await tx.wait();
      const gasCost = receipt!.gasUsed * receipt!.gasPrice;
      const after = await ethers.provider.getBalance(admin.address);
      // after ≈ before + AUDIT_FEE − gasCost
      expect(after).to.be.closeTo(before + AUDIT_FEE - gasCost, ethers.parseEther("0.0001"));
    });

    it("reverts when no funds available", async () => {
      await queue.connect(admin).withdrawFees(admin.address);
      await expect(
        queue.connect(admin).withdrawFees(admin.address)
      ).to.be.revertedWith("AuditJobQueue: No funds to withdraw");
    });

    it("reverts if called by non-admin", async () => {
      await expect(
        queue.connect(other).withdrawFees(other.address)
      ).to.be.reverted;
    });
  });

  // ─── getUserJobs ─────────────────────────────────────────────────────────────

  describe("getUserJobs()", () => {
    it("returns empty array for user with no jobs", async () => {
      const ids = await queue.getUserJobs(other.address);
      expect(ids).to.have.length(0);
    });

    it("returns all job IDs for a user across multiple submissions", async () => {
      await queue.connect(user).submitJob("QmHash1", { value: AUDIT_FEE });
      await queue.connect(user).submitJob("QmHash2", { value: AUDIT_FEE });
      await queue.connect(other).submitJob("QmHash3", { value: AUDIT_FEE });
      const userIds = await queue.getUserJobs(user.address);
      expect(userIds).to.deep.equal([1n, 2n]);
    });
  });
});
