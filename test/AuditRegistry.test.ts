import { expect } from "chai";
import pkg from "hardhat";
const { ethers } = pkg;

describe("AuditRegistry", function () {
  let agentRegistry: any;
  let auditRegistry: any;
  let owner: any;
  let agent1: any;
  let nonAgent: any;
  let disputeResolver: any;
  let treasury: any;

  beforeEach(async function () {
    [owner, agent1, nonAgent, disputeResolver, treasury] = await ethers.getSigners();
    
    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await AgentRegistry.deploy(treasury.address);
    await agentRegistry.waitForDeployment();

    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    auditRegistry = await AuditRegistry.deploy(await agentRegistry.getAddress(), disputeResolver.address);
    await auditRegistry.waitForDeployment();

    // Register agent1
    await agentRegistry.connect(agent1).register({ value: ethers.parseEther("0.1") });
  });

  it("Should allow active agent to submit an audit", async function () {
    const contractHash = ethers.id("test_contract");
    const ipfsCid = "QmTest123";

    await expect(
      auditRegistry.connect(agent1).submitAudit(contractHash, ipfsCid, 75, 2) // 75 score, risk 2 (high)
    ).to.emit(auditRegistry, "AuditSubmitted").withArgs(contractHash, agent1.address, ipfsCid, 75, 2);

    const count = await auditRegistry.getAuditCount(contractHash);
    expect(count).to.equal(1);

    const audit = await auditRegistry.audits(contractHash, 0);
    expect(audit.auditor).to.equal(agent1.address);
    expect(audit.ipfsCID).to.equal(ipfsCid);
  });

  it("Should reject audit from non-agent", async function () {
    const contractHash = ethers.id("test_contract");
    await expect(
      auditRegistry.connect(nonAgent).submitAudit(contractHash, "Qm123", 50, 1)
    ).to.be.revertedWith("Not an active registered agent");
  });

  it("Should allow raising and resolving a dispute", async function () {
    const contractHash = ethers.id("test_contract");
    await auditRegistry.connect(agent1).submitAudit(contractHash, "QmTest123", 75, 2);

    // Raise dispute
    await expect(
      auditRegistry.connect(nonAgent).disputeAudit(contractHash, 0, "QmEvidence123")
    ).to.emit(auditRegistry, "DisputeRaised").withArgs(contractHash, 0, nonAgent.address, "QmEvidence123");

    let audit = await auditRegistry.audits(contractHash, 0);
    expect(audit.disputed).to.be.true;

    // Resolve dispute via disputeResolver
    await expect(
      auditRegistry.connect(disputeResolver).resolveDispute(contractHash, 0, false)
    ).to.emit(auditRegistry, "DisputeResolved").withArgs(contractHash, 0, false);

    audit = await auditRegistry.audits(contractHash, 0);
    expect(audit.disputed).to.be.false;
  });
});
