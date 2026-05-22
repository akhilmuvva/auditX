import { expect } from "chai";
import pkg from "hardhat";
const { ethers } = pkg;

describe("AgentRegistry", function () {
  let agentRegistry: any;
  let owner: any;
  let agent1: any;
  let disputeResolver: any;
  let treasury: any;

  beforeEach(async function () {
    [owner, agent1, disputeResolver, treasury] = await ethers.getSigners();
    
    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await AgentRegistry.deploy(treasury.address);
    await agentRegistry.waitForDeployment();

    const DISPUTE_RESOLVER_ROLE = await agentRegistry.DISPUTE_RESOLVER_ROLE();
    await agentRegistry.grantRole(DISPUTE_RESOLVER_ROLE, disputeResolver.address);
  });

  it("Should allow an agent to register with 0.1 ETH", async function () {
    await agentRegistry.connect(agent1).register({ value: ethers.parseEther("0.1") });
    const agentData = await agentRegistry.agents(agent1.address);
    
    expect(agentData.active).to.be.true;
    expect(agentData.stake).to.equal(ethers.parseEther("0.1"));
    expect(agentData.reputation).to.equal(100);
  });

  it("Should reject registration with insufficient stake", async function () {
    await expect(
      agentRegistry.connect(agent1).register({ value: ethers.parseEther("0.05") })
    ).to.be.revertedWith("Insufficient stake");
  });

  it("Should allow dispute resolver to slash an agent", async function () {
    await agentRegistry.connect(agent1).register({ value: ethers.parseEther("0.1") });
    
    await expect(
      agentRegistry.connect(disputeResolver).slash(agent1.address, ethers.parseEther("0.1"))
    ).to.emit(agentRegistry, "AgentSlashed").withArgs(agent1.address, ethers.parseEther("0.1"));

    const agentData = await agentRegistry.agents(agent1.address);
    expect(agentData.active).to.be.false; // Deactivated due to < 0.1 ETH remaining
    expect(agentData.stake).to.equal(0);
    expect(agentData.reputation).to.equal(90); // 100 - 10
  });

  it("Should allow agent to deregister and withdraw after 7 days", async function () {
    await agentRegistry.connect(agent1).register({ value: ethers.parseEther("0.1") });
    await agentRegistry.connect(agent1).deregister();

    const agentData = await agentRegistry.agents(agent1.address);
    expect(agentData.active).to.be.false;

    // Fast-forward time
    await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    await expect(
      agentRegistry.connect(agent1).withdrawStake()
    ).to.emit(agentRegistry, "StakeWithdrawn").withArgs(agent1.address, ethers.parseEther("0.1"));
  });
});
