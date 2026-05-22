import hre from "hardhat";
const { ethers } = hre;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying AuditX Network contracts with account:", deployer.address);

  // 1. AuditBadgeNFT
  const Badge = await ethers.getContractFactory("AuditBadgeNFT");
  const badge = await Badge.deploy();
  await badge.waitForDeployment();
  const badgeAddress = await badge.getAddress();
  console.log("AuditBadgeNFT deployed to:", badgeAddress);

  // 2. AgentRegistry (with treasury = deployer for now)
  const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
  const agentRegistry = await AgentRegistry.deploy(deployer.address);
  await agentRegistry.waitForDeployment();
  const agentRegistryAddress = await agentRegistry.getAddress();
  console.log("AgentRegistry deployed to:", agentRegistryAddress);

  // 3. DisputeResolver
  const DisputeResolver = await ethers.getContractFactory("DisputeResolver");
  // Temporary circular dependency workaround: AuditRegistry needs DisputeResolver, DisputeResolver needs AuditRegistry.
  // We will deploy DisputeResolver with dummy AuditRegistry address, then set it later if possible, 
  // or deploy AuditRegistry first.
  
  // Deploy AuditRegistry first (with dummy dispute resolver)
  const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
  const auditRegistry = await AuditRegistry.deploy(agentRegistryAddress, ethers.ZeroAddress);
  await auditRegistry.waitForDeployment();
  const auditRegistryAddress = await auditRegistry.getAddress();
  console.log("AuditRegistry deployed to:", auditRegistryAddress);

  // Now deploy DisputeResolver
  const disputeResolver = await DisputeResolver.deploy(agentRegistryAddress, auditRegistryAddress);
  await disputeResolver.waitForDeployment();
  const disputeResolverAddress = await disputeResolver.getAddress();
  console.log("DisputeResolver deployed to:", disputeResolverAddress);

  // Set DisputeResolver in AuditRegistry
  await auditRegistry.setDisputeResolver(disputeResolverAddress);
  console.log("Linked DisputeResolver to AuditRegistry.");

  // Grant DISPUTE_RESOLVER_ROLE in AgentRegistry to DisputeResolver
  const DISPUTE_RESOLVER_ROLE = await agentRegistry.DISPUTE_RESOLVER_ROLE();
  await agentRegistry.grantRole(DISPUTE_RESOLVER_ROLE, disputeResolverAddress);
  console.log("Granted DISPUTE_RESOLVER_ROLE to DisputeResolver.");

  // 4. StakeManager
  // We need an AuditXToken. For now, deploy a dummy ERC20 if needed, or use zero address.
  // Assuming StakeManager handles sAUDITX natively.
  const StakeManager = await ethers.getContractFactory("StakeManager");
  const stakeManager = await StakeManager.deploy(agentRegistryAddress, ethers.ZeroAddress); // Dummy token address
  await stakeManager.waitForDeployment();
  console.log("StakeManager deployed to:", await stakeManager.getAddress());

  // 5. ResumeRegistry
  // Needs a dummy ZK verifier for now
  const ResumeRegistry = await ethers.getContractFactory("ResumeRegistry");
  const resumeRegistry = await ResumeRegistry.deploy(ethers.ZeroAddress, 75); // 75 threshold
  await resumeRegistry.waitForDeployment();
  console.log("ResumeRegistry deployed to:", await resumeRegistry.getAddress());

  console.log("All contracts deployed successfully!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
