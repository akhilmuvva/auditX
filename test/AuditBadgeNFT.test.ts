import { expect } from "chai";
import pkg from "hardhat";
const { ethers } = pkg;
import { Contract } from "ethers";

describe("AuditBadgeNFT", function () {
  let nft: any;
  let owner: any;
  let addr1: any;
  let agent: any;

  beforeEach(async function () {
    [owner, addr1, agent] = await ethers.getSigners();
    const BadgeFactory = await ethers.getContractFactory("AuditBadgeNFT");
    nft = await BadgeFactory.deploy();
  });

  it("Should have correct name and symbol", async function () {
    expect(await nft.name()).to.equal("AuditX Security Badge");
    expect(await nft.symbol()).to.equal("AUDITX");
  });

  it("Should allow owner to set authorized agent", async function () {
    await nft.setAuthorizedAgent(agent.address);
    expect(await nft.authorizedAgent()).to.equal(agent.address);
  });

  it("Should prevent non-agent from minting", async function () {
    await expect(
      nft.connect(addr1).mintBadge(addr1.address, "Vault", 10, "ipfs://hash")
    ).to.be.revertedWith("Only authorized agent allowed");
  });

  it("Should mint badge safely to recipient via agent", async function () {
    await nft.setAuthorizedAgent(agent.address);
    const tx = await nft.connect(agent).mintBadge(addr1.address, "Vault.sol", 0, "ipfs123");
    
    const receipt = await tx.wait();
    expect(await nft.ownerOf(1)).to.equal(addr1.address);
    expect(await nft.balanceOf(addr1.address)).to.equal(1);
  });

  it("Should revert if severity score is too high", async function () {
    await expect(
      nft.mintBadge(addr1.address, "Danger", 75, "ipfsHash")
    ).to.be.revertedWith("Severity too high for security badge");
  });

  it("Should generate valid base64 JSON metadata for EMERALD GUARD", async function () {
    await nft.mintBadge(addr1.address, "SafeContract", 15, "ipfsABC");
    const uri = await nft.tokenURI(1);
    
    expect(uri).to.include("data:application/json;base64,");
    
    const base64Part = uri.split(",")[1];
    const jsonStr = Buffer.from(base64Part, 'base64').toString('utf-8');
    const json = JSON.parse(jsonStr);

    expect(json.name).to.equal("AuditX Certificate #1");
    
    const gradeTrait = json.attributes.find((a: any) => a.trait_type === "Grade");
    expect(gradeTrait.value).to.equal("EMERALD GUARD");
  });

  it("Should generate valid base64 JSON metadata for AMBER GUARD", async function () {
    await nft.mintBadge(addr1.address, "WarnContract", 45, "ipfsABC");
    const uri = await nft.tokenURI(1);
    
    const base64Part = uri.split(",")[1];
    const jsonStr = Buffer.from(base64Part, 'base64').toString('utf-8');
    const json = JSON.parse(jsonStr);

    const gradeTrait = json.attributes.find((a: any) => a.trait_type === "Grade");
    expect(gradeTrait.value).to.equal("AMBER GUARD");
  });
});
