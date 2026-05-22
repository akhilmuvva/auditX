import { expect } from "chai";
import pkg from "hardhat";
const { ethers } = pkg;

describe("ResumeRegistry", function () {
  let resumeRegistry: any;
  let owner: any;
  let user1: any;
  let verifierMock: any;

  beforeEach(async function () {
    [owner, user1] = await ethers.getSigners();
    
    // Deploy a mock verifier that always returns true
    const MockVerifier = await ethers.getContractFactory("MockVerifier");
    verifierMock = await MockVerifier.deploy();
    await verifierMock.waitForDeployment();

    const ResumeRegistry = await ethers.getContractFactory("ResumeRegistry");
    resumeRegistry = await ResumeRegistry.deploy(await verifierMock.getAddress(), 75);
    await resumeRegistry.waitForDeployment();
  });

  it("Should accept valid proof with qualified and threshold passed", async function () {
    const pA = [0, 0];
    const pB = [[0, 0], [0, 0]];
    const pC = [0, 0];
    const pubSignals = [1, 80, 12345]; // [isQualified, score, studentIdHash]

    await expect(
      resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1")
    ).to.emit(resumeRegistry, "ProofVerified");
  });

  it("Should reject if not qualified (VULN-2)", async function () {
    const pA = [0, 0];
    const pB = [[0, 0], [0, 0]];
    const pC = [0, 0];
    const pubSignals = [0, 80, 12345]; // isQualified = 0

    await expect(
      resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1")
    ).to.be.revertedWith("Not qualified");
  });

  it("Should reject if below threshold (VULN-3)", async function () {
    const pA = [0, 0];
    const pB = [[0, 0], [0, 0]];
    const pC = [0, 0];
    const pubSignals = [1, 70, 12345]; // score 70 < 75

    await expect(
      resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1")
    ).to.be.revertedWith("Below threshold");
  });

  it("Should prevent replay attacks on same job (VULN-1/4)", async function () {
    const pA = [0, 0];
    const pB = [[0, 0], [0, 0]];
    const pC = [0, 0];
    const pubSignals = [1, 80, 12345];

    await resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1");

    await expect(
      resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1")
    ).to.be.revertedWith("Proof already used");
  });

  it("Should allow same proof for different job", async function () {
    const pA = [0, 0];
    const pB = [[0, 0], [0, 0]];
    const pC = [0, 0];
    const pubSignals = [1, 80, 12345];

    await resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-1");
    await expect(
      resumeRegistry.connect(user1).submitProof(pA, pB, pC, pubSignals, "job-2")
    ).to.emit(resumeRegistry, "ProofVerified");
  });

  it("Should enforce 48h timelock on verifier upgrades (VULN-5)", async function () {
    const newVerifier = ethers.Wallet.createRandom().address;
    await resumeRegistry.proposeVerifierUpdate(newVerifier);

    await expect(
      resumeRegistry.executeVerifierUpdate()
    ).to.be.revertedWith("Timelock not expired");

    await ethers.provider.send("evm_increaseTime", [48 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    await resumeRegistry.executeVerifierUpdate();
    expect(await resumeRegistry.verifier()).to.equal(newVerifier);
  });
});
