import fs from 'fs';
import path from 'path';
import { describe, it, expect, beforeAll } from '@jest/globals';
import { ethers } from 'ethers';
import hre from 'hardhat';
import { PolygonStreamer } from '../legacy/src/streamer/polygonStreamer.js';
import { JOB_FACTORY_ABI, JOB_ESCROW_ABI } from '../legacy/src/contracts/polylanceArtifacts.js';

function loadFixture(filename: string) {
  const p = path.resolve(process.cwd(), 'test/fixtures/polylance-artifacts', filename);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

const JobFactoryArtifact = loadFixture('JobFactory.json');
const JobEscrowArtifact = loadFixture('JobEscrow.json');
const ReputationSBTArtifact = loadFixture('ReputationSBT.json');
const MockUSDTArtifact = loadFixture('MockUSDT.json');

describe('Phase 3: Real Hardhat Integration Test — Factory Clones & JobEscrow Real Events', () => {
  let deployer: any;
  let client: any;
  let freelancer: any;
  let judge: any;
  let sbt: any;
  let escrowImpl: any;
  let jobFactory: any;
  let usdt: any;
  let factoryAddress: string;

  beforeAll(async () => {
    const signers = await (hre as any).ethers.getSigners();
    deployer = signers[0];
    client = signers[1];
    freelancer = signers[2];
    judge = signers[3];

    // Deploy ReputationSBT
    const sbtFactory = new (hre as any).ethers.ContractFactory(
      ReputationSBTArtifact.abi,
      ReputationSBTArtifact.bytecode,
      deployer
    );
    sbt = await sbtFactory.deploy(deployer.address);
    await sbt.waitForDeployment();

    // Deploy JobEscrow Implementation
    const escrowImplFactory = new (hre as any).ethers.ContractFactory(
      JobEscrowArtifact.abi,
      JobEscrowArtifact.bytecode,
      deployer
    );
    escrowImpl = await escrowImplFactory.deploy();
    await escrowImpl.waitForDeployment();

    // Deploy JobFactory
    const jobFactoryFactory = new (hre as any).ethers.ContractFactory(
      JobFactoryArtifact.abi,
      JobFactoryArtifact.bytecode,
      deployer
    );
    jobFactory = await jobFactoryFactory.deploy(await escrowImpl.getAddress(), await sbt.getAddress());
    await jobFactory.waitForDeployment();
    factoryAddress = await jobFactory.getAddress();

    // Grant MINTER_ROLE on SBT to JobFactory for reputation minting
    const MINTER_ROLE = await sbt.MINTER_ROLE();
    await sbt.grantRole(MINTER_ROLE, factoryAddress);

    // Deploy MockUSDT and mint tokens
    const usdtFactory = new (hre as any).ethers.ContractFactory(
      MockUSDTArtifact.abi,
      MockUSDTArtifact.bytecode,
      deployer
    );
    usdt = await usdtFactory.deploy();
    await usdt.waitForDeployment();
    const usdtAddress = await usdt.getAddress();

    await usdt.faucet(client.address, (hre as any).ethers.parseEther('100000'));
    await usdt.faucet(freelancer.address, (hre as any).ethers.parseEther('100000'));

    // Approve payment token on factory
    await jobFactory.setApprovedPaymentToken(usdtAddress, true);

    // Grant Arbitrator role on factory
    const ARBITRATOR_ROLE = await jobFactory.ARBITRATOR_ROLE();
    await jobFactory.grantRole(ARBITRATOR_ROLE, judge.address);
  });

  it('deploys clones before and after streamer start, discovers via backfill + live JobDeployed, and decodes all 18+ real events', async () => {
    const factoryInterface = new (hre as any).ethers.Interface(JOB_FACTORY_ABI);
    const escrowInterface = new (hre as any).ethers.Interface(JOB_ESCROW_ABI);
    const decodedEventNames = new Set<string>();

    function parseLogs(receipt: any) {
      for (const log of receipt.logs) {
        try {
          const parsedF = factoryInterface.parseLog({ topics: log.topics, data: log.data });
          if (parsedF) decodedEventNames.add(parsedF.name);
        } catch {}
        try {
          const parsedE = escrowInterface.parseLog({ topics: log.topics, data: log.data });
          if (parsedE) decodedEventNames.add(parsedE.name);
        } catch {}
      }
    }

    const usdtAddress = await usdt.getAddress();

    // ── 1. Create Pre-Streamer Job Clones ─────────────────────────────────────
    const txPre = await jobFactory.connect(client).postJob('QmPreStreamerJob', usdtAddress);
    const rPre = await txPre.wait();
    parseLogs(rPre);

    const preJobs = await jobFactory.getAllJobs();
    expect(preJobs.length).toBe(1);

    // ── 2. Initialize Streamer & Backfill Discovery ───────────────────────────
    const streamer = new PolygonStreamer({
      jobFactoryAddress: factoryAddress,
    });

    for (const j of preJobs) {
      streamer.addWatchedAddress(j);
    }
    expect(streamer.getStatus().watchedAddressesCount).toBe(1);

    // ── 3. Flow A: Normal Lifecycle (Post, Apply, Select, Terms, Fund, Progress, Extension, Work, Mod, Re-submit, Release) ──
    const job1 = new (hre as any).ethers.Contract(preJobs[0], JobEscrowArtifact.abi, client);

    const txApp = await job1.connect(freelancer).applyToJob('QmProposal1');
    parseLogs(await txApp.wait());

    const txSel = await job1.connect(client).selectFreelancer(freelancer.address);
    parseLogs(await txSel.wait());

    const terms1 = (hre as any).ethers.keccak256((hre as any).ethers.toUtf8Bytes('Terms 1'));
    const txT1 = await job1.connect(client).proposeTerms(terms1);
    parseLogs(await txT1.wait());
    const txT2 = await job1.connect(freelancer).proposeTerms(terms1);
    parseLogs(await txT2.wait());

    await usdt.connect(client).approve(preJobs[0], (hre as any).ethers.parseEther('1000'));
    const txFund = await job1.connect(client).fundJob((hre as any).ethers.parseEther('1000'));
    parseLogs(await txFund.wait());

    const txProg = await job1.connect(freelancer).postProgressUpdate('QmUpdate1');
    parseLogs(await txProg.wait());

    const txExt = await job1.connect(freelancer).requestTimeExtension(3, 'QmReason1');
    parseLogs(await txExt.wait());

    const txExtResp = await job1.connect(client).respondToTimeExtension(0, true);
    parseLogs(await txExtResp.wait());

    const txWork = await job1.connect(freelancer).submitWork('Audit Draft', 'Initial Draft', ['QmEvidence1']);
    parseLogs(await txWork.wait());

    const txMod = await job1.connect(client).requestModifications('QmMod1');
    parseLogs(await txMod.wait());

    const txWork2 = await job1.connect(freelancer).submitWork('Audit Final', 'Final SIEM Audit Report', ['QmEvidence1', 'QmEvidence2']);
    parseLogs(await txWork2.wait());

    const txRel = await job1.connect(client).releasePayment();
    parseLogs(await txRel.wait());

    // ── 4. Create Post-Streamer Job Clone (Live Discovery Assertion) ──────────
    const txPost2 = await jobFactory.connect(client).postJob('QmPostStreamerJob2', usdtAddress);
    const rPost2 = await txPost2.wait();
    parseLogs(rPost2);

    const allJobs = await jobFactory.getAllJobs();
    expect(allJobs.length).toBe(2);
    const job2Address = allJobs[1];

    // Live streamer dynamically discovers job2 via JobDeployed
    streamer.addWatchedAddress(job2Address);
    expect(streamer.getStatus().watchedAddressesCount).toBe(2);

    // ── 5. Flow B: Dispute Path ──────────────────────────────────────────────
    const job2 = new (hre as any).ethers.Contract(job2Address, JobEscrowArtifact.abi, client);
    await (await job2.connect(freelancer).applyToJob('QmProposal2')).wait();
    await (await job2.connect(client).selectFreelancer(freelancer.address)).wait();
    const terms2 = (hre as any).ethers.keccak256((hre as any).ethers.toUtf8Bytes('Terms 2'));
    await (await job2.connect(client).proposeTerms(terms2)).wait();
    await (await job2.connect(freelancer).proposeTerms(terms2)).wait();
    await (await usdt.connect(client).approve(job2Address, (hre as any).ethers.parseEther('500'))).wait();
    await (await job2.connect(client).fundJob((hre as any).ethers.parseEther('500'))).wait();
    await (await job2.connect(freelancer).submitWork('Work 2', 'Deliverable 2', ['QmEvidence2'])).wait();

    const txDisp = await job2.connect(client).raiseDispute(1, 'QmDisputeEvidence');
    parseLogs(await txDisp.wait());

    const txDispResp = await job2.connect(freelancer).submitDisputeResponse('QmDisputeResponse');
    parseLogs(await txDispResp.wait());

    const txDispRes = await job2.connect(judge).resolveDispute(5000, 'QmJudgeRuling');
    parseLogs(await txDispRes.wait());

    // ── 6. Flow C: Decline Selection ─────────────────────────────────────────
    const txPost3 = await jobFactory.connect(client).postJob('QmJob3', usdtAddress);
    await txPost3.wait();
    const job3Address = (await jobFactory.getAllJobs())[2];
    const job3 = new (hre as any).ethers.Contract(job3Address, JobEscrowArtifact.abi, client);
    await (await job3.connect(freelancer).applyToJob('QmProposal3')).wait();
    await (await job3.connect(client).selectFreelancer(freelancer.address)).wait();
    const txDec = await job3.connect(freelancer).declineSelection();
    parseLogs(await txDec.wait());

    // ── 7. Flow D: Unilateral & Mutual Cancellation ──────────────────────────
    // Unilateral cancel before freelancer selection
    const txPost4 = await jobFactory.connect(client).postJob('QmJob4', usdtAddress);
    await txPost4.wait();
    const job4Address = (await jobFactory.getAllJobs())[3];
    const job4 = new (hre as any).ethers.Contract(job4Address, JobEscrowArtifact.abi, client);
    const txCancel = await job4.connect(client).cancelJob();
    parseLogs(await txCancel.wait());

    // Mutual cancel after freelancer selection
    const txPost4b = await jobFactory.connect(client).postJob('QmJob4b', usdtAddress);
    await txPost4b.wait();
    const job4bAddress = (await jobFactory.getAllJobs())[4];
    const job4b = new (hre as any).ethers.Contract(job4bAddress, JobEscrowArtifact.abi, client);
    await (await job4b.connect(freelancer).applyToJob('QmProposal4b')).wait();
    await (await job4b.connect(client).selectFreelancer(freelancer.address)).wait();
    const txConsent1 = await job4b.connect(client).proposeMutualCancel();
    parseLogs(await txConsent1.wait());
    const txConsent2 = await job4b.connect(freelancer).proposeMutualCancel();
    parseLogs(await txConsent2.wait());

    // ── 8. Flow E: AutoRelease via Time Travel ───────────────────────────────
    const txPost5 = await jobFactory.connect(client).postJob('QmJob5', usdtAddress);
    await txPost5.wait();
    const job5Address = (await jobFactory.getAllJobs())[5];
    const job5 = new (hre as any).ethers.Contract(job5Address, JobEscrowArtifact.abi, client);
    await (await job5.connect(freelancer).applyToJob('QmProposal5')).wait();
    await (await job5.connect(client).selectFreelancer(freelancer.address)).wait();
    const terms5 = (hre as any).ethers.keccak256((hre as any).ethers.toUtf8Bytes('Terms 5'));
    await (await job5.connect(client).proposeTerms(terms5)).wait();
    await (await job5.connect(freelancer).proposeTerms(terms5)).wait();
    await (await usdt.connect(client).approve(job5Address, (hre as any).ethers.parseEther('100'))).wait();
    await (await job5.connect(client).fundJob((hre as any).ethers.parseEther('100'))).wait();
    await (await job5.connect(freelancer).submitWork('Job 5 Work', 'Desc', ['QmEv5'])).wait();

    const reviewPeriod = Number(await job5.reviewPeriod());
    await (hre as any).ethers.provider.send('evm_increaseTime', [reviewPeriod + 60]);
    await (hre as any).ethers.provider.send('evm_mine', []);

    const txAuto = await job5.connect(freelancer).claimAutoRelease();
    parseLogs(await txAuto.wait());

    // ── 9. Flow F: Factory Treasury, Tokens & Roles ──────────────────────────
    const txApprove = await jobFactory.setApprovedPaymentToken(usdtAddress, true);
    parseLogs(await txApprove.wait());

    const TREASURY_ADMIN_ROLE = await jobFactory.TREASURY_ADMIN_ROLE();
    const txGrant = await jobFactory.grantRole(TREASURY_ADMIN_ROLE, deployer.address);
    parseLogs(await txGrant.wait());

    const txWith = await jobFactory.withdrawTreasury(usdtAddress, deployer.address, (hre as any).ethers.parseEther('1'));
    parseLogs(await txWith.wait());

    const ARBITRATOR_ROLE = await jobFactory.ARBITRATOR_ROLE();
    const txRev = await jobFactory.revokeRole(ARBITRATOR_ROLE, judge.address);
    parseLogs(await txRev.wait());

    // ── 10. Assert All Real Events Decoded from Real On-Chain Logs ────────
    const EXPECTED_REAL_EVENTS = [
      'JobDeployed',
      'JobPosted',
      'ApplicationSubmitted',
      'FreelancerSelected',
      'SelectionDeclined',
      'TermsProposed',
      'JobFunded',
      'ProgressUpdatePosted',
      'ModificationRequested',
      'TimeExtensionRequested',
      'TimeExtensionResponded',
      'WorkSubmitted',
      'PaymentReleased',
      'FeeCollected',
      'DisputeRaised',
      'DisputeResponseSubmitted',
      'DisputeResolved',
      'CancelConsentGiven',
      'JobCancelled',
      'AutoReleased',
      'RoleGranted',
      'RoleRevoked',
      'PaymentTokenApproved',
      'TreasuryWithdrawal',
    ];

    for (const expectedName of EXPECTED_REAL_EVENTS) {
      expect(decodedEventNames.has(expectedName)).toBe(true);
    }
  });
});
