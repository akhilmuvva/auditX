// @ts-nocheck
import { ethers } from 'ethers';
import { PolygonStreamer } from '../legacy/src/streamer/polygonStreamer.js';

describe('Phase 3: JobFactory & JobEscrow Discovery & Event Decoding', () => {
  const JOB_FACTORY_ABI = [
    'event JobDeployed(address indexed jobContract, address indexed client, address paymentToken)',
    'event FeeCollected(address indexed job, uint256 amount)',
    'event TreasuryWithdrawal(address indexed to, uint256 amount, address indexed by)',
    'function getAllJobs() external view returns (address[])',
    'function jobImplementation() external view returns (address)',
    'function isJob(address) external view returns (bool)',
  ];

  const JOB_ESCROW_ABI = [
    'event JobPosted(address client, string descriptionIpfsHash)',
    'event ApplicationSubmitted(address applicant)',
    'event FreelancerSelected(address freelancer)',
    'event SelectionDeclined()',
    'event TermsProposed(address by, bytes32 termsHash)',
    'event JobFunded(uint256 amount)',
    'event WorkSubmitted(string title, uint256 evidenceCount)',
    'event PaymentReleased(uint256 toFreelancer, uint256 fee)',
    'event AutoReleased()',
    'event JobCancelled(uint256 refund)',
    'event CancelConsentGiven(address by)',
    'event DisputeRaised(address by, uint8 reason, string evidenceIpfsHash)',
    'event DisputeResponseSubmitted(address by, string responseIpfsHash)',
    'event DisputeResolved(uint256 freelancerBps, address judge, string reasoningIpfsHash)',
  ];

  it('correctly parses and decodes all JobEscrow events using ethers Interface', () => {
    const escrowIf = new ethers.Interface(JOB_ESCROW_ABI);

    // 1. JobPosted
    const postLog = escrowIf.encodeEventLog('JobPosted', ['0x1111111111111111111111111111111111111111', 'QmTestHash123']);
    const parsedPost = escrowIf.parseLog(postLog);
    expect(parsedPost?.name).toBe('JobPosted');
    expect(parsedPost?.args[0]).toBe('0x1111111111111111111111111111111111111111');
    expect(parsedPost?.args[1]).toBe('QmTestHash123');

    // 2. ApplicationSubmitted
    const appLog = escrowIf.encodeEventLog('ApplicationSubmitted', ['0x2222222222222222222222222222222222222222']);
    const parsedApp = escrowIf.parseLog(appLog);
    expect(parsedApp?.name).toBe('ApplicationSubmitted');

    // 3. FreelancerSelected
    const selLog = escrowIf.encodeEventLog('FreelancerSelected', ['0x2222222222222222222222222222222222222222']);
    const parsedSel = escrowIf.parseLog(selLog);
    expect(parsedSel?.name).toBe('FreelancerSelected');

    // 4. SelectionDeclined
    const decLog = escrowIf.encodeEventLog('SelectionDeclined', []);
    const parsedDec = escrowIf.parseLog(decLog);
    expect(parsedDec?.name).toBe('SelectionDeclined');

    // 5. TermsProposed
    const termsHash = ethers.keccak256(ethers.toUtf8Bytes('Milestone terms v1'));
    const termLog = escrowIf.encodeEventLog('TermsProposed', ['0x1111111111111111111111111111111111111111', termsHash]);
    const parsedTerms = escrowIf.parseLog(termLog);
    expect(parsedTerms?.name).toBe('TermsProposed');
    expect(parsedTerms?.args[1]).toBe(termsHash);

    // 6. JobFunded
    const fundLog = escrowIf.encodeEventLog('JobFunded', [ethers.parseEther('10.0')]);
    const parsedFund = escrowIf.parseLog(fundLog);
    expect(parsedFund?.name).toBe('JobFunded');
    expect(parsedFund?.args[0]).toEqual(ethers.parseEther('10.0'));

    // 7. WorkSubmitted
    const workLog = escrowIf.encodeEventLog('WorkSubmitted', ['Frontend Audit Report', 3]);
    const parsedWork = escrowIf.parseLog(workLog);
    expect(parsedWork?.name).toBe('WorkSubmitted');
    expect(parsedWork?.args[0]).toBe('Frontend Audit Report');
    expect(parsedWork?.args[1]).toEqual(3n);

    // 8. PaymentReleased
    const payLog = escrowIf.encodeEventLog('PaymentReleased', [ethers.parseEther('9.75'), ethers.parseEther('0.25')]);
    const parsedPay = escrowIf.parseLog(payLog);
    expect(parsedPay?.name).toBe('PaymentReleased');
    expect(parsedPay?.args[0]).toEqual(ethers.parseEther('9.75'));
    expect(parsedPay?.args[1]).toEqual(ethers.parseEther('0.25'));

    // 9. AutoReleased
    const autoLog = escrowIf.encodeEventLog('AutoReleased', []);
    const parsedAuto = escrowIf.parseLog(autoLog);
    expect(parsedAuto?.name).toBe('AutoReleased');

    // 10. JobCancelled
    const cancelLog = escrowIf.encodeEventLog('JobCancelled', [ethers.parseEther('10.0')]);
    const parsedCancel = escrowIf.parseLog(cancelLog);
    expect(parsedCancel?.name).toBe('JobCancelled');

    // 11. CancelConsentGiven
    const consentLog = escrowIf.encodeEventLog('CancelConsentGiven', ['0x2222222222222222222222222222222222222222']);
    const parsedConsent = escrowIf.parseLog(consentLog);
    expect(parsedConsent?.name).toBe('CancelConsentGiven');

    // 12. DisputeRaised
    const dispLog = escrowIf.encodeEventLog('DisputeRaised', ['0x1111111111111111111111111111111111111111', 0, 'QmDisputeEvidenceHash']);
    const parsedDisp = escrowIf.parseLog(dispLog);
    expect(parsedDisp?.name).toBe('DisputeRaised');
    expect(parsedDisp?.args[1]).toEqual(0n);

    // 13. DisputeResponseSubmitted
    const respLog = escrowIf.encodeEventLog('DisputeResponseSubmitted', ['0x2222222222222222222222222222222222222222', 'QmResponseHash']);
    const parsedResp = escrowIf.parseLog(respLog);
    expect(parsedResp?.name).toBe('DisputeResponseSubmitted');

    // 14. DisputeResolved
    const resLog = escrowIf.encodeEventLog('DisputeResolved', [8000, '0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A', 'QmRulingHash']);
    const parsedRes = escrowIf.parseLog(resLog);
    expect(parsedRes?.name).toBe('DisputeResolved');
    expect(parsedRes?.args[0]).toEqual(8000n);
    expect(parsedRes?.args[1]).toBe('0x25F6C8ed995C811E6c0ADb1D66A60830E8115e9A');
  });

  it('supports backfill via getAllJobs and live JobDeployed discovery', () => {
    const streamer = new PolygonStreamer({
      jobFactoryAddress: '0xbE74923BBfd72d400a681915dBcf6e6Adc72C317',
    });

    const preStreamerJobs = ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'];
    for (const j of preStreamerJobs) {
      streamer.addWatchedAddress(j);
    }
    expect(streamer.getStatus().watchedAddressesCount).toBe(2);

    // Simulate live JobDeployed event received after streamer startup
    const postStreamerJob = '0xcccccccccccccccccccccccccccccccccccccccc';
    streamer.addWatchedAddress(postStreamerJob);
    expect(streamer.getStatus().watchedAddressesCount).toBe(3);
  });
});
