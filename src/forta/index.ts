// Re-export everything needed externally
export {
  getAlertsForContract,
  checkScamDetector,
  getCommunityBotAlerts,
  getContractMonitorStatus,
  FORTA_BOT_IDS
} from './client.js';

export {
  generateFortaBot,
  saveFortaBot
} from './generator.js';

export type {
  FortaAlert,
  GeneratedBot,
  ContractMonitorStatus,
  BotRule,
  FortaQueryOptions
} from './types.js';

import {
  getContractMonitorStatus,
  checkScamDetector,
  getCommunityBotAlerts
} from './client.js';
import type { FortaAlert, ContractMonitorStatus } from './types.js';

// Convenience function: full post-deploy analysis
export async function analyzeDeployedContract(
  contractAddress: string,
  chainId = 1
): Promise<{
  status: ContractMonitorStatus;
  scamCheck: { isScammer: boolean; alertCount: number; latestAlert: FortaAlert | null };
  communityAlerts: FortaAlert[];
  overallRisk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}> {
  const [status, scamCheck, communityAlerts] = await Promise.all([
    getContractMonitorStatus(contractAddress, chainId),
    checkScamDetector(contractAddress),
    getCommunityBotAlerts(contractAddress)
  ]);

  // Calculate overallRisk based on status.riskScore
  let overallRisk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'SAFE';
  const score = status.riskScore;

  if (score > 80) {
    overallRisk = 'CRITICAL';
  } else if (score > 60) {
    overallRisk = 'HIGH';
  } else if (score > 30) {
    overallRisk = 'MEDIUM';
  } else if (score > 10) {
    overallRisk = 'LOW';
  }

  return {
    status,
    scamCheck,
    communityAlerts,
    overallRisk
  };
}
