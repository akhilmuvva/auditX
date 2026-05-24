import { request, gql } from 'graphql-request';
import type { FortaAlert, FortaQueryOptions, ContractMonitorStatus } from './types.js';

const FORTA_API = 'https://api.forta.network/graphql';

// Known high-value community bot IDs to query by default
export const FORTA_BOT_IDS = {
  SCAM_DETECTOR:     '0x1d646c4045189991fdfd24a66100422bf1729cf2',
  ATTACK_DETECTOR:   '0x80ed808b586aeebe9cdd4088ea4dea0a8e322909',
  FLASH_LOAN:        '0x8badbf2ad65abc3df5a1d9d04d1ff7a4ae004854',
  TORNADO_CASH:      '0x4adff9d0652b965d8d2ea5e05f32f04d7af0e6a',
  RUG_PULL_DETECTOR: '0xc608f1aff80657091ad14d974ea37607f6e7513f',
  EXPLOIT_DETECTOR:  '0x3acf759d7e1f1e5e47b78aa0b5f366b4db7e0e9b',
} as const;

// Get all Forta alerts for a specific contract address
export async function getAlertsForContract(
  contractAddress: string,
  options: FortaQueryOptions = {}
): Promise<FortaAlert[]> {
  console.log(`[Forta] Fetching alerts for ${contractAddress}...`);
  const query = gql`
    query GetAlerts($input: AlertsInput) {
      alerts(input: $input) {
        alerts {
          alertId
          name
          description
          severity
          createdAt
          source {
            bot {
              id
              name
            }
            transactionHash
            block {
              number
              timestamp
              chainId
            }
          }
          addresses
          metadata
        }
      }
    }
  `;

  // Compute 30 days ago as starting date if not specified
  let startDateStr = options.startDate;
  if (!startDateStr) {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    startDateStr = thirtyDaysAgo.toISOString();
  }

  const variables = {
    input: {
      addresses: options.addresses || [contractAddress.toLowerCase()],
      botIds: options.botIds,
      severities: options.severities || ['CRITICAL', 'HIGH', 'MEDIUM'],
      chainIds: options.chainIds,
      createdSince: startDateStr,
      first: options.limit || 50
    }
  };

  try {
    const response = await request<{ alerts: { alerts: FortaAlert[] } }>(FORTA_API, query, variables);
    return response?.alerts?.alerts || [];
  } catch (err: any) {
    console.warn(`[Forta] Alert query failed for ${contractAddress}:`, err.message);
    return [];
  }
}

// Check if a contract is flagged by the Scam Detector bot
export async function checkScamDetector(
  contractAddress: string
): Promise<{ isScammer: boolean; alertCount: number; latestAlert: FortaAlert | null }> {
  try {
    const alerts = await getAlertsForContract(contractAddress, {
      botIds: [FORTA_BOT_IDS.SCAM_DETECTOR],
      severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      limit: 1
    });

    if (alerts && alerts.length > 0) {
      return {
        isScammer: true,
        alertCount: alerts.length,
        latestAlert: alerts[0]
      };
    }
  } catch (err: any) {
    console.warn('[Forta] Scam detector check failed:', err.message);
  }

  return { isScammer: false, alertCount: 0, latestAlert: null };
}

// Get comprehensive monitoring status for a contract
export async function getContractMonitorStatus(
  contractAddress: string,
  chainId = 1
): Promise<ContractMonitorStatus> {
  const [alerts, scamCheck] = await Promise.all([
    getAlertsForContract(contractAddress, { chainIds: [chainId], limit: 100 }),
    checkScamDetector(contractAddress)
  ]);

  const alertsBySeverity: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };

  let lastAlertAt: string | null = null;
  const botIdsSet = new Set<string>();

  for (const alert of alerts) {
    const sev = alert.severity.toUpperCase();
    alertsBySeverity[sev] = (alertsBySeverity[sev] || 0) + 1;
    
    if (alert.source?.bot?.id) {
      botIdsSet.add(alert.source.bot.id);
    }
    
    if (!lastAlertAt || new Date(alert.createdAt) > new Date(lastAlertAt)) {
      lastAlertAt = alert.createdAt;
    }
  }

  // Calculate riskScore (0-100)
  let baseScore = 0;
  baseScore += (alertsBySeverity.CRITICAL || 0) * 25;
  baseScore += (alertsBySeverity.HIGH || 0) * 10;
  baseScore += (alertsBySeverity.MEDIUM || 0) * 5;
  if (scamCheck.isScammer) {
    baseScore += 50;
  }
  const riskScore = Math.min(100, baseScore);

  return {
    contractAddress,
    chainId,
    totalAlerts: alerts.length,
    alertsBySeverity,
    lastAlertAt,
    botIds: Array.from(botIdsSet),
    recentAlerts: alerts.slice(0, 10), // Limit to top 10 recent alerts for UI
    riskScore,
    monitoredSince: Date.now() - 30 * 24 * 60 * 60 * 1000 // Mock: active for 30 days
  };
}

// Query alerts from all known community bots for an address
export async function getCommunityBotAlerts(
  contractAddress: string
): Promise<FortaAlert[]> {
  const alerts = await getAlertsForContract(contractAddress, {
    botIds: Object.values(FORTA_BOT_IDS),
    severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    limit: 50
  });

  return alerts.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}
