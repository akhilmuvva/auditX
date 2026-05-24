import { generateFortaBot, analyzeDeployedContract } from '../src/forta/index.js';
import { lookupAttestation } from '../src/pipeline.js';
import { describe, it, expect, jest } from '@jest/globals';

// Mock the public GraphQL API requests to ensure test suite remains fast and local-compliant
jest.mock('graphql-request', () => ({
  request: jest.fn().mockImplementation(async (url: any, query: any, variables: any) => {
    // If querying Scam Detector
    if (variables?.input?.botIds?.includes('0x1d646c4045189991fdfd24a66100422bf1729cf2')) {
      return {
        alerts: {
          alerts: [
            {
              alertId: 'SCAM-1',
              name: 'Address flagged as Scam',
              description: 'Suspicious transaction patterns matching phishing address.',
              severity: 'HIGH',
              createdAt: '2026-05-24T12:00:00Z',
              source: { bot: { id: '0x1d646c4045189991fdfd24a66100422bf1729cf2', name: 'Scam Detector' } },
              addresses: [variables.input.addresses[0]],
              metadata: {}
            }
          ]
        }
      };
    }

    // Default mock alerts
    return {
      alerts: {
        alerts: [
          {
            alertId: 'CRITICAL-1',
            name: 'Reentrancy Threat Alert',
            description: 'Recursive withdraw calls detected in tx.',
            severity: 'CRITICAL',
            createdAt: '2026-05-24T12:10:00Z',
            source: { bot: { id: '0xreentrancy', name: 'Reentrancy Monitor' } },
            addresses: [variables.input.addresses[0]],
            metadata: {}
          }
        ]
      }
    };
  }),
  gql: (strs: string[]) => strs[0]
}));

// Mock the subgraph query
jest.mock('../src/storage/theGraph.js', () => ({
  queryAuditsByContract: jest.fn().mockImplementation(async (hash: any) => {
    if (hash === '0xexisting') {
      return [{
        id: '0xeasuid123',
        auditor: '0xauditor',
        ipfsCID: 'QmCachedCid',
        cvssScore: 85,
        riskLevel: 'high',
        blockTimestamp: 1779378169
      }];
    }
    return [];
  })
}));

describe('Forta Lifecycle Security Integration', () => {
  describe('Forta Bot Auto-Generation', () => {
    it('should generate a reentrancy bot if a reentrancy finding exists', async () => {
      const findings = [
        { title: 'Reentrancy ETH vulnerability detected', severity: 'CRITICAL', tool: 'Slither' }
      ];
      
      const bot = await generateFortaBot(findings, '0xDe30da3929db217e65B17B45bcE1bB8206d2E30d', 'Vault');
      
      expect(bot).not.toBeNull();
      expect(bot!.botName).toBe('AuditX Monitor — Vault');
      expect(bot!.rules.length).toBeGreaterThanOrEqual(1);
      expect(bot!.rules[0].ruleId).toBe('REENTRANCY-WATCH-001');
      expect(bot!.sourceCode).toContain('Potential Reentrancy Attack Detected');
    });

    it('should fallback to drain template if other high severity findings exist without custom mapping', async () => {
      const findings = [
        { title: 'Unprotected selfdestruct call in function', severity: 'HIGH', tool: 'Mythril' }
      ];

      const bot = await generateFortaBot(findings, '0xDe30da3929db217e65B17B45bcE1bB8206d2E30d', 'Vault');
      expect(bot).not.toBeNull();
      expect(bot!.sourceCode).toContain('Drain Monitor');
      expect(bot!.rules[0].ruleId).toBe('DRAIN-WATCH-001');
    });
  });

  describe('Post-Deploy threat intelligence analysis', () => {
    it('should fetch contract alerts, scam checks and aggregate dynamic riskScore', async () => {
      const result = await analyzeDeployedContract('0xDe30da3929db217e65B17B45bcE1bB8206d2E30d', 1);

      expect(result.overallRisk).toBe('HIGH');
      expect(result.status.totalAlerts).toBe(1);
      expect(result.status.riskScore).toBe(75); // Critical alert (25) + Scam Detector flag (50)
      expect(result.scamCheck.isScammer).toBe(true);
      expect(result.communityAlerts.length).toBe(1);
    });
  });

  describe('EAS Attestation Caching Check', () => {
    it('should resolve a cached audit record if attestation exists in subgraph', async () => {
      const existing = await lookupAttestation('0xexisting');
      expect(existing).not.toBeNull();
      expect(existing!.id).toBe('0xeasuid123');
      expect(existing!.ipfsCID).toBe('QmCachedCid');
    });

    it('should return null if no attestation exists in subgraph for the given contract hash', async () => {
      const existing = await lookupAttestation('0xnewhash');
      expect(existing).toBeNull();
    });
  });
});
