import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

const REPORTS_CACHE_DIR = path.join(process.cwd(), '..', 'reports-cache');

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const reportId = id.toLowerCase();

  // 1. Check for Demo Scenarios
  if (reportId === 'clean') {
    return NextResponse.json({
      project_name: 'Clean Demo Portal',
      audit_date: new Date().toISOString(),
      web3_cvss: 1.8,
      web2_cvss: 0.0,
      combined_cvss: 1.8,
      web3_findings: [
        {
          id: 'web3-custom-gas-opt-1',
          tool: 'custom',
          swc_id: null,
          severity: 'Low',
          cvss: 1.8,
          title: 'Gas Optimization: public vs external',
          description: 'State read functions can be declared external to reduce deployment gas.',
          file: 'SecureEscrow.sol',
          line: 12,
          remediation: 'Change public visibility to external for read-only view calls.'
        }
      ],
      web2_findings: [],
      secret_findings: [],
      dependency_findings: [],
      attack_chains: [],
      total_critical: 0,
      total_high: 0,
      total_medium: 0,
      total_low: 1,
      ipfs_cid: 'QmCleanDemoIPFSHash998877',
      eas_attestation: '0xee9988cc77ffaa',
      badge_token_id: 42,
      pipeline_duration_ms: 1500
    });
  }

  if (reportId === 'reentrancy') {
    return NextResponse.json({
      project_name: 'Vulnerable Staking Pool',
      audit_date: new Date().toISOString(),
      web3_cvss: 8.5,
      web2_cvss: 0.0,
      combined_cvss: 8.5,
      web3_findings: [
        {
          id: 'web3-slither-reentrancy-1',
          tool: 'slither',
          swc_id: 'SWC-107',
          severity: 'High',
          cvss: 8.5,
          title: 'Reentrancy vulnerability',
          description: 'Unchecked call sends ether to recipient before resolving internal state balance updates.',
          file: 'VulnerableVault.sol',
          line: 42,
          remediation: 'Update balances before executing transfer calls (checks-effects-interactions pattern).'
        }
      ],
      web2_findings: [],
      secret_findings: [],
      dependency_findings: [],
      attack_chains: [],
      total_critical: 0,
      total_high: 1,
      total_medium: 0,
      total_low: 0,
      ipfs_cid: 'QmReentrancyDemoIPFSHash5544',
      eas_attestation: null,
      badge_token_id: null,
      pipeline_duration_ms: 2200
    });
  }

  if (reportId === 'fullstack') {
    return NextResponse.json({
      project_name: 'Full Stack De-Fi Portal',
      audit_date: new Date().toISOString(),
      web3_cvss: 8.0,
      web2_cvss: 9.8,
      combined_cvss: 9.8,
      web3_findings: [
        {
          id: 'web3-custom-replay-1',
          tool: 'custom',
          swc_id: 'SWC-121',
          severity: 'High',
          cvss: 8.0,
          title: 'Cross-Contract Signature Replay',
          description: 'Missing contract address in signed hashes allows execution replaying.',
          file: 'Escrow.sol',
          line: 90,
          remediation: 'Bind address(this) into signed digest.'
        }
      ],
      web2_findings: [
        {
          id: 'web2-semgrep-cmd-injection-1',
          tool: 'semgrep',
          owasp_id: 'OWASP A03:2021-Injection',
          severity: 'Critical',
          cvss: 9.8,
          title: 'Command Injection in node backend',
          description: 'User input concatenated directly into child_process.exec call.',
          file: 'server.js',
          line: 214,
          remediation: 'Avoid command shell executions, parse parameters cleanly or use safe spawn calls.'
        }
      ],
      secret_findings: [
        {
          description: 'Ethereum Private Key pattern detected',
          file: '.env',
          line: 1,
          commit: null,
          entropy: 4.8
        }
      ],
      dependency_findings: [
        {
          package: 'ethers',
          version: '5.4.0',
          severity: 'High',
          cve: 'CVE-2023-ethers',
          cvss: 7.5,
          fixed_in: '^6.0.0',
          exploit_available: true
        }
      ],
      attack_chains: [
        {
          chain_id: 'CHAIN-01',
          title: 'Web2 Command Injection yields Web3 contract compromise',
          steps: [
            {
              layer: 'Web2',
              finding_ref: 'Command Injection in node backend',
              description: 'Attacker executes code on Node server',
              enables_next: 'Extract private keys stored in server env config'
            },
            {
              layer: 'Web3',
              finding_ref: 'Cross-Contract Signature Replay',
              description: 'Attacker replays administrator signature to drain Escrow',
              enables_next: 'Complete project vault drainage'
            }
          ],
          combined_cvss: 9.8,
          likelihood: 'High',
          web2_remediation: 'Fix the input validation in Node.js backend server.',
          web3_remediation: 'Incorporate address(this) into signature check.'
        }
      ],
      total_critical: 1,
      total_high: 2,
      total_medium: 0,
      total_low: 0,
      ipfs_cid: 'QmFullStackDemoIPFSHash3322',
      eas_attestation: null,
      badge_token_id: null,
      pipeline_duration_ms: 3100
    });
  }

  // 2. Read from local cache if present
  const reportPath = path.join(REPORTS_CACHE_DIR, `${reportId}.json`);
  if (fs.existsSync(reportPath)) {
    try {
      const data = fs.readFileSync(reportPath, 'utf8');
      return NextResponse.json(JSON.parse(data));
    } catch (e: any) {
      return NextResponse.json({ error: 'Failed to read cached report file' }, { status: 500 });
    }
  }

  return NextResponse.json({ error: 'Report not found' }, { status: 404 });
}
