import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

let FORTA_ALERTS: any[] = [
  {
    alert_id: 'FORTA-ALERT-892104',
    bot_id: '0x1928a412b590e091024bc',
    bot_name: 'FORTA-REENTRANCY-CALL-DEPTH',
    severity: 'Critical',
    title: 'Reentrancy Threat Flagged by Forta Bot',
    description: 'Forta Bot 0x1928 detected 4 recursive fallback iterations in contract 0x1234567890abcdef1234567890abcdef12345678.',
    contract_address: '0x1234567890abcdef1234567890abcdef12345678',
    tx_hash: '0xa1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
    timestamp: new Date(Date.now() - 1200000).toISOString(),
    protocol: 'EVM Call Depth Watcher',
    confidence_score: 0.96,
    action_suggested: 'Pause contract deposits immediately and enforce nonReentrant guards.'
  },
  {
    alert_id: 'FORTA-ALERT-771920',
    bot_id: '0x429188f91023a12bf0011',
    bot_name: 'FORTA-FLASH-LOAN-LARGE-SWAP',
    severity: 'Critical',
    title: 'Flash Loan Oracle Manipulation Alert',
    description: 'Forta Bot 0x4291 detected 350 ETH flash borrow impacting DEX reserves at 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D.',
    contract_address: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
    tx_hash: '0xf9e8d7c6b5a432109876543210fedcba9876543210fedcba9876543210fedcba',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    protocol: 'DeFi Reserve Health',
    confidence_score: 0.94,
    action_suggested: 'Switch price oracle source to TWAP or Chainlink price feeds.'
  },
  {
    alert_id: 'FORTA-ALERT-551029',
    bot_id: '0x3310f8291048b29103841',
    bot_name: 'FORTA-PERMIT2-SIGNATURE-REPLAY',
    severity: 'High',
    title: 'Permit2 Signature Replay Detected',
    description: 'Replayed permit signature attempted token transfer on contract 0x5FbDB2315678afecb367f032d93F642f64180aa3.',
    contract_address: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    tx_hash: '0x8888888888888888888888888888888888888888888888888888888888888888',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    protocol: 'Signature Guard',
    confidence_score: 0.91,
    action_suggested: 'Invalidate signature nonces and check EIP-712 domain separator.'
  }
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const address = searchParams.get('address');

  let filtered = FORTA_ALERTS;
  if (address) {
    filtered = FORTA_ALERTS.filter(
      (a) => a.contract_address.toLowerCase() === address.toLowerCase()
    );
  }

  return NextResponse.json({
    alerts: filtered,
    total_alerts: FORTA_ALERTS.length,
    active_forta_bots: 5,
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { bot_type, target_address } = body;

    const target = target_address || '0x1234567890abcdef1234567890abcdef12345678';
    const now = new Date().toISOString();
    const randomHash = '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    let alert: any = null;

    switch (bot_type) {
      case 'reentrancy_bot':
        alert = {
          alert_id: `FORTA-ALERT-${Math.floor(Math.random() * 900000 + 100000)}`,
          bot_id: '0x1928a412b590e091024bc',
          bot_name: 'FORTA-REENTRANCY-CALL-DEPTH',
          severity: 'Critical',
          title: 'Reentrancy Threat Flagged by Forta Bot',
          description: `Forta Bot 0x1928 detected 4 recursive fallback iterations in contract ${target} within transaction ${randomHash}.`,
          contract_address: target,
          tx_hash: randomHash,
          timestamp: now,
          protocol: 'EVM Call Depth Watcher',
          confidence_score: 0.96,
          action_suggested: 'Pause contract deposits immediately and enforce nonReentrant guards.'
        };
        break;
      case 'flashloan_bot':
        alert = {
          alert_id: `FORTA-ALERT-${Math.floor(Math.random() * 900000 + 100000)}`,
          bot_id: '0x429188f91023a12bf0011',
          bot_name: 'FORTA-FLASH-LOAN-LARGE-SWAP',
          severity: 'Critical',
          title: 'Flash Loan Oracle Manipulation Alert',
          description: `Forta Bot 0x4291 detected 420 ETH flash borrow impacting reserves at ${target}.`,
          contract_address: target,
          tx_hash: randomHash,
          timestamp: now,
          protocol: 'DeFi Reserve Health',
          confidence_score: 0.94,
          action_suggested: 'Switch price oracle source to TWAP or Chainlink price feeds.'
        };
        break;
      case 'permit2_bot':
        alert = {
          alert_id: `FORTA-ALERT-${Math.floor(Math.random() * 900000 + 100000)}`,
          bot_id: '0x3310f8291048b29103841',
          bot_name: 'FORTA-PERMIT2-SIGNATURE-REPLAY',
          severity: 'High',
          title: 'Permit2 Signature Replay Detected',
          description: `Replayed permit signature attempted token transfer on contract ${target}.`,
          contract_address: target,
          tx_hash: randomHash,
          timestamp: now,
          protocol: 'Signature Guard',
          confidence_score: 0.91,
          action_suggested: 'Invalidate signature nonces and check EIP-712 domain separator.'
        };
        break;
      default:
        alert = {
          alert_id: `FORTA-ALERT-${Math.floor(Math.random() * 900000 + 100000)}`,
          bot_id: '0x7701e92019a84b1029471',
          bot_name: 'FORTA-UNVERIFIED-BYTECODE-DEPLOY',
          severity: 'Medium',
          title: 'Unverified Bytecode Interaction Alert',
          description: `Unverified contract address interacted with admin methods at ${target}.`,
          contract_address: target,
          tx_hash: randomHash,
          timestamp: now,
          protocol: 'Contract Bytecode Integrity',
          confidence_score: 0.88,
          action_suggested: 'Verify source code on Etherscan or Polygonscan before executing calls.'
        };
        break;
    }

    FORTA_ALERTS.unshift(alert);

    return NextResponse.json({ success: true, alert });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
