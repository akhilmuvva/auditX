import { NextResponse } from 'next/server';

// In-memory SIEM telemetry event store for real-time monitoring
let SIEM_EVENTS: any[] = [
  {
    id: 'siem-init-1',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    network: 'Polygon PoS',
    contract_address: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
    event_type: 'Swap & Arbitrage',
    tx_hash: '0xa1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
    block_number: 54109200,
    value_eth: 150.0,
    gas_used: 820000,
    caller: '0x39f5068A8cf61664e48956903D5BfB42BEEF6887',
    severity: 'High',
    category: 'FlashLoan',
    rule_matched: 'RULE-01: Flash Loan Arbitrage & Oracle Drain',
    description: '150 ETH flash borrow detected across 2 liquidity pools without TWAP protection.',
    payload_preview: 'executeOperation(address,uint256,uint256,bytes)'
  },
  {
    id: 'siem-init-2',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    network: 'Base Sepolia',
    contract_address: '0x1234567890abcdef1234567890abcdef12345678',
    event_type: 'Withdrawal Fallback',
    tx_hash: '0xf9e8d7c6b5a432109876543210fedcba9876543210fedcba9876543210fedcba',
    block_number: 18920400,
    value_eth: 18.2,
    gas_used: 412000,
    caller: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    severity: 'Critical',
    category: 'Reentrancy',
    rule_matched: 'RULE-02: Reentrancy Call Depth Violation',
    description: 'Unchecked .call{value} triggered recursive fallback execution before state balance mutation.',
    payload_preview: 'withdraw() -> receive() -> withdraw()'
  }
];

const SIEM_RULES = [
  {
    id: 'RULE-01',
    name: 'Flash Loan Arbitrage & Oracle Drain',
    category: 'FlashLoan',
    severity: 'Critical',
    condition_description: 'Transaction value > 100 ETH with >3 DEX swap calls in single block',
    enabled: true,
  },
  {
    id: 'RULE-02',
    name: 'Reentrancy Call Depth Violation',
    category: 'Reentrancy',
    severity: 'Critical',
    condition_description: 'External call stack depth > 2 with state mutation pending',
    enabled: true,
  },
  {
    id: 'RULE-03',
    name: 'Unverified Admin Ownership Hijack',
    category: 'OwnershipHijack',
    severity: 'High',
    condition_description: 'OwnershipTransferred emitted to address with 0 transaction history',
    enabled: true,
  },
  {
    id: 'RULE-04',
    name: 'Anomalous Gas Limit Consumption',
    category: 'GasSpike',
    severity: 'Medium',
    condition_description: 'Transaction gas usage > 85% of total block gas limit',
    enabled: true,
  },
  {
    id: 'RULE-05',
    name: 'Web2 Key Leak to Web3 Admin Execution',
    category: 'CrossLayerIntrusion',
    severity: 'Critical',
    condition_description: 'Web2 API secret access log followed within 60s by Web3 contract admin call',
    enabled: true,
  },
];

export async function GET() {
  const criticalCount = SIEM_EVENTS.filter((e) => e.severity === 'Critical').length;
  const highCount = SIEM_EVENTS.filter((e) => e.severity === 'High').length;

  return NextResponse.json({
    events: SIEM_EVENTS,
    rules: SIEM_RULES,
    metrics: {
      total_events: SIEM_EVENTS.length,
      critical_threats: criticalCount,
      high_threats: highCount,
      active_rules: SIEM_RULES.filter((r) => r.enabled).length,
      status: criticalCount > 0 ? 'ALERTING' : 'SECURE',
    },
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { scenario, customEvent } = body;

    let newEvent: any = null;
    const now = new Date().toISOString();
    const randomTxHash = '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    if (customEvent) {
      newEvent = {
        ...customEvent,
        id: `siem-${Date.now()}`,
        timestamp: now,
        tx_hash: customEvent.tx_hash || randomTxHash,
      };
    } else {
      switch (scenario) {
        case 'flashloan':
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Polygon PoS',
            contract_address: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
            event_type: 'FlashLoan Swap & Liquidation',
            tx_hash: randomTxHash,
            block_number: 54109350,
            value_eth: 500.0,
            gas_used: 1350000,
            caller: '0x39f5068A8cf61664e48956903D5BfB42BEEF6887',
            severity: 'Critical',
            category: 'FlashLoan',
            rule_matched: 'RULE-01: Flash Loan Arbitrage & Oracle Drain',
            description: 'High-volume 500 ETH flash loan execution detected across DEX reserves without TWAP oracle protection.',
            payload_preview: 'executeOperation(address,uint256,uint256,bytes)'
          };
          break;
        case 'reentrancy':
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Base Sepolia',
            contract_address: '0x1234567890abcdef1234567890abcdef12345678',
            event_type: 'Recursive Fallback Call',
            tx_hash: randomTxHash,
            block_number: 18920510,
            value_eth: 42.0,
            gas_used: 680000,
            caller: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
            severity: 'Critical',
            category: 'Reentrancy',
            rule_matched: 'RULE-02: Reentrancy Call Depth Violation',
            description: 'Unchecked .call{value} transfer triggered 3 recursive reentrancy loops before updating balance mapping.',
            payload_preview: 'withdraw() -> receive() -> withdraw() -> receive()'
          };
          break;
        case 'ownership':
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Ethereum Mainnet',
            contract_address: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
            event_type: 'OwnershipTransferred',
            tx_hash: randomTxHash,
            block_number: 19842210,
            value_eth: 0.0,
            gas_used: 72000,
            caller: '0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73',
            severity: 'High',
            category: 'OwnershipHijack',
            rule_matched: 'RULE-03: Unverified Admin Ownership Hijack',
            description: 'Owner role transferred to unverified address with zero recorded transaction history.',
            payload_preview: 'transferOwnership(0x000000000000000000000000000000000000dEaD)'
          };
          break;
        case 'gasspike':
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Polygon PoS',
            contract_address: '0x9999999999999999999999999999999999999999',
            event_type: 'Complex State Iteration',
            tx_hash: randomTxHash,
            block_number: 54109380,
            value_eth: 0.5,
            gas_used: 28500000,
            caller: '0x7777777777777777777777777777777777777777',
            severity: 'Medium',
            category: 'GasSpike',
            rule_matched: 'RULE-04: Anomalous Gas Limit Consumption',
            description: 'Transaction consumed 95% of total block gas limit in a single execution loop.',
            payload_preview: 'batchDistributeRewards(address[])'
          };
          break;
        case 'crosslayer':
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Base Sepolia',
            contract_address: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
            event_type: 'Web2-Web3 Privilege Escalation',
            tx_hash: randomTxHash,
            block_number: 18920550,
            value_eth: 150.0,
            gas_used: 340000,
            caller: '0x8626f69A00E2eb1F10e44b065154161E5b7D0000',
            severity: 'Critical',
            category: 'CrossLayerIntrusion',
            rule_matched: 'RULE-05: Web2 Key Leak to Web3 Admin Execution',
            description: 'Web2 node.js server memory leak allowed attacker to extract private key and execute emergency vault drain.',
            payload_preview: 'emergencyWithdrawVault(address)'
          };
          break;
        default:
          newEvent = {
            id: `siem-${Date.now()}`,
            timestamp: now,
            network: 'Base Sepolia',
            contract_address: '0x0000000000000000000000000000000000000001',
            event_type: 'Compliant Execution',
            tx_hash: randomTxHash,
            block_number: 18920600,
            value_eth: 0.1,
            gas_used: 21000,
            caller: '0x1111111111111111111111111111111111111111',
            severity: 'Info',
            category: 'UnverifiedContractCall',
            rule_matched: 'N/A - Standard Transaction',
            description: 'Standard ETH transfer executed within expected security parameters.',
            payload_preview: 'transfer(address,uint256)'
          };
          break;
      }
    }

    // Prepend to telemetry stream
    SIEM_EVENTS.unshift(newEvent);

    return NextResponse.json({ success: true, event: newEvent });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
