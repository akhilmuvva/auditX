use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SIEMSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SIEMCategory {
    FlashLoan,
    Reentrancy,
    OwnershipHijack,
    GasSpike,
    CrossLayerIntrusion,
    UnverifiedContractCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMEvent {
    pub id: String,
    pub timestamp: String,
    pub network: String,
    pub contract_address: String,
    pub event_type: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub value_eth: f64,
    pub gas_used: u64,
    pub caller: String,
    pub severity: SIEMSeverity,
    pub category: SIEMCategory,
    pub rule_matched: String,
    pub description: String,
    pub payload_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMRule {
    pub id: String,
    pub name: String,
    pub category: SIEMCategory,
    pub severity: SIEMSeverity,
    pub condition_description: String,
    pub enabled: bool,
}

impl SIEMRule {
    pub fn default_rules() -> Vec<Self> {
        vec![
            SIEMRule {
                id: "RULE-01".to_string(),
                name: "Flash Loan Arbitrage & Oracle Drain".to_string(),
                category: SIEMCategory::FlashLoan,
                severity: SIEMSeverity::Critical,
                condition_description: "Transaction value > 100 ETH with >3 DEX swap calls in single block".to_string(),
                enabled: true,
            },
            SIEMRule {
                id: "RULE-02".to_string(),
                name: "Reentrancy Call Depth Violation".to_string(),
                category: SIEMCategory::Reentrancy,
                severity: SIEMSeverity::Critical,
                condition_description: "External call stack depth > 2 with state mutation pending".to_string(),
                enabled: true,
            },
            SIEMRule {
                id: "RULE-03".to_string(),
                name: "Unverified Admin Ownership Hijack".to_string(),
                category: SIEMCategory::OwnershipHijack,
                severity: SIEMSeverity::High,
                condition_description: "OwnershipTransferred emitted to address with 0 transaction history".to_string(),
                enabled: true,
            },
            SIEMRule {
                id: "RULE-04".to_string(),
                name: "Anomalous Gas Limit Consumption".to_string(),
                category: SIEMCategory::GasSpike,
                severity: SIEMSeverity::Medium,
                condition_description: "Transaction gas usage > 85% of total block gas limit".to_string(),
                enabled: true,
            },
            SIEMRule {
                id: "RULE-05".to_string(),
                name: "Web2 Key Leak to Web3 Admin Execution".to_string(),
                category: SIEMCategory::CrossLayerIntrusion,
                severity: SIEMSeverity::Critical,
                condition_description: "Web2 API secret access log followed within 60s by Web3 contract admin call".to_string(),
                enabled: true,
            },
        ]
    }
}

pub fn create_simulated_event(scenario: &str) -> SIEMEvent {
    let now = Utc::now().to_rfc3339();
    let tx_id = format!("0x{:x}", Uuid::new_v4().simple());
    
    match scenario {
        "flashloan" => SIEMEvent {
            id: format!("siem-{}", Uuid::new_v4()),
            timestamp: now,
            network: "Polygon PoS".to_string(),
            contract_address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".to_string(),
            event_type: "Swap & Liquidation".to_string(),
            tx_hash: tx_id,
            block_number: 54109281,
            value_eth: 450.0,
            gas_used: 1245000,
            caller: "0x39f5068A8cf61664e48956903D5BfB42BEEF6887".to_string(),
            severity: SIEMSeverity::Critical,
            category: SIEMCategory::FlashLoan,
            rule_matched: "RULE-01: Flash Loan Arbitrage & Oracle Drain".to_string(),
            description: "High velocity 450 ETH borrow detected across 3 pools without TWAP check.".to_string(),
            payload_preview: "executeOperation(address,uint256,uint256,bytes)".to_string(),
        },
        "reentrancy" => SIEMEvent {
            id: format!("siem-{}", Uuid::new_v4()),
            timestamp: now,
            network: "Base Sepolia".to_string(),
            contract_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            event_type: "Withdrawal Fallback".to_string(),
            tx_hash: tx_id,
            block_number: 18920412,
            value_eth: 25.5,
            gas_used: 489000,
            caller: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            severity: SIEMSeverity::Critical,
            category: SIEMCategory::Reentrancy,
            rule_matched: "RULE-02: Reentrancy Call Depth Violation".to_string(),
            description: "Unchecked .call{value} triggered recursive fallback before balance zeroing.".to_string(),
            payload_preview: "withdraw() -> receive() -> withdraw()".to_string(),
        },
        "ownership" => SIEMEvent {
            id: format!("siem-{}", Uuid::new_v4()),
            timestamp: now,
            network: "Ethereum Mainnet".to_string(),
            contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            event_type: "OwnershipTransferred".to_string(),
            tx_hash: tx_id,
            block_number: 19842100,
            value_eth: 0.0,
            gas_used: 65000,
            caller: "0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73".to_string(),
            severity: SIEMSeverity::High,
            category: SIEMCategory::OwnershipHijack,
            rule_matched: "RULE-03: Unverified Admin Ownership Hijack".to_string(),
            description: "Contract owner role transferred to fresh address with zero prior activity.".to_string(),
            payload_preview: "transferOwnership(0x000000000000000000000000000000000000dEaD)".to_string(),
        },
        "crosslayer" => SIEMEvent {
            id: format!("siem-{}", Uuid::new_v4()),
            timestamp: now,
            network: "Polygon PoS".to_string(),
            contract_address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".to_string(),
            event_type: "Privileged Execution".to_string(),
            tx_hash: tx_id,
            block_number: 54109400,
            value_eth: 120.0,
            gas_used: 310000,
            caller: "0x8626f69A00E2eb1F10e44b065154161E5b7D0000".to_string(),
            severity: SIEMSeverity::Critical,
            category: SIEMCategory::CrossLayerIntrusion,
            rule_matched: "RULE-05: Web2 Key Leak to Web3 Admin Execution".to_string(),
            description: "Web2 server environment key leak triggered admin withdrawal call 14 seconds later.".to_string(),
            payload_preview: "emergencyWithdrawVault(address)".to_string(),
        },
        _ => SIEMEvent {
            id: format!("siem-{}", Uuid::new_v4()),
            timestamp: now,
            network: "Base Sepolia".to_string(),
            contract_address: "0x0000000000000000000000000000000000000001".to_string(),
            event_type: "Standard Transfer".to_string(),
            tx_hash: tx_id,
            block_number: 18920450,
            value_eth: 1.2,
            gas_used: 21000,
            caller: "0x1111111111111111111111111111111111111111".to_string(),
            severity: SIEMSeverity::Info,
            category: SIEMCategory::UnverifiedContractCall,
            rule_matched: "N/A - Compliant Transaction".to_string(),
            description: "Normal ETH transfer passed all security thresholds.".to_string(),
            payload_preview: "transfer(address,uint256)".to_string(),
        },
    }
}
