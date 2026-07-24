use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FortaSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortaBot {
    pub bot_id: String,
    pub name: String,
    pub description: String,
    pub developer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortaAlert {
    pub alert_id: String,
    pub bot_id: String,
    pub bot_name: String,
    pub severity: FortaSeverity,
    pub title: String,
    pub description: String,
    pub contract_address: String,
    pub tx_hash: String,
    pub timestamp: String,
    pub protocol: String,
    pub confidence_score: f32,
    pub action_suggested: String,
}

impl FortaBot {
    pub fn list_official_bots() -> Vec<Self> {
        vec![
            FortaBot {
                bot_id: "0x1928a412b590e091024bc".to_string(),
                name: "FORTA-REENTRANCY-CALL-DEPTH".to_string(),
                description: "Detects recursive call stack depth anomalies in real-time EVM transactions.".to_string(),
                developer: "Forta Foundation".to_string(),
            },
            FortaBot {
                bot_id: "0x429188f91023a12bf0011".to_string(),
                name: "FORTA-FLASH-LOAN-LARGE-SWAP".to_string(),
                description: "Monitors DEX reserve manipulation and multi-pool flash loan arbitrages.".to_string(),
                developer: "Nethermind Security".to_string(),
            },
            FortaBot {
                bot_id: "0x8812c390a12e847192301".to_string(),
                name: "FORTA-GOV-PROPOSAL-FLASH-VOTE".to_string(),
                description: "Flags flash-loan-funded governance vote spikes in a single block.".to_string(),
                developer: "OpenZeppelin".to_string(),
            },
            FortaBot {
                bot_id: "0x3310f8291048b29103841".to_string(),
                name: "FORTA-PERMIT2-SIGNATURE-REPLAY".to_string(),
                description: "Detects replayed cross-chain EIP-712 permit signatures.".to_string(),
                developer: "Arbitrary Execution".to_string(),
            },
            FortaBot {
                bot_id: "0x7701e92019a84b1029471".to_string(),
                name: "FORTA-UNVERIFIED-BYTECODE-DEPLOY".to_string(),
                description: "Alerts on unverified bytecode deployments interacting with vault admin functions.".to_string(),
                developer: "Forta Community".to_string(),
            },
        ]
    }
}

pub fn create_forta_alert(bot_type: &str, target_address: &str) -> FortaAlert {
    let now = Utc::now().to_rfc3339();
    let alert_id = format!("FORTA-ALERT-{}", Uuid::new_v4().simple());
    let tx_hash = format!("0x{:x}", Uuid::new_v4().simple());

    match bot_type {
        "reentrancy_bot" => FortaAlert {
            alert_id,
            bot_id: "0x1928a412b590e091024bc".to_string(),
            bot_name: "FORTA-REENTRANCY-CALL-DEPTH".to_string(),
            severity: FortaSeverity::Critical,
            title: "Reentrancy Threat Flagged by Forta Bot".to_string(),
            description: format!("Forta Bot 0x1928 detected 4 recursive fallback iterations in contract {} within transaction {}.", target_address, tx_hash),
            contract_address: target_address.to_string(),
            tx_hash,
            timestamp: now,
            protocol: "EVM Call Depth Watcher".to_string(),
            confidence_score: 0.96,
            action_suggested: "Pause contract deposits immediately and enforce nonReentrant guards.".to_string(),
        },
        "flashloan_bot" => FortaAlert {
            alert_id,
            bot_id: "0x429188f91023a12bf0011".to_string(),
            bot_name: "FORTA-FLASH-LOAN-LARGE-SWAP".to_string(),
            severity: FortaSeverity::Critical,
            title: "Flash Loan Oracle Manipulation Alert".to_string(),
            description: format!("Forta Bot 0x4291 detected 350 ETH flash borrow impacting reserves at {}.", target_address),
            contract_address: target_address.to_string(),
            tx_hash,
            timestamp: now,
            protocol: "DeFi Reserve Health".to_string(),
            confidence_score: 0.94,
            action_suggested: "Switch price oracle source to TWAP or Chainlink price feeds.".to_string(),
        },
        "permit2_bot" => FortaAlert {
            alert_id,
            bot_id: "0x3310f8291048b29103841".to_string(),
            bot_name: "FORTA-PERMIT2-SIGNATURE-REPLAY".to_string(),
            severity: FortaSeverity::High,
            title: "Permit2 Signature Replay Detected".to_string(),
            description: format!("Replayed permit signature attempted token transfer on contract {}.", target_address),
            contract_address: target_address.to_string(),
            tx_hash,
            timestamp: now,
            protocol: "Signature Guard".to_string(),
            confidence_score: 0.91,
            action_suggested: "Invalidate signature nonces and check EIP-712 domain separator.".to_string(),
        },
        _ => FortaAlert {
            alert_id,
            bot_id: "0x7701e92019a84b1029471".to_string(),
            bot_name: "FORTA-UNVERIFIED-BYTECODE-DEPLOY".to_string(),
            severity: FortaSeverity::Medium,
            title: "Unverified Bytecode Interaction Alert".to_string(),
            description: format!("Unverified contract address interacted with admin methods at {}.", target_address),
            contract_address: target_address.to_string(),
            tx_hash,
            timestamp: now,
            protocol: "Contract Bytecode Integrity".to_string(),
            confidence_score: 0.88,
            action_suggested: "Verify source code on Etherscan or Polygonscan before executing calls.".to_string(),
        },
    }
}
