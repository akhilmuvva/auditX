use chrono::Utc;
use ethers::types::Address;

use crate::model::{LoginDecision, RiskFlag, WalletTrustAssessment};

// ─── Deterministic Point Deduction Constants ─────────────────────────────────

pub const DEDUCTION_KNOWN_BAD_ADDRESS: u8 = 80;
pub const DEDUCTION_NONCE_REUSE: u8 = 60;
pub const DEDUCTION_INVALID_SIGNATURE: u8 = 50;
pub const DEDUCTION_IMPOSSIBLE_TRAVEL: u8 = 40;
pub const DEDUCTION_LOGIN_VELOCITY: u8 = 35;
pub const DEDUCTION_NEW_DEVICE: u8 = 25;
pub const DEDUCTION_FRESH_WALLET: u8 = 15;

// ─── Policy Decision Threshold Constants ─────────────────────────────────────

/// Trust score >= 70 yields Allow decision
pub const ALLOW_THRESHOLD: u8 = 70;
/// Trust score between 40 and 69 yields StepUp challenge
pub const STEPUP_THRESHOLD: u8 = 40;

/// Maps a single risk flag to its deterministic point deduction
pub fn deduction_for_flag(flag: &RiskFlag) -> u8 {
    match flag {
        RiskFlag::KnownBadAddress { .. } => DEDUCTION_KNOWN_BAD_ADDRESS,
        RiskFlag::NonceReuseAttempt => DEDUCTION_NONCE_REUSE,
        RiskFlag::InvalidSignature { .. } => DEDUCTION_INVALID_SIGNATURE,
        RiskFlag::ImpossibleTravel { .. } => DEDUCTION_IMPOSSIBLE_TRAVEL,
        RiskFlag::LoginVelocityAbuse { .. } => DEDUCTION_LOGIN_VELOCITY,
        RiskFlag::NewDeviceForWallet => DEDUCTION_NEW_DEVICE,
        RiskFlag::FreshWalletFirstLogin { .. } => DEDUCTION_FRESH_WALLET,
    }
}

/// Computes the final trust score (0 - 100) from the active risk flags
pub fn calculate_trust_score(flags: &[RiskFlag]) -> u8 {
    let mut score: i16 = 100;
    for flag in flags {
        score -= deduction_for_flag(flag) as i16;
    }
    score.clamp(0, 100) as u8
}

/// Evaluates the policy decision from the computed trust score
pub fn determine_decision(score: u8) -> LoginDecision {
    if score >= ALLOW_THRESHOLD {
        LoginDecision::Allow
    } else if score >= STEPUP_THRESHOLD {
        LoginDecision::StepUp
    } else {
        LoginDecision::Deny
    }
}

/// Builds a complete WalletTrustAssessment with full explainability
pub fn build_assessment(wallet_addr: Address, risk_flags: Vec<RiskFlag>) -> WalletTrustAssessment {
    let trust_score = calculate_trust_score(&risk_flags);
    let decision = determine_decision(trust_score);

    WalletTrustAssessment {
        wallet_addr,
        trust_score,
        risk_flags,
        decision,
        assessed_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_perfect_score_allows() {
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let assessment = build_assessment(addr, vec![]);
        assert_eq!(assessment.trust_score, 100);
        assert_eq!(assessment.decision, LoginDecision::Allow);
        assert!(assessment.risk_flags.is_empty());
    }

    #[test]
    fn test_new_device_deduction() {
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let flags = vec![RiskFlag::NewDeviceForWallet]; // -25
        let assessment = build_assessment(addr, flags);
        assert_eq!(assessment.trust_score, 75);
        assert_eq!(assessment.decision, LoginDecision::Allow);
    }

    #[test]
    fn test_impossible_travel_stepup() {
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let flags = vec![
            RiskFlag::ImpossibleTravel { km: 5000.0, minutes: 30 }, // -40
        ];
        let assessment = build_assessment(addr, flags);
        assert_eq!(assessment.trust_score, 60);
        assert_eq!(assessment.decision, LoginDecision::StepUp);
    }

    #[test]
    fn test_known_bad_address_denies() {
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let flags = vec![
            RiskFlag::KnownBadAddress { source: "OFAC".to_string() }, // -80
        ];
        let assessment = build_assessment(addr, flags);
        assert_eq!(assessment.trust_score, 20);
        assert_eq!(assessment.decision, LoginDecision::Deny);
    }
}
