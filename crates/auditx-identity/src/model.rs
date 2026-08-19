use chrono::{DateTime, Utc};
use ethers::types::Address;
use serde::{Deserialize, Serialize};

/// The single canonical way in the entire crate to format an Address as a store key.
/// Produces a lowercase 0x-prefixed hex string without checksum casing.
pub fn wallet_key(addr: &Address) -> String {
    format!("{:#x}", addr)
}

/// Raw login request payload received from the frontend/API proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLoginRequest {
    /// Raw EIP-4361 SIWE message string
    pub message: String,
    /// Hex-encoded 65-byte ECDSA signature (0x...)
    pub signature: String,
    /// Client IP address (will be immediately SHA-256 hashed, never stored raw)
    pub ip_address: String,
    /// Browser / hardware device fingerprint string
    pub device_fingerprint: String,
    /// Optional coarse geographic latitude/longitude hint (e.g. from upstream edge proxy)
    pub geo_hint: Option<(f64, f64)>,
}

/// Parsed & signature-verified wallet login event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletLoginEvent {
    /// Recovered, verified Ethereum wallet address
    pub wallet_addr: Address,
    /// SHA-256 hash of the client IP address (never raw IP)
    pub ip_hash: String,
    /// Device hardware/browser fingerprint
    pub device_fingerprint: String,
    /// EIP-4361 SIWE message nonce
    pub siwe_nonce: String,
    /// EIP-4361 SIWE domain (e.g. "polylance.app")
    pub siwe_domain: String,
    /// Hex signature string
    pub signature: String,
    /// Login event UTC timestamp
    pub timestamp: DateTime<Utc>,
    /// Coarse lat/lng (if provided by upstream proxy)
    pub geo_hint: Option<(f64, f64)>,
}

/// Decision output of the SIWE trust assessment pipeline
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LoginDecision {
    /// Score >= 70: Trusted login, grant session directly
    Allow,
    /// Score 40-69: Suspicious login, require step-up challenge
    StepUp,
    /// Score < 40: High-risk login, reject immediately
    Deny,
}

impl LoginDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            LoginDecision::Allow => "ALLOW",
            LoginDecision::StepUp => "STEP_UP",
            LoginDecision::Deny => "DENY",
        }
    }
}

/// Explainable risk flags explaining why the trust score was deducted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "details")]
pub enum RiskFlag {
    /// First time seeing this device fingerprint for an established wallet
    NewDeviceForWallet,
    /// Physical impossible travel speed between consecutive logins
    ImpossibleTravel { km: f64, minutes: i64 },
    /// Wallet was created very recently on-chain
    FreshWalletFirstLogin { wallet_age_hours: i64 },
    /// Nonce has already been consumed in a prior SIWE login (Replay attack defense)
    NonceReuseAttempt,
    /// Wallet address is flagged on known exploit / sanctions / mixer threat feeds
    KnownBadAddress { source: String },
    /// Abnormally high login attempt frequency from the same wallet or IP
    LoginVelocityAbuse { attempts: u32, window_secs: u32 },
    /// Cryptographic signature failed verification
    InvalidSignature { reason: String },
}

impl RiskFlag {
    pub fn description(&self) -> String {
        match self {
            RiskFlag::NewDeviceForWallet => "New device fingerprint detected for wallet".to_string(),
            RiskFlag::ImpossibleTravel { km, minutes } => {
                format!("Impossible travel speed: {:.1} km traveled in {} minutes", km, minutes)
            }
            RiskFlag::FreshWalletFirstLogin { wallet_age_hours } => {
                format!("Fresh wallet on-chain: created {} hours ago", wallet_age_hours)
            }
            RiskFlag::NonceReuseAttempt => "SIWE nonce reuse replay attempt detected".to_string(),
            RiskFlag::KnownBadAddress { source } => {
                format!("Wallet flagged on threat intelligence feed: {}", source)
            }
            RiskFlag::LoginVelocityAbuse { attempts, window_secs } => {
                format!("Login velocity abuse: {} attempts in {}s", attempts, window_secs)
            }
            RiskFlag::InvalidSignature { reason } => {
                format!("Invalid cryptographic SIWE signature: {}", reason)
            }
        }
    }
}

/// Output of the wallet trust assessment pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTrustAssessment {
    /// Evaluated wallet address
    pub wallet_addr: Address,
    /// Trust score from 0 to 100 (100 = fully trusted, 0 = critical risk)
    pub trust_score: u8,
    /// Comprehensive list of explainable risk flags
    pub risk_flags: Vec<RiskFlag>,
    /// Automated policy decision (Allow | StepUp | Deny)
    pub decision: LoginDecision,
    /// Timestamp when assessment occurred
    pub assessed_at: DateTime<Utc>,
}
