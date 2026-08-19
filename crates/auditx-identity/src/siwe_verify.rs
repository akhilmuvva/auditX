use chrono::Utc;
use ethers::types::Address;
use sha2::{Digest, Sha256};
use siwe::Message;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

use crate::model::{RawLoginRequest, WalletLoginEvent};
use crate::store::IdentityStore;

#[derive(Debug, Error)]
pub enum SiweVerificationError {
    #[error("Malformed EIP-4361 SIWE message: {0}")]
    MalformedMessage(String),

    #[error("Hex signature decoding failed: {0}")]
    InvalidSignatureFormat(String),

    #[error("Cryptographic signature verification failed: recovered address mismatch or invalid ECDSA signature")]
    SignatureVerificationFailed,

    #[error("Domain mismatch: expected domain '{expected}', but message was signed for '{actual}'")]
    DomainMismatch { expected: String, actual: String },

    #[error("SIWE message has expired at {0}")]
    MessageExpired(String),

    #[error("SIWE message is not yet valid before {0}")]
    MessageNotYetValid(String),

    #[error("SIWE nonce '{0}' has already been consumed (Replay attack detected)")]
    NonceReplayed(String),

    #[error("Internal store error: {0}")]
    StoreFailure(String),
}

/// Verifies SIWE message, signature, domain, timestamp, and checks for nonce replay
pub async fn verify_siwe_login(
    req: &RawLoginRequest,
    expected_domain: &str,
    store: &Arc<dyn IdentityStore>,
    nonce_ttl_secs: u64,
) -> Result<WalletLoginEvent, SiweVerificationError> {
    // 1. Parse EIP-4361 message
    let message = Message::from_str(&req.message)
        .map_err(|e| SiweVerificationError::MalformedMessage(e.to_string()))?;

    // 2. Validate Domain (Phishing-relay defense)
    if message.domain.as_str() != expected_domain {
        return Err(SiweVerificationError::DomainMismatch {
            expected: expected_domain.to_string(),
            actual: message.domain.as_str().to_string(),
        });
    }

    // 3. Validate Expiration & Not-Before timestamps
    let now = Utc::now();
    if let Some(ref exp) = message.expiration_time {
        let exp_utc = chrono::DateTime::parse_from_rfc3339(&exp.to_string())
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| SiweVerificationError::MalformedMessage(format!("Invalid expiration timestamp: {}", e)))?;
        if now > exp_utc {
            return Err(SiweVerificationError::MessageExpired(exp.to_string()));
        }
    }

    if let Some(ref nbf) = message.not_before {
        let nbf_utc = chrono::DateTime::parse_from_rfc3339(&nbf.to_string())
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| SiweVerificationError::MalformedMessage(format!("Invalid not_before timestamp: {}", e)))?;
        if now < nbf_utc {
            return Err(SiweVerificationError::MessageNotYetValid(nbf.to_string()));
        }
    }

    // 4. Nonce Replay Defense (Check if nonce was already consumed)
    let nonce = &message.nonce;
    let seen = store.seen_nonce(nonce).await
        .map_err(|e| SiweVerificationError::StoreFailure(e.to_string()))?;
    if seen {
        return Err(SiweVerificationError::NonceReplayed(nonce.clone()));
    }

    // 5. Signature Verification (Recover signer & compare)
    let sig_hex = req.signature.trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| SiweVerificationError::InvalidSignatureFormat(e.to_string()))?;
    let sig_array: &[u8; 65] = sig_bytes.as_slice().try_into()
        .map_err(|_| SiweVerificationError::InvalidSignatureFormat(
            format!("Expected 65-byte signature, got {} bytes", sig_bytes.len())
        ))?;

    // Verify signature with EIP-191 via siwe crate
    message.verify_eip191(sig_array)
        .map_err(|_| SiweVerificationError::SignatureVerificationFailed)?;

    // 6. Mark Nonce as Used
    store.mark_nonce_used(nonce, nonce_ttl_secs).await
        .map_err(|e| SiweVerificationError::StoreFailure(e.to_string()))?;

    // 7. Hash Client IP (Never store raw IP)
    let mut hasher = Sha256::new();
    hasher.update(req.ip_address.as_bytes());
    let ip_hash = format!("{:x}", hasher.finalize());

    // 8. Construct validated WalletLoginEvent
    let wallet_addr = Address::from_slice(&message.address);

    Ok(WalletLoginEvent {
        wallet_addr,
        ip_hash,
        device_fingerprint: req.device_fingerprint.clone(),
        siwe_nonce: message.nonce,
        siwe_domain: message.domain.as_str().to_string(),
        signature: req.signature.clone(),
        timestamp: now,
        geo_hint: req.geo_hint,
    })
}
