use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ethers::types::Address;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::baseline::WalletBaseline;
use crate::model::wallet_key;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Store I/O or connection error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Abstract persistence layer for SIWE identity security state
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Check whether a SIWE nonce has already been consumed
    async fn seen_nonce(&self, nonce: &str) -> Result<bool, StoreError>;

    /// Mark a SIWE nonce as consumed with a TTL window
    async fn mark_nonce_used(&self, nonce: &str, ttl_secs: u64) -> Result<(), StoreError>;

    /// Retrieve the historical behavioral baseline for a wallet
    async fn get_baseline(&self, wallet: &Address) -> Result<Option<WalletBaseline>, StoreError>;

    /// Persist the updated behavioral baseline for a wallet
    async fn save_baseline(&self, wallet: &Address, baseline: &WalletBaseline) -> Result<(), StoreError>;

    /// Retrieve recent login attempt timestamps for velocity tracking
    async fn recent_attempts(&self, wallet_or_ip: &str, window_secs: u32) -> Result<Vec<DateTime<Utc>>, StoreError>;

    /// Record a login attempt timestamp
    async fn record_attempt(&self, wallet_or_ip: &str, at: DateTime<Utc>) -> Result<(), StoreError>;

    /// Retrieve cached first on-chain activity timestamp
    async fn get_wallet_first_seen(&self, wallet: &Address) -> Result<Option<DateTime<Utc>>, StoreError>;

    /// Cache first on-chain activity timestamp indefinitely
    async fn save_wallet_first_seen(&self, wallet: &Address, first_seen: DateTime<Utc>) -> Result<(), StoreError>;
}

/// In-memory implementation of IdentityStore for development, testing, and single-node setups
#[derive(Clone, Default)]
pub struct InMemoryStore {
    nonces: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    baselines: Arc<RwLock<HashMap<String, WalletBaseline>>>,
    attempts: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
    wallet_age_cache: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            baselines: Arc::new(RwLock::new(HashMap::new())),
            attempts: Arc::new(RwLock::new(HashMap::new())),
            wallet_age_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl IdentityStore for InMemoryStore {
    async fn seen_nonce(&self, nonce: &str) -> Result<bool, StoreError> {
        let map = self.nonces.read().await;
        if let Some(exp) = map.get(nonce) {
            if *exp > Utc::now() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn mark_nonce_used(&self, nonce: &str, ttl_secs: u64) -> Result<(), StoreError> {
        let mut map = self.nonces.write().await;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        map.insert(nonce.to_string(), expires_at);
        Ok(())
    }

    async fn get_baseline(&self, wallet: &Address) -> Result<Option<WalletBaseline>, StoreError> {
        let key = wallet_key(wallet);
        let map = self.baselines.read().await;
        Ok(map.get(&key).cloned())
    }

    async fn save_baseline(&self, wallet: &Address, baseline: &WalletBaseline) -> Result<(), StoreError> {
        let key = wallet_key(wallet);
        let mut map = self.baselines.write().await;
        map.insert(key, baseline.clone());
        Ok(())
    }

    async fn recent_attempts(&self, wallet_or_ip: &str, window_secs: u32) -> Result<Vec<DateTime<Utc>>, StoreError> {
        let map = self.attempts.read().await;
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(window_secs as i64);

        if let Some(list) = map.get(wallet_or_ip) {
            let filtered: Vec<DateTime<Utc>> = list.iter().filter(|&&t| t >= cutoff).cloned().collect();
            Ok(filtered)
        } else {
            Ok(Vec::new())
        }
    }

    async fn record_attempt(&self, wallet_or_ip: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        let mut map = self.attempts.write().await;
        let entry = map.entry(wallet_or_ip.to_string()).or_insert_with(Vec::new);
        entry.push(at);
        // Trim timestamps older than 1 hour to prevent unbounded growth
        let cutoff = Utc::now() - chrono::Duration::hours(1);
        entry.retain(|&t| t >= cutoff);
        Ok(())
    }

    async fn get_wallet_first_seen(&self, wallet: &Address) -> Result<Option<DateTime<Utc>>, StoreError> {
        let key = wallet_key(wallet);
        let map = self.wallet_age_cache.read().await;
        Ok(map.get(&key).cloned())
    }

    async fn save_wallet_first_seen(&self, wallet: &Address, first_seen: DateTime<Utc>) -> Result<(), StoreError> {
        let key = wallet_key(wallet);
        let mut map = self.wallet_age_cache.write().await;
        map.insert(key, first_seen);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_case_insensitive_wallet_key_normalization() {
        let store = InMemoryStore::new();

        // One lowercase address, one checksum-cased address representing the SAME account
        let addr_lower = Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        let addr_checksum = Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();

        // Confirm wallet_key formats identically
        assert_eq!(wallet_key(&addr_lower), wallet_key(&addr_checksum));

        // Insert baseline with lowercase Address
        let mut baseline = WalletBaseline::new();
        baseline.login_count = 42;
        store.save_baseline(&addr_lower, &baseline).await.unwrap();

        // Retrieve baseline with checksum Address
        let retrieved = store.get_baseline(&addr_checksum).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().login_count, 42);

        // Test wallet age cache with case variance
        let test_time = Utc::now();
        store.save_wallet_first_seen(&addr_checksum, test_time).await.unwrap();
        let age_retrieved = store.get_wallet_first_seen(&addr_lower).await.unwrap();
        assert_eq!(age_retrieved, Some(test_time));
    }
}
