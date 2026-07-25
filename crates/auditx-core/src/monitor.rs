use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use uuid::Uuid;
use crate::siem::{ChainEvent, EventSeverity, EventCategory};

type HmacSha256 = Hmac<Sha256>;

// ─── Client App Model ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientApp {
    pub id: String,
    pub name: String,
    pub api_key_hash: String,
    pub webhook_url: String,
    pub webhook_secret: String,
    pub created_at: u64,
}

// ─── Monitored Address Model ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredAddress {
    pub id: String,
    pub address: String,
    pub chain: String,
    pub owning_app: String,
    pub webhook_url: String,
    pub api_key_hash: String,
    pub watch_config: Vec<String>,
    pub registered_at: u64,
}

// ─── Webhook Alert Payload Model ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlertPayload {
    pub alert_id: String,
    pub contract_address: String,
    pub owning_app: String,
    pub chain: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub timestamp: u64,
    pub event_type: String,
    pub tx_hash: String,
}

// ─── Multi-Tenant Registry ───────────────────────────────────────────────────

#[derive(Clone)]
pub struct MultiTenantRegistry {
    clients: Arc<Mutex<HashMap<String, ClientApp>>>,            // api_key_hash -> ClientApp
    monitored: Arc<Mutex<HashMap<String, Vec<MonitoredAddress>>>>, // contract_address (lowercase) -> Vec<MonitoredAddress>
}

impl MultiTenantRegistry {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            monitored: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn hash_api_key(api_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn generate_hmac_signature(secret: &str, payload_bytes: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload_bytes);
        let bytes = mac.finalize().into_bytes();
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("sha256={}", hex_str)
    }

    pub fn register_client(&self, name: &str, webhook_url: &str) -> (ClientApp, String, String) {
        let raw_api_key = format!("ax_live_{}", Uuid::new_v4().simple());
        let api_key_hash = Self::hash_api_key(&raw_api_key);
        let webhook_secret = format!("sec_{}", Uuid::new_v4().simple());
        let now = Utc::now().timestamp_millis() as u64;

        let client = ClientApp {
            id: format!("client-{}", Uuid::new_v4().simple()),
            name: name.to_string(),
            api_key_hash: api_key_hash.clone(),
            webhook_url: webhook_url.to_string(),
            webhook_secret: webhook_secret.clone(),
            created_at: now,
        };

        let mut clients = self.clients.lock().unwrap();
        clients.insert(api_key_hash, client.clone());

        (client, raw_api_key, webhook_secret)
    }

    pub fn authenticate(&self, raw_api_key: &str) -> Option<ClientApp> {
        let hash = Self::hash_api_key(raw_api_key);
        let clients = self.clients.lock().unwrap();
        clients.get(&hash).cloned()
    }

    pub fn register_monitored_address(
        &self,
        raw_api_key: &str,
        address: &str,
        chain: &str,
        watch_config: Vec<String>,
    ) -> Result<MonitoredAddress, String> {
        let client = self.authenticate(raw_api_key)
            .ok_or_else(|| "Invalid API key".to_string())?;

        let norm_address = address.to_lowercase();
        let now = Utc::now().timestamp_millis() as u64;

        let monitored = MonitoredAddress {
            id: format!("mon-{}", Uuid::new_v4().simple()),
            address: norm_address.clone(),
            chain: chain.to_string(),
            owning_app: client.name.clone(),
            webhook_url: client.webhook_url.clone(),
            api_key_hash: client.api_key_hash.clone(),
            watch_config,
            registered_at: now,
        };

        let mut monitored_map = self.monitored.lock().unwrap();
        let list = monitored_map.entry(norm_address).or_insert_with(Vec::new);
        list.push(monitored.clone());

        Ok(monitored)
    }

    pub fn lookup_address(&self, address: &str) -> Vec<MonitoredAddress> {
        let norm = address.to_lowercase();
        let monitored_map = self.monitored.lock().unwrap();
        monitored_map.get(&norm).cloned().unwrap_or_default()
    }

    pub async fn dispatch_webhook_alert(
        &self,
        monitored: &MonitoredAddress,
        alert_id: &str,
        event_name: &str,
        tx_hash: &str,
        severity: EventSeverity,
        category: EventCategory,
        title: &str,
        description: &str,
    ) -> Result<bool, String> {
        let payload = WebhookAlertPayload {
            alert_id: alert_id.to_string(),
            contract_address: monitored.address.clone(),
            owning_app: monitored.owning_app.clone(),
            chain: monitored.chain.clone(),
            severity: severity.as_str().to_string(),
            category: category.as_str().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            timestamp: Utc::now().timestamp_millis() as u64,
            event_type: event_name.to_string(),
            tx_hash: tx_hash.to_string(),
        };

        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| e.to_string())?;

        let secret = {
            let clients = self.clients.lock().unwrap();
            clients.get(&monitored.api_key_hash)
                .map(|c| c.webhook_secret.clone())
                .unwrap_or_else(|| "default_secret".to_string())
        };

        let signature = Self::generate_hmac_signature(&secret, payload_json.as_bytes());

        let client = reqwest::Client::new();
        let res = client.post(&monitored.webhook_url)
            .header("Content-Type", "application/json")
            .header("X-AuditX-Signature", signature)
            .body(payload_json)
            .send()
            .await;

        match res {
            Ok(r) => Ok(r.status().is_success()),
            Err(e) => Err(e.to_string()),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_registration_and_auth() {
        let registry = MultiTenantRegistry::new();
        let (client, api_key, secret) = registry.register_client("polylance", "https://polylance.app/api/webhooks/auditx");

        assert_eq!(client.name, "polylance");
        assert!(api_key.starts_with("ax_live_"));
        assert!(secret.starts_with("sec_"));

        let authed = registry.authenticate(&api_key);
        assert!(authed.is_some());
        assert_eq!(authed.unwrap().name, "polylance");

        let invalid = registry.authenticate("ax_live_invalidkey123");
        assert!(invalid.is_none());
    }

    #[test]
    fn test_monitored_address_multi_tenant_isolation() {
        let registry = MultiTenantRegistry::new();
        let (_, key1, _) = registry.register_client("polylance", "https://polylance.app/webhook");
        let (_, key2, _) = registry.register_client("otherapp", "https://otherapp.io/webhook");

        let target_contract = "0x89205A3A3b2A69De6Dbf7f01EDf300210574473e";

        let mon1 = registry.register_monitored_address(&key1, target_contract, "polygon-amoy", vec!["reentrancy".to_string()]);
        assert!(mon1.is_ok());

        let mon2 = registry.register_monitored_address(&key2, target_contract, "polygon-amoy", vec!["flashloan".to_string()]);
        assert!(mon2.is_ok());

        let matches = registry.lookup_address(target_contract);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].owning_app, "polylance");
        assert_eq!(matches[1].owning_app, "otherapp");
    }

    #[test]
    fn test_hmac_signature_generation() {
        let secret = "sec_test_secret_key_123";
        let payload = b"{\"event\":\"ReentrancySignal\",\"contract\":\"0x123\"}";
        let sig = MultiTenantRegistry::generate_hmac_signature(secret, payload);

        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64); // sha256= + 64 hex chars
    }
}
