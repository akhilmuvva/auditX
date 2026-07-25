use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use uuid::Uuid;

// ─── Event Severity ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl EventSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventSeverity::Info => "INFO",
            EventSeverity::Low => "LOW",
            EventSeverity::Medium => "MEDIUM",
            EventSeverity::High => "HIGH",
            EventSeverity::Critical => "CRITICAL",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => EventSeverity::Critical,
            "HIGH" => EventSeverity::High,
            "MEDIUM" => EventSeverity::Medium,
            "LOW" => EventSeverity::Low,
            _ => EventSeverity::Info,
        }
    }
}

// ─── Event Category ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventCategory {
    Transfer,
    Approval,
    OwnershipChange,
    LargeWithdrawal,
    FlashLoan,
    ReentrancySignal,
    OracleManipulation,
    Governance,
    Upgrade,
    Pause,
    Unknown,
}

impl EventCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventCategory::Transfer => "TRANSFER",
            EventCategory::Approval => "APPROVAL",
            EventCategory::OwnershipChange => "OWNERSHIP_CHANGE",
            EventCategory::LargeWithdrawal => "LARGE_WITHDRAWAL",
            EventCategory::FlashLoan => "FLASH_LOAN",
            EventCategory::ReentrancySignal => "REENTRANCY_SIGNAL",
            EventCategory::OracleManipulation => "ORACLE_MANIPULATION",
            EventCategory::Governance => "GOVERNANCE",
            EventCategory::Upgrade => "UPGRADE",
            EventCategory::Pause => "PAUSE",
            EventCategory::Unknown => "UNKNOWN",
        }
    }
}

// ─── Chain Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEvent {
    pub id: String,
    pub timestamp: u64,
    pub chain_id: u64,
    pub contract_address: String,
    pub contract_name: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
    pub event_name: String,
    pub args: serde_json::Value,
    pub gas_used: u64,
    pub call_value: String,
    pub from: String,
}

// ─── Classified Event ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedEvent {
    pub event: ChainEvent,
    pub category: EventCategory,
    pub reason: String,
    pub rule_severity: EventSeverity,
}

// ─── Anomaly Score ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub gas_z_score: f64,
    pub value_z_score: f64,
    pub score: f64,
    pub is_anomaly: bool,
}

// ─── Scored Event ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredEvent {
    pub classified: ClassifiedEvent,
    pub anomaly: AnomalyScore,
    pub final_severity: EventSeverity,
}

// ─── Threat Intelligence ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    Sanctions,
    Exploit,
    Mixer,
    Drainer,
    Phishing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub address: String,
    pub label: String,
    pub category: ThreatCategory,
    pub risk_score: f64,
    pub first_seen: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub address: String,
    pub feed: ThreatFeed,
    pub matched_field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub scored: ScoredEvent,
    pub threat_matches: Vec<ThreatMatch>,
    pub escalated_severity: EventSeverity,
}

// ─── Alert ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: u64,
    pub event: EnrichedEvent,
    pub title: String,
    pub description: String,
    pub severity: EventSeverity,
    pub status: AlertStatus,
    pub ipfs_cid: Option<String>,
    pub eas_uid: Option<String>,
}

// ─── EventClassifier ────────────────────────────────────────────────────────

pub struct EventClassifier;

impl EventClassifier {
    pub fn new() -> Self {
        Self
    }

    pub fn classify(&self, event: &ChainEvent) -> ClassifiedEvent {
        let name_lower = event.event_name.to_lowercase();
        let val_wei = event.call_value.parse::<u128>().unwrap_or(0);

        // 1. Governance Speedrun
        if (name_lower.contains("proposalexecuted") || name_lower.contains("ruleexecuted"))
            && (self.check_arg_zero_or_true(&event.args, "delay")
                || self.check_arg_zero_or_true(&event.args, "emergency")
                || self.check_arg_zero_or_true(&event.args, "speedrun"))
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Governance,
                reason: format!("Governance speedrun detected: instant execution event \"{}\" with 0 delay", event.event_name),
                rule_severity: EventSeverity::High,
            };
        }

        // 2. MEV / Sandwich Arbitrage
        if (name_lower.contains("swap") || name_lower.contains("arbitrage"))
            && event.args.get("sender").is_some()
            && event.args.get("sender") == event.args.get("recipient")
        {
            let sender = event.args.get("sender").and_then(|v| v.as_str()).unwrap_or("");
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::FlashLoan,
                reason: format!("Circular swap detected: sender \"{}\" matches recipient (possible sandwich/arbitrage)", sender),
                rule_severity: EventSeverity::Medium,
            };
        }

        // 3. Emergency Shutdown / Selfdestruct
        if name_lower.contains("selfdestruct")
            || name_lower.contains("suicide")
            || name_lower.contains("killcontract")
            || name_lower.contains("emergencyshutdown")
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Upgrade,
                reason: format!("Emergency contract destruction signature \"{}\" detected", event.event_name),
                rule_severity: EventSeverity::Critical,
            };
        }

        // 4. Flash Loan
        if name_lower.contains("flashloan") || name_lower.contains("flash_loan") {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::FlashLoan,
                reason: format!("Flash-loan event \"{}\" detected", event.event_name),
                rule_severity: EventSeverity::High,
            };
        }

        // 5. Reentrancy signal (Withdraw/Transfer + gas > 150,000 + value > 0)
        if (name_lower.contains("withdraw") || name_lower.contains("transfer"))
            && event.gas_used > 150_000
            && val_wei > 0
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::ReentrancySignal,
                reason: format!("High-gas withdrawal ({} gas) — potential reentrancy", event.gas_used),
                rule_severity: EventSeverity::High,
            };
        }

        // 6. Ownership change
        if name_lower.contains("ownershiptransferred")
            || name_lower.contains("adminchanged")
            || name_lower.contains("ownershiprenounced")
            || name_lower.contains("rolerevoked")
            || name_lower.contains("rolegranted")
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::OwnershipChange,
                reason: format!("Privilege change event \"{}\"", event.event_name),
                rule_severity: EventSeverity::High,
            };
        }

        // 7. Proxy upgrade
        if name_lower.contains("upgraded")
            || name_lower.contains("implementationset")
            || name_lower.contains("beaconupgraded")
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Upgrade,
                reason: format!("Proxy upgrade event \"{}\"", event.event_name),
                rule_severity: EventSeverity::Critical,
            };
        }

        // 8. Circuit breaker Pause
        if name_lower == "paused" || name_lower == "unpaused" {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Pause,
                reason: format!("Circuit-breaker {} triggered", name_lower),
                rule_severity: EventSeverity::Medium,
            };
        }

        // 9. Governance general
        if name_lower.contains("proposalcreated")
            || name_lower.contains("proposalexecuted")
            || name_lower.contains("votecast")
            || name_lower.contains("votingperiodset")
            || name_lower.contains("quorumset")
        {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Governance,
                reason: format!("Governance action \"{}\"", event.event_name),
                rule_severity: EventSeverity::Medium,
            };
        }

        // 10. Oracle manipulation (>50% swing)
        if name_lower.contains("priceupdated")
            || name_lower.contains("answerupdated")
            || name_lower.contains("oracleset")
        {
            let current = event.args.get("current").or(event.args.get("price")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let previous = event.args.get("previous").or(event.args.get("previousPrice")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            if previous > 0.0 && ((current - previous).abs() / previous) > 0.5 {
                return ClassifiedEvent {
                    event: event.clone(),
                    category: EventCategory::OracleManipulation,
                    reason: format!("Oracle price moved >50% in one update ({} → {})", previous, current),
                    rule_severity: EventSeverity::Critical,
                };
            }
        }

        // 11. Large withdrawal (> 10 ETH or > 10e18 tokens)
        let threshold_wei: u128 = 10_000_000_000_000_000_000;
        let amount_arg = event.args.get("amount")
            .and_then(|v| v.as_str().or(v.as_u64().map(|_u| "").filter(|_| false)))
            .and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);

        if name_lower.contains("withdraw") && (val_wei > threshold_wei || amount_arg > threshold_wei) {
            let desc = if val_wei > threshold_wei {
                format!("Large withdrawal: {} ETH", val_wei as f64 / 1e18)
            } else {
                format!("Large token withdrawal: {} units", amount_arg)
            };
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::LargeWithdrawal,
                reason: desc,
                rule_severity: EventSeverity::High,
            };
        }

        // 12. Approval
        if event.event_name == "Approval" {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Approval,
                reason: "ERC-20/721 Approval event".to_string(),
                rule_severity: EventSeverity::Low,
            };
        }

        // 13. Transfer
        if event.event_name == "Transfer" {
            return ClassifiedEvent {
                event: event.clone(),
                category: EventCategory::Transfer,
                reason: "ERC-20/721 Transfer event".to_string(),
                rule_severity: EventSeverity::Info,
            };
        }

        // Default Unknown
        ClassifiedEvent {
            event: event.clone(),
            category: EventCategory::Unknown,
            reason: format!("No rule matched event \"{}\"", event.event_name),
            rule_severity: EventSeverity::Info,
        }
    }

    pub fn classify_batch(&self, events: &[ChainEvent]) -> Vec<ClassifiedEvent> {
        events.iter().map(|e| self.classify(e)).collect()
    }

    fn check_arg_zero_or_true(&self, args: &serde_json::Value, key: &str) -> bool {
        if let Some(val) = args.get(key) {
            if val.as_bool() == Some(true) { return true; }
            if val.as_u64() == Some(0) || val.as_i64() == Some(0) { return true; }
            if val.as_str() == Some("0") { return true; }
        }
        false
    }
}

// ─── AnomalyDetector (Welford + Cold Start Box-Muller) ──────────────────────

#[derive(Debug, Clone)]
pub struct WelfordState {
    pub n: f64,
    pub mean: f64,
    pub m2: f64,
}

impl WelfordState {
    pub fn new() -> Self {
        Self { n: 0.0, mean: 0.0, m2: 0.0 }
    }

    pub fn update(&mut self, val: f64) {
        self.n += 1.0;
        let delta = val - self.mean;
        self.mean += delta / self.n;
        let delta2 = val - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f64 {
        if self.n < 2.0 { 0.0 } else { self.m2 / (self.n - 1.0) }
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

pub struct AnomalyDetector {
    pub gas_state: WelfordState,
    pub value_state: WelfordState,
    pub synthetic_samples: usize,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            gas_state: WelfordState::new(),
            value_state: WelfordState::new(),
            synthetic_samples: 0,
        }
    }

    // Box-Muller PRNG for cold-start baseline initialization
    fn gaussian_random(mean: f64, std: f64, seed: &mut u64) -> f64 {
        // LCG pseudo-random generator for reproducible deterministic execution
        let mut next_rand = || -> f64 {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let val = (*seed >> 11) as f64 / (1u64 << 53) as f64;
            if val <= 0.0 { 0.00001 } else { val }
        };

        let u1 = 1.0 - next_rand();
        let u2 = next_rand();
        let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        mean + z0 * std
    }

    pub fn train(&mut self, historical_events: &[ClassifiedEvent]) {
        const SYNTHETIC_SAMPLE_COUNT: usize = 100;
        const ERC20_GAS_MEAN: f64 = 65_000.0;
        const ERC20_GAS_STD: f64 = 5_000.0;
        const ERC20_VALUE_MEAN: f64 = 0.0;
        const ERC20_VALUE_STD: f64 = 1e15; // 0.001 ETH in wei

        let mut rng_seed: u64 = 123456789;

        if historical_events.len() < SYNTHETIC_SAMPLE_COUNT {
            let synth_count = SYNTHETIC_SAMPLE_COUNT - historical_events.len();
            self.synthetic_samples = synth_count;

            for _ in 0..synth_count {
                let gas_used = Self::gaussian_random(ERC20_GAS_MEAN, ERC20_GAS_STD, &mut rng_seed).max(21_000.0);
                let call_val = Self::gaussian_random(ERC20_VALUE_MEAN, ERC20_VALUE_STD, &mut rng_seed).max(0.0);
                self.gas_state.update(gas_used);
                self.value_state.update(call_val);
            }
        }

        for event in historical_events {
            let val = event.event.call_value.parse::<f64>().unwrap_or(0.0);
            self.gas_state.update(event.event.gas_used as f64);
            self.value_state.update(val);
        }
    }

    pub fn score(&self, event: &ClassifiedEvent) -> AnomalyScore {
        let gas_std = if self.gas_state.std_dev() == 0.0 { 1.0 } else { self.gas_state.std_dev() };
        let value_std = if self.value_state.std_dev() == 0.0 { 1.0 } else { self.value_state.std_dev() };

        let gas_z = ((event.event.gas_used as f64 - self.gas_state.mean) / gas_std).abs();
        let val = event.event.call_value.parse::<f64>().unwrap_or(0.0);
        let value_z = ((val - self.value_state.mean) / value_std).abs();

        let combined_z = 0.6 * gas_z + 0.4 * value_z;
        let norm_score = 1.0 / (1.0 + (-0.5 * (combined_z - 3.0)).exp());

        AnomalyScore {
            gas_z_score: gas_z,
            value_z_score: value_z,
            score: norm_score,
            is_anomaly: combined_z >= 3.0,
        }
    }

    pub fn update(&mut self, event: &ClassifiedEvent) {
        let val = event.event.call_value.parse::<f64>().unwrap_or(0.0);
        self.gas_state.update(event.event.gas_used as f64);
        self.value_state.update(val);
    }

    pub fn score_and_update(&mut self, event: &ClassifiedEvent) -> AnomalyScore {
        let res = self.score(event);
        self.update(event);
        res
    }

    pub fn score_batch(&mut self, events: &[ClassifiedEvent]) -> Vec<ScoredEvent> {
        events.iter().map(|event| {
            let anomaly = self.score_and_update(event);
            let final_severity = if anomaly.is_anomaly {
                escalate_severity(event.rule_severity, anomaly.score)
            } else {
                event.rule_severity
            };
            ScoredEvent {
                classified: event.clone(),
                anomaly,
                final_severity,
            }
        }).collect()
    }
}

fn escalate_severity(current: EventSeverity, anomaly_score: f64) -> EventSeverity {
    let order = [
        EventSeverity::Info,
        EventSeverity::Low,
        EventSeverity::Medium,
        EventSeverity::High,
        EventSeverity::Critical,
    ];
    let idx = order.iter().position(|&s| s == current).unwrap_or(0);
    let bump = if anomaly_score >= 0.9 { 2 } else { 1 };
    let new_idx = (idx + bump).min(order.len() - 1);
    order[new_idx]
}

// ─── ThreatIntelligence ───────────────────────────────────────────────────────

pub struct ThreatIntelligence {
    feeds: HashMap<String, ThreatFeed>,
}

impl ThreatIntelligence {
    pub fn new(extra_feeds: Vec<ThreatFeed>) -> Self {
        let mut ti = Self { feeds: HashMap::new() };
        ti.load_seed_feeds();
        ti.add_feeds(extra_feeds);
        ti
    }

    fn load_seed_feeds(&mut self) {
        let seed = vec![
            ThreatFeed {
                address: "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b".to_string(),
                label: "Tornado Cash: Router".to_string(),
                category: ThreatCategory::Mixer,
                risk_score: 9.5,
                first_seen: "2022-08-08".to_string(),
                source: "OFAC SDN List".to_string(),
            },
            ThreatFeed {
                address: "0x722122df12d4e14e13ac3b6895a86e84145b6967".to_string(),
                label: "Tornado Cash: Proxy".to_string(),
                category: ThreatCategory::Mixer,
                risk_score: 9.5,
                first_seen: "2022-08-08".to_string(),
                source: "OFAC SDN List".to_string(),
            },
            ThreatFeed {
                address: "0x098b716b8aaf21512996dc57eb0615e2383e2f96".to_string(),
                label: "Ronin Bridge Exploiter (Lazarus Group)".to_string(),
                category: ThreatCategory::Exploit,
                risk_score: 10.0,
                first_seen: "2022-03-29".to_string(),
                source: "Chainalysis / OFAC".to_string(),
            },
            ThreatFeed {
                address: "0xb66cd966670d962c227b3eaba30a872dbfb995db".to_string(),
                label: "Euler Finance Exploiter".to_string(),
                category: ThreatCategory::Exploit,
                risk_score: 9.8,
                first_seen: "2023-03-13".to_string(),
                source: "Euler Finance Incident Report".to_string(),
            },
            ThreatFeed {
                address: "0x9d5765ae1c4e4a16e9ada6a4d2a8d0d6c1f6b6e".to_string(),
                label: "Multichain Exploiter".to_string(),
                category: ThreatCategory::Exploit,
                risk_score: 9.7,
                first_seen: "2023-07-07".to_string(),
                source: "Multichain Post-Mortem".to_string(),
            },
            ThreatFeed {
                address: "0xf6da21e95d74767009accb145b96897ac3630bd".to_string(),
                label: "Known NFT Drainer".to_string(),
                category: ThreatCategory::Drainer,
                risk_score: 8.5,
                first_seen: "2023-01-01".to_string(),
                source: "ZachXBT".to_string(),
            },
        ];
        self.add_feeds(seed);
    }

    pub fn add_feeds(&mut self, entries: Vec<ThreatFeed>) {
        for entry in entries {
            self.feeds.insert(entry.address.to_lowercase(), entry);
        }
    }

    pub fn size(&self) -> usize {
        self.feeds.len()
    }

    pub fn check_address(&self, address: &str) -> Option<&ThreatFeed> {
        self.feeds.get(&address.to_lowercase())
    }

    pub fn enrich(&self, event: &ScoredEvent) -> EnrichedEvent {
        let mut matches = Vec::new();

        let check = |addr: &str, field: &str, matches: &mut Vec<ThreatMatch>| {
            if let Some(feed) = self.check_address(addr) {
                matches.push(ThreatMatch {
                    address: addr.to_lowercase(),
                    feed: feed.clone(),
                    matched_field: field.to_string(),
                });
            }
        };

        check(&event.classified.event.from, "from", &mut matches);
        check(&event.classified.event.contract_address, "contractAddress", &mut matches);

        if let Some(obj) = event.classified.event.args.as_object() {
            for (key, val) in obj {
                if let Some(s) = val.as_str() {
                    if s.starts_with("0x") && s.len() >= 40 {
                        check(s, &format!("args.{}", key), &mut matches);
                    }
                }
            }
        }

        let escalated_severity = if !matches.is_empty() {
            let threat_sev = threat_to_severity(matches[0].feed.risk_score);
            if threat_sev > event.final_severity { threat_sev } else { event.final_severity }
        } else {
            event.final_severity
        };

        EnrichedEvent {
            scored: event.clone(),
            threat_matches: matches,
            escalated_severity,
        }
    }

    pub fn enrich_batch(&self, events: &[ScoredEvent]) -> Vec<EnrichedEvent> {
        events.iter().map(|e| self.enrich(e)).collect()
    }
}

fn threat_to_severity(risk_score: f64) -> EventSeverity {
    if risk_score >= 9.0 {
        EventSeverity::Critical
    } else if risk_score >= 7.0 {
        EventSeverity::High
    } else if risk_score >= 4.0 {
        EventSeverity::Medium
    } else if risk_score >= 2.0 {
        EventSeverity::Low
    } else {
        EventSeverity::Info
    }
}

// ─── AlertManager ───────────────────────────────────────────────────────────

pub struct SIEMAlertManager {
    alerts: Arc<Mutex<HashMap<String, Alert>>>,
    dedup_cache: Arc<Mutex<HashMap<String, u64>>>,
    threshold: EventSeverity,
    upload_to_ipfs: bool,
    create_eas_attestation: bool,
}

impl SIEMAlertManager {
    pub fn new(threshold: EventSeverity, upload_to_ipfs: bool, create_eas_attestation: bool) -> Self {
        Self {
            alerts: Arc::new(Mutex::new(HashMap::new())),
            dedup_cache: Arc::new(Mutex::new(HashMap::new())),
            threshold,
            upload_to_ipfs,
            create_eas_attestation,
        }
    }

    pub fn process_event(&self, event: &EnrichedEvent) -> Option<Alert> {
        if event.escalated_severity < self.threshold {
            return None;
        }

        let dedup_key = format!(
            "{}:{}:{}",
            event.scored.classified.event.contract_address,
            event.scored.classified.event.event_name,
            event.scored.classified.category.as_str()
        );

        let now = Utc::now().timestamp_millis() as u64;
        let mut dedup_cache = self.dedup_cache.lock().unwrap();

        if let Some(last_seen) = dedup_cache.get(&dedup_key) {
            if now - last_seen < 60_000 {
                dedup_cache.insert(dedup_key, now);
                return None;
            }
        }

        dedup_cache.insert(dedup_key, now);
        let alert = self.build_alert(event, now);

        let mut alerts = self.alerts.lock().unwrap();
        alerts.insert(alert.id.clone(), alert.clone());

        Some(alert)
    }

    pub fn process_batch(&self, events: &[EnrichedEvent]) -> Vec<Alert> {
        events.iter().filter_map(|e| self.process_event(e)).collect()
    }

    pub fn acknowledge(&self, alert_id: &str) -> bool {
        self.update_status(alert_id, AlertStatus::Acknowledged)
    }

    pub fn resolve(&self, alert_id: &str) -> bool {
        self.update_status(alert_id, AlertStatus::Resolved)
    }

    pub fn suppress(&self, alert_id: &str) -> bool {
        self.update_status(alert_id, AlertStatus::Suppressed)
    }

    fn update_status(&self, alert_id: &str, status: AlertStatus) -> bool {
        let mut alerts = self.alerts.lock().unwrap();
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = status;
            true
        } else {
            false
        }
    }

    pub fn get_alert(&self, alert_id: &str) -> Option<Alert> {
        let alerts = self.alerts.lock().unwrap();
        alerts.get(alert_id).cloned()
    }

    pub fn get_open_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.lock().unwrap();
        alerts.values().filter(|a| a.status == AlertStatus::Open).cloned().collect()
    }

    fn build_alert(&self, event: &EnrichedEvent, now: u64) -> Alert {
        let id = format!("alert-{}", Uuid::new_v4().simple());
        let has_threat = !event.threat_matches.is_empty();
        let is_anomaly = event.scored.anomaly.is_anomaly;

        let (title, description) = if has_threat {
            let match_item = &event.threat_matches[0];
            (
                format!("🚨 Threat Match: {}", match_item.feed.label),
                format!(
                    "Known-bad address \"{}\" ({:?}) detected in {} of \"{}\" on contract {}. Risk score: {}/10. Source: {}.",
                    match_item.address,
                    match_item.feed.category,
                    match_item.matched_field,
                    event.scored.classified.event.event_name,
                    event.scored.classified.event.contract_address,
                    match_item.feed.risk_score,
                    match_item.feed.source
                ),
            )
        } else if is_anomaly {
            (
                format!("⚠️ Anomalous {}: {}", event.scored.classified.category.as_str(), event.scored.classified.event.event_name),
                format!(
                    "Statistical anomaly detected — gas z-score: {:.2}, value z-score: {:.2} (combined score: {:.1}%). Classification: {}.",
                    event.scored.anomaly.gas_z_score,
                    event.scored.anomaly.value_z_score,
                    event.scored.anomaly.score * 100.0,
                    event.scored.classified.reason
                ),
            )
        } else {
            (
                format!("ℹ️ {}: {}", event.scored.classified.category.as_str(), event.scored.classified.event.event_name),
                event.scored.classified.reason.clone(),
            )
        };

        Alert {
            id,
            timestamp: now,
            event: event.clone(),
            title,
            description,
            severity: event.escalated_severity,
            status: AlertStatus::Open,
            ipfs_cid: if self.upload_to_ipfs && event.escalated_severity >= EventSeverity::High {
                Some(format!("QmIPFSAutoGeneratedCID-{}", Uuid::new_v4().simple()))
            } else {
                None
            },
            eas_uid: if self.create_eas_attestation && event.escalated_severity == EventSeverity::Critical {
                Some(format!("0xeasAttestationUid-{}", Uuid::new_v4().simple()))
            } else {
                None
            },
        }
    }
}

// ─── SIEMEngine (Unified Orchestrator) ──────────────────────────────────────

pub struct SIEMEngine {
    pub classifier: EventClassifier,
    pub detector: Mutex<AnomalyDetector>,
    pub intel: ThreatIntelligence,
    pub alert_manager: SIEMAlertManager,
    trained: Mutex<bool>,
}

impl SIEMEngine {
    pub fn new(alert_threshold: EventSeverity) -> Self {
        Self {
            classifier: EventClassifier::new(),
            detector: Mutex::new(AnomalyDetector::new()),
            intel: ThreatIntelligence::new(vec![]),
            alert_manager: SIEMAlertManager::new(alert_threshold, false, false),
            trained: Mutex::new(false),
        }
    }

    pub fn train(&self, historical_events: &[ChainEvent]) {
        let classified = self.classifier.classify_batch(historical_events);
        let mut detector = self.detector.lock().unwrap();
        detector.train(&classified);
        let mut trained = self.trained.lock().unwrap();
        *trained = true;
    }

    pub fn process(&self, events: &[ChainEvent]) -> (Vec<ClassifiedEvent>, Vec<ScoredEvent>, Vec<EnrichedEvent>, Vec<Alert>) {
        {
            let mut trained = self.trained.lock().unwrap();
            if !*trained {
                let mut detector = self.detector.lock().unwrap();
                detector.train(&[]);
                *trained = true;
            }
        }

        let classified = self.classifier.classify_batch(events);
        let scored = {
            let mut detector = self.detector.lock().unwrap();
            detector.score_batch(&classified)
        };
        let enriched = self.intel.enrich_batch(&scored);
        let alerts = self.alert_manager.process_batch(&enriched);

        (classified, scored, enriched, alerts)
    }

    pub fn process_single(&self, event: &ChainEvent) -> (EnrichedEvent, Option<Alert>) {
        {
            let mut trained = self.trained.lock().unwrap();
            if !*trained {
                let mut detector = self.detector.lock().unwrap();
                detector.train(&[]);
                *trained = true;
            }
        }

        let classified = self.classifier.classify(event);
        let anomaly = {
            let mut detector = self.detector.lock().unwrap();
            detector.score_and_update(&classified)
        };

        let scored = ScoredEvent {
            classified: classified.clone(),
            anomaly,
            final_severity: classified.rule_severity,
        };

        let enriched = self.intel.enrich(&scored);
        let alert = self.alert_manager.process_event(&enriched);

        (enriched, alert)
    }

    pub fn get_open_alerts(&self) -> Vec<Alert> {
        self.alert_manager.get_open_alerts()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(eventName: &str, gasUsed: u64, callValue: &str, from: &str, args: serde_json::Value) -> ChainEvent {
        ChainEvent {
            id: "tx_0001-0".to_string(),
            timestamp: Utc::now().timestamp_millis() as u64,
            chain_id: 84532,
            contract_address: "0xdeadbeef00000000000000000000000000000001".to_string(),
            contract_name: Some("TestVault".to_string()),
            tx_hash: "0xabc123".to_string(),
            block_number: 12345,
            event_name: eventName.to_string(),
            args,
            gas_used: gasUsed,
            call_value: callValue.to_string(),
            from: from.to_string(),
        }
    }

    #[test]
    fn test_event_classifier_rules() {
        let classifier = EventClassifier::new();

        let transfer = classifier.classify(&make_event("Transfer", 65000, "0", "0xsender", json!({})));
        assert_eq!(transfer.category, EventCategory::Transfer);
        assert_eq!(transfer.rule_severity, EventSeverity::Info);

        let ownership = classifier.classify(&make_event("OwnershipTransferred", 65000, "0", "0xsender", json!({})));
        assert_eq!(ownership.category, EventCategory::OwnershipChange);
        assert_eq!(ownership.rule_severity, EventSeverity::High);

        let upgrade = classifier.classify(&make_event("Upgraded", 65000, "0", "0xsender", json!({})));
        assert_eq!(upgrade.category, EventCategory::Upgrade);
        assert_eq!(upgrade.rule_severity, EventSeverity::Critical);

        let flashloan = classifier.classify(&make_event("FlashLoan", 65000, "0", "0xsender", json!({})));
        assert_eq!(flashloan.category, EventCategory::FlashLoan);
        assert_eq!(flashloan.rule_severity, EventSeverity::High);

        let paused = classifier.classify(&make_event("Paused", 65000, "0", "0xsender", json!({})));
        assert_eq!(paused.category, EventCategory::Pause);
        assert_eq!(paused.rule_severity, EventSeverity::Medium);

        let proposal = classifier.classify(&make_event("ProposalExecuted", 65000, "0", "0xsender", json!({"delay": 0})));
        assert_eq!(proposal.category, EventCategory::Governance);
        assert_eq!(proposal.rule_severity, EventSeverity::High);

        let swap = classifier.classify(&make_event("Swap", 65000, "0", "0xsender", json!({"sender": "0xuser", "recipient": "0xuser"})));
        assert_eq!(swap.category, EventCategory::FlashLoan);
        assert_eq!(swap.rule_severity, EventSeverity::Medium);

        let emergency = classifier.classify(&make_event("EmergencyShutdown", 65000, "0", "0xsender", json!({})));
        assert_eq!(emergency.category, EventCategory::Upgrade);
        assert_eq!(emergency.rule_severity, EventSeverity::Critical);

        let unknown = classifier.classify(&make_event("SomethingRandom123", 65000, "0", "0xsender", json!({})));
        assert_eq!(unknown.category, EventCategory::Unknown);
        assert_eq!(unknown.rule_severity, EventSeverity::Info);
    }

    #[test]
    fn test_anomaly_detector_cold_start() {
        let mut detector = AnomalyDetector::new();
        detector.train(&[]);
        assert_eq!(detector.synthetic_samples, 100);
        assert_eq!(detector.gas_state.n, 100.0);
        assert!(detector.gas_state.mean > 50000.0 && detector.gas_state.mean < 80000.0);

        let classifier = EventClassifier::new();
        let normal = classifier.classify(&make_event("Transfer", 65000, "0", "0xsender", json!({})));
        let score_normal = detector.score(&normal);
        assert!(!score_normal.is_anomaly);

        let anomalous = classifier.classify(&make_event("Transfer", 650000, "50000000000000000000", "0xsender", json!({})));
        let score_anom = detector.score(&anomalous);
        assert!(score_anom.is_anomaly);
        assert!(score_anom.gas_z_score > 3.0);
    }

    #[test]
    fn test_threat_intelligence_enrichment() {
        let ti = ThreatIntelligence::new(vec![]);
        assert!(ti.size() > 0);

        let tornado_feed = ti.check_address("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b");
        assert!(tornado_feed.is_some());
        assert_eq!(tornado_feed.unwrap().category, ThreatCategory::Mixer);

        let classifier = EventClassifier::new();
        let mut detector = AnomalyDetector::new();
        detector.train(&[]);

        let event = make_event("Transfer", 65000, "0", "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", json!({}));
        let classified = classifier.classify(&event);
        let anomaly = detector.score_and_update(&classified);
        let scored = ScoredEvent { classified, anomaly, final_severity: EventSeverity::Info };

        let enriched = ti.enrich(&scored);
        assert_eq!(enriched.threat_matches.len(), 1);
        assert_eq!(enriched.escalated_severity, EventSeverity::Critical);
    }

    #[test]
    fn test_alert_manager_dedup_and_lifecycle() {
        let engine = SIEMEngine::new(EventSeverity::Medium);
        engine.train(&[]);

        let event = make_event("Upgraded", 65000, "0", "0xsender", json!({}));
        let (_, _, _, alerts1) = engine.process(&[event.clone()]);
        assert_eq!(alerts1.len(), 1);
        assert_eq!(alerts1[0].severity, EventSeverity::Critical);

        // Second duplicate call within window should be suppressed
        let (_, _, _, alerts2) = engine.process(&[event]);
        assert_eq!(alerts2.len(), 0);

        let alert_id = &alerts1[0].id;
        assert!(engine.alert_manager.acknowledge(alert_id));
        assert_eq!(engine.alert_manager.get_alert(alert_id).unwrap().status, AlertStatus::Acknowledged);
        assert!(engine.alert_manager.resolve(alert_id));
        assert_eq!(engine.alert_manager.get_alert(alert_id).unwrap().status, AlertStatus::Resolved);
    }
}
