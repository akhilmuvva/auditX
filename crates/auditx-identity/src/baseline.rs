use chrono::{DateTime, Utc, Timelike};
use serde::{Deserialize, Serialize};
use crate::model::WalletLoginEvent;

pub const COLD_START_THRESHOLD: usize = 20;
pub const MAX_RECENT_DEVICES: usize = 5;

/// Online statistical baseline per wallet address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBaseline {
    /// Number of verified logins recorded for this wallet
    pub login_count: usize,
    /// Welford running mean and variance for login hour of the day (0.0 .. 23.99)
    pub mean_login_hour: f64,
    pub m2_login_hour: f64,
    /// Small LRU / set of recently observed device fingerprints (max 5)
    pub recent_devices: Vec<String>,
    /// Last observed geographic coordinate (latitude, longitude)
    pub last_geo: Option<(f64, f64)>,
    /// Last observed login timestamp
    pub last_login_time: Option<DateTime<Utc>>,
}

impl Default for WalletBaseline {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletBaseline {
    pub fn new() -> Self {
        Self {
            login_count: 0,
            mean_login_hour: 0.0,
            m2_login_hour: 0.0,
            recent_devices: Vec::new(),
            last_geo: None,
            last_login_time: None,
        }
    }

    /// Determines if the baseline is still in the cold-start learning phase (< 20 logins)
    pub fn is_cold_start(&self) -> bool {
        self.login_count < COLD_START_THRESHOLD
    }

    /// Updates the baseline with a new verified login event
    pub fn record_login(&mut self, event: &WalletLoginEvent) {
        self.login_count += 1;

        // Update Welford state for hour of day
        let hour = event.timestamp.hour() as f64 + (event.timestamp.minute() as f64 / 60.0);
        let n = self.login_count as f64;
        let delta = hour - self.mean_login_hour;
        self.mean_login_hour += delta / n;
        let delta2 = hour - self.mean_login_hour;
        self.m2_login_hour += delta * delta2;

        // Update recent devices list (LRU order, max 5)
        self.recent_devices.retain(|d| d != &event.device_fingerprint);
        self.recent_devices.insert(0, event.device_fingerprint.clone());
        if self.recent_devices.len() > MAX_RECENT_DEVICES {
            self.recent_devices.truncate(MAX_RECENT_DEVICES);
        }

        // Update geo and timestamp
        if event.geo_hint.is_some() {
            self.last_geo = event.geo_hint;
        }
        self.last_login_time = Some(event.timestamp);
    }

    pub fn variance(&self) -> f64 {
        if self.login_count < 2 {
            0.0
        } else {
            self.m2_login_hour / (self.login_count as f64 - 1.0)
        }
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}
