use chrono::Duration;
use auditx_core::siem::ThreatIntelligence;

use crate::baseline::WalletBaseline;
use crate::model::{RiskFlag, WalletLoginEvent, wallet_key};

pub const MAX_COMMERCIAL_FLIGHT_SPEED_KMH: f64 = 900.0;
pub const FRESH_WALLET_HOURS_THRESHOLD: i64 = 24;
pub const MAX_LOGIN_ATTEMPTS_PER_WINDOW: u32 = 5;
pub const VELOCITY_WINDOW_SECS: u32 = 60;

/// Haversine formula to compute great-circle distance between two coordinates in kilometers
pub fn haversine_distance_km(coord1: (f64, f64), coord2: (f64, f64)) -> f64 {
    let (lat1, lon1) = coord1;
    let (lat2, lon2) = coord2;

    let r = 6371.0; // Earth's radius in km
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();

    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}

/// Rule 1: Check if device fingerprint is brand new for an established wallet (post-cold start)
pub fn check_new_device(event: &WalletLoginEvent, baseline: &WalletBaseline) -> Option<RiskFlag> {
    // If the wallet is in cold start (< 20 logins), new devices are informational and not penalized
    if baseline.is_cold_start() {
        return None;
    }

    if !baseline.recent_devices.contains(&event.device_fingerprint) {
        Some(RiskFlag::NewDeviceForWallet)
    } else {
        None
    }
}

/// Rule 2: Check for physical impossible travel speed between consecutive logins
pub fn check_impossible_travel(event: &WalletLoginEvent, baseline: &WalletBaseline) -> Option<RiskFlag> {
    let current_geo = event.geo_hint?;
    let last_geo = baseline.last_geo?;
    let last_time = baseline.last_login_time?;

    let elapsed = event.timestamp.signed_duration_since(last_time);
    let minutes = elapsed.num_minutes();

    if minutes <= 0 {
        // Logins occurring in the same minute from different coordinates
        let km = haversine_distance_km(last_geo, current_geo);
        if km > 10.0 {
            return Some(RiskFlag::ImpossibleTravel { km, minutes: 1 });
        }
        return None;
    }

    let km = haversine_distance_km(last_geo, current_geo);
    let hours = minutes as f64 / 60.0;
    let speed_kmh = km / hours;

    if speed_kmh > MAX_COMMERCIAL_FLIGHT_SPEED_KMH && km > 100.0 {
        Some(RiskFlag::ImpossibleTravel { km, minutes })
    } else {
        None
    }
}

/// Rule 3: Pure function evaluating whether pre-resolved on-chain wallet age indicates a fresh wallet
/// Note: MANDATE 2 requires this function to perform ZERO I/O or RPC calls.
pub fn check_fresh_wallet(wallet_age: Option<Duration>) -> Option<RiskFlag> {
    if let Some(age) = wallet_age {
        let hours = age.num_hours();
        if hours < FRESH_WALLET_HOURS_THRESHOLD {
            return Some(RiskFlag::FreshWalletFirstLogin { wallet_age_hours: hours.max(0) });
        }
    }
    None
}

/// Rule 4: Check if wallet address matches curated threat intelligence feeds (Tornado Cash, Ronin/Lazarus, etc.)
pub fn check_known_bad_address(event: &WalletLoginEvent, threat_intel: &ThreatIntelligence) -> Option<RiskFlag> {
    let key = wallet_key(&event.wallet_addr);
    if let Some(feed) = threat_intel.check_address(&key) {
        Some(RiskFlag::KnownBadAddress {
            source: format!("{} ({})", feed.label, feed.source),
        })
    } else {
        None
    }
}

/// Rule 5: Check login attempt frequency (velocity abuse)
pub fn check_login_velocity(recent_attempts_count: u32, window_secs: u32) -> Option<RiskFlag> {
    if recent_attempts_count > MAX_LOGIN_ATTEMPTS_PER_WINDOW {
        Some(RiskFlag::LoginVelocityAbuse {
            attempts: recent_attempts_count,
            window_secs,
        })
    } else {
        None
    }
}

/// Evaluates all rules against the login event, baseline, pre-resolved wallet age, and threat feed
pub fn evaluate_rules(
    event: &WalletLoginEvent,
    baseline: &WalletBaseline,
    wallet_age: Option<Duration>,
    recent_attempts_count: u32,
    threat_intel: &ThreatIntelligence,
) -> Vec<RiskFlag> {
    let mut flags = Vec::new();

    if let Some(flag) = check_known_bad_address(event, threat_intel) {
        flags.push(flag);
    }
    if let Some(flag) = check_impossible_travel(event, baseline) {
        flags.push(flag);
    }
    if let Some(flag) = check_login_velocity(recent_attempts_count, VELOCITY_WINDOW_SECS) {
        flags.push(flag);
    }
    if let Some(flag) = check_new_device(event, baseline) {
        flags.push(flag);
    }
    if let Some(flag) = check_fresh_wallet(wallet_age) {
        flags.push(flag);
    }

    flags
}
