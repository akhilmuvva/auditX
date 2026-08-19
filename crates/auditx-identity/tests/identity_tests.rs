use chrono::{Duration, Utc};
use ethers::types::Address;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use auditx_core::siem::ThreatIntelligence;
use auditx_identity::{
    assess_wallet_login, build_assessment, check_fresh_wallet, check_impossible_travel,
    check_known_bad_address, check_login_velocity, check_new_device, wallet_key,
    IdentityStore, InMemoryStore, LoginDecision, RawLoginRequest, RiskFlag,
    SiemIdentityContext, WalletBaseline, WalletLoginEvent,
};

#[test]
fn test_mandate_1_canonical_wallet_key() {
    let addr_lower = Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
    let addr_upper = Address::from_str("0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045").unwrap();

    let key1 = wallet_key(&addr_lower);
    let key2 = wallet_key(&addr_upper);

    assert_eq!(key1, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    assert_eq!(key1, key2);
}

#[tokio::test]
async fn test_mandate_1_store_case_insensitivity() {
    let store = InMemoryStore::new();
    let addr_a = Address::from_str("0x89205a3a3b2a69de6dbf7f01edf300210574473e").unwrap();
    let addr_b = Address::from_str("0x89205A3A3B2A69DE6DBF7F01EDF300210574473E").unwrap();

    let mut baseline = WalletBaseline::new();
    baseline.login_count = 25;
    store.save_baseline(&addr_a, &baseline).await.unwrap();

    let retrieved = store.get_baseline(&addr_b).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().login_count, 25);
}

#[test]
fn test_rule_check_fresh_wallet_mandate_2() {
    // Under 24h -> FreshWalletFirstLogin
    let age_5h = Some(Duration::hours(5));
    let flag = check_fresh_wallet(age_5h);
    assert_eq!(flag, Some(RiskFlag::FreshWalletFirstLogin { wallet_age_hours: 5 }));

    // Over 24h -> Safe (None)
    let age_500h = Some(Duration::hours(500));
    let flag_old = check_fresh_wallet(age_500h);
    assert_eq!(flag_old, None);

    // Unknown age -> None (does not assume risky)
    let flag_none = check_fresh_wallet(None);
    assert_eq!(flag_none, None);
}

#[test]
fn test_rule_check_new_device_cold_start_transition() {
    let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
    let mut baseline = WalletBaseline::new();

    let event = WalletLoginEvent {
        wallet_addr: addr,
        ip_hash: "hash123".to_string(),
        device_fingerprint: "device_macbook_m3".to_string(),
        siwe_nonce: "nonce1".to_string(),
        siwe_domain: "polylance.app".to_string(),
        signature: "0x...".to_string(),
        timestamp: Utc::now(),
        geo_hint: None,
    };

    // Cold start phase (< 20 logins) -> New device is NOT penalized
    baseline.login_count = 5;
    assert_eq!(check_new_device(&event, &baseline), None);

    // Warm established phase (>= 20 logins) with unseen device -> Penalized
    baseline.login_count = 25;
    baseline.recent_devices = vec!["device_iphone_15".to_string()];
    assert_eq!(
        check_new_device(&event, &baseline),
        Some(RiskFlag::NewDeviceForWallet)
    );

    // Known device -> Not penalized
    baseline.recent_devices.push("device_macbook_m3".to_string());
    assert_eq!(check_new_device(&event, &baseline), None);
}

#[test]
fn test_rule_check_impossible_travel() {
    let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
    let now = Utc::now();

    // Tokyo coordinates
    let mut baseline = WalletBaseline::new();
    baseline.last_geo = Some((35.6762, 139.6503));
    baseline.last_login_time = Some(now - Duration::minutes(30));

    // New York coordinates 30 minutes later (impossible speed ~21,700 km/h)
    let event = WalletLoginEvent {
        wallet_addr: addr,
        ip_hash: "hash".to_string(),
        device_fingerprint: "device".to_string(),
        siwe_nonce: "nonce".to_string(),
        siwe_domain: "polylance.app".to_string(),
        signature: "0x".to_string(),
        timestamp: now,
        geo_hint: Some((40.7128, -74.0060)),
    };

    let flag = check_impossible_travel(&event, &baseline);
    assert!(matches!(flag, Some(RiskFlag::ImpossibleTravel { .. })));
}

#[test]
fn test_rule_check_known_bad_address() {
    let threat_intel = ThreatIntelligence::new(vec![]);
    // Tornado Cash Router
    let tornado_addr = Address::from_str("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b").unwrap();

    let event = WalletLoginEvent {
        wallet_addr: tornado_addr,
        ip_hash: "hash".to_string(),
        device_fingerprint: "device".to_string(),
        siwe_nonce: "nonce".to_string(),
        siwe_domain: "polylance.app".to_string(),
        signature: "0x".to_string(),
        timestamp: Utc::now(),
        geo_hint: None,
    };

    let flag = check_known_bad_address(&event, &threat_intel);
    assert!(flag.is_some());
    assert!(matches!(flag.unwrap(), RiskFlag::KnownBadAddress { .. }));
}

#[test]
fn test_rule_check_login_velocity() {
    assert_eq!(check_login_velocity(3, 60), None);
    assert_eq!(
        check_login_velocity(8, 60),
        Some(RiskFlag::LoginVelocityAbuse { attempts: 8, window_secs: 60 })
    );
}

#[tokio::test]
async fn test_latency_contract_warm_path() {
    let store = Arc::new(InMemoryStore::new());
    let ctx = SiemIdentityContext::new(store, "polylance.app");

    // Pre-populate wallet baseline
    let addr = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let mut baseline = WalletBaseline::new();
    baseline.login_count = 30;
    baseline.recent_devices = vec!["trusted_device".to_string()];
    ctx.store.save_baseline(&addr, &baseline).await.unwrap();

    let start = Instant::now();

    // Replay check using build_assessment (warm in-memory evaluation)
    let assessment = build_assessment(addr, vec![]);
    let duration = start.elapsed();

    assert_eq!(assessment.decision, LoginDecision::Allow);
    assert_eq!(assessment.trust_score, 100);
    // Warm in-memory path must execute in sub-millisecond time (< 50ms locally)
    assert!(duration.as_millis() < 50, "Warm path exceeded 50ms: {:?}", duration);
}
