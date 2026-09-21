use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{Duration, Utc};
use ethers::signers::{LocalWallet, Signer};
use ethers::utils::to_checksum;
use siwe::Message;
use std::str::FromStr;
use std::sync::Arc;
use tower::ServiceExt;

use auditx_identity::{InMemoryStore, SiemIdentityContext};
use auditx_identity_http::{create_router, AppState};

async fn create_valid_signed_request(domain: &str) -> String {
    let wallet: LocalWallet = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse()
        .unwrap();
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    let checksum_addr = to_checksum(&wallet.address(), None);

    let message_str = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{checksum_addr}\n\nSign in to PolyLance\n\nURI: https://{domain}\nVersion: 1\nChain ID: 137\nNonce: testnonce12345678\nIssued At: {}\nExpiration Time: {}",
        now.to_rfc3339(),
        exp.to_rfc3339()
    );

    let message = Message::from_str(&message_str).unwrap();
    let message_bytes = message.eip191_bytes().unwrap();
    let sig = wallet.sign_message(message_bytes).await.unwrap();
    let sig_hex = format!("0x{}", hex::encode(sig.to_vec()));

    serde_json::json!({
        "message": message_str,
        "signature": sig_hex,
        "ip_address": "198.51.100.1",
        "device_fingerprint": "fp-test-hardware-id",
        "geo_hint": null
    })
    .to_string()
}

fn dummy_request_body() -> String {
    serde_json::json!({
        "message": "dummy",
        "signature": "0x1234",
        "ip_address": "198.51.100.1",
        "device_fingerprint": "fp-test",
        "geo_hint": null
    })
    .to_string()
}

fn create_test_context(domain: &str) -> Arc<SiemIdentityContext> {
    Arc::new(SiemIdentityContext::new(
        Arc::new(InMemoryStore::new()),
        domain,
    ))
}

#[tokio::test]
async fn test_missing_service_key_returns_401() {
    let ctx = create_test_context("polylance.codes");
    let state = AppState {
        ctx,
        service_key: Some("EXPECTED_SECRET_SERVICE_KEY_12345".to_string()),
    };
    let app = create_router(state);

    let req = Request::builder()
        .uri("/assess-wallet-login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(dummy_request_body()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_wrong_service_key_returns_401() {
    let ctx = create_test_context("polylance.codes");
    let state = AppState {
        ctx,
        service_key: Some("EXPECTED_SECRET_SERVICE_KEY_12345".to_string()),
    };
    let app = create_router(state);

    let req = Request::builder()
        .uri("/assess-wallet-login")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-service-key", "WRONG_INVALID_KEY")
        .body(Body::from(dummy_request_body()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_valid_service_key_returns_200() {
    let domain = "polylance.codes";
    let ctx = create_test_context(domain);
    let state = AppState {
        ctx,
        service_key: Some("EXPECTED_SECRET_SERVICE_KEY_12345".to_string()),
    };
    let app = create_router(state);

    let valid_body = create_valid_signed_request(domain).await;

    let req = Request::builder()
        .uri("/assess-wallet-login")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-service-key", "EXPECTED_SECRET_SERVICE_KEY_12345")
        .body(Body::from(valid_body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_unset_service_key_config_fails_closed_503() {
    let ctx = create_test_context("polylance.codes");
    let state = AppState {
        ctx,
        service_key: None, // Unset service key config
    };
    let app = create_router(state);

    let req = Request::builder()
        .uri("/assess-wallet-login")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-service-key", "ANY_KEY")
        .body(Body::from(dummy_request_body()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
