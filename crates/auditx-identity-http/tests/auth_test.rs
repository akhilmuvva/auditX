use std::sync::Arc;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use auditx_identity::{InMemoryStore, SiemIdentityContext};
use auditx_identity_http::{create_router, AppState};

#[tokio::test]
async fn test_service_key_enforcement() {
    let store = Arc::new(InMemoryStore::new());
    let ctx = Arc::new(SiemIdentityContext::new(store, "polylance.app"));

    let state = AppState {
        ctx: ctx.clone(),
        service_key: Some("test-secret-service-key-999".to_string()),
    };

    let sample_payload = serde_json::json!({
        "message": "polylance.app wants you to sign in with your Ethereum account:\n0x1111111111111111111111111111111111111111\n\nSign in to PolyLance\n\nURI: https://polylance.app\nVersion: 1\nChain ID: 137\nNonce: abc12345\nIssued At: 2026-09-20T00:00:00Z",
        "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "ip_address": "198.51.100.42",
        "device_fingerprint": "browser_fingerprint_hash_1"
    });

    // 1. Missing X-Service-Key -> 401 Unauthorized
    let app = create_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/assess-wallet-login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&sample_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid X-Service-Key -> 401 Unauthorized
    let app = create_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/assess-wallet-login")
        .header("content-type", "application/json")
        .header("X-Service-Key", "wrong-key-123")
        .body(Body::from(serde_json::to_vec(&sample_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 3. Valid X-Service-Key -> Evaluates payload (returns 200/400, NOT 401)
    let app = create_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/assess-wallet-login")
        .header("content-type", "application/json")
        .header("X-Service-Key", "test-secret-service-key-999")
        .body(Body::from(serde_json::to_vec(&sample_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_ne!(res.status(), StatusCode::UNAUTHORIZED);
}
