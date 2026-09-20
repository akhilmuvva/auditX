use axum::{
    extract::{rejection::JsonRejection, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::error;

use auditx_identity::{
    assess_wallet_login, RawLoginRequest, SiemIdentityContext,
};

pub const REQUEST_TIMEOUT_MS: u64 = 250;

#[derive(Clone)]
pub struct AppState {
    pub ctx: Arc<SiemIdentityContext>,
    pub service_key: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/assess-wallet-login", post(handle_assess_wallet_login))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn handle_assess_wallet_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload_res: Result<Json<RawLoginRequest>, JsonRejection>,
) -> impl IntoResponse {
    // 1. Enforce X-Service-Key if configured (Constant-time check)
    if let Some(ref required_key) = state.service_key {
        let auth_header = headers.get("x-service-key").and_then(|v| v.to_str().ok());
        let matches = match auth_header {
            Some(key) => constant_time_eq(key.as_bytes(), required_key.as_bytes()),
            None => false,
        };

        if !matches {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Unauthorized: missing or invalid X-Service-Key header",
                    "status": "UNAUTHORIZED"
                })),
            );
        }
    }

    // 2. Validate JSON body structure
    let Json(payload) = match payload_res {
        Ok(p) => p,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Invalid JSON request payload: {}", err),
                    "status": "BAD_REQUEST"
                })),
            );
        }
    };

    // 3. Wrap entire handler in 250ms timeout to guarantee headroom under 300ms SLA
    let res = timeout(
        Duration::from_millis(REQUEST_TIMEOUT_MS),
        assess_wallet_login(payload, &state.ctx),
    )
    .await;

    match res {
        Ok(Ok(assessment)) => (StatusCode::OK, Json(serde_json::to_value(assessment).unwrap())),
        Ok(Err(err)) => {
            error!("Identity assessment error: {:?}", err);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": err.to_string(),
                    "status": "ASSESSMENT_FAILED"
                })),
            )
        }
        Err(_) => {
            error!("Request timed out after {}ms", REQUEST_TIMEOUT_MS);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "Assessment timed out",
                    "status": "TIMEOUT"
                })),
            )
        }
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
