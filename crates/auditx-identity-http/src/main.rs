use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use auditx_identity::{
    assess_wallet_login, InMemoryStore, RawLoginRequest, SiemIdentityContext,
};

const REQUEST_TIMEOUT_MS: u64 = 250;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // 2. Build shared assessment context
    let store = Arc::new(InMemoryStore::new());
    let expected_domain = std::env::var("IDENTITY_EXPECTED_DOMAIN")
        .unwrap_or_else(|_| "polylance.app".to_string());
    let rpc_url = std::env::var("RPC_URL").ok();

    let mut ctx = SiemIdentityContext::new(store, &expected_domain);
    ctx.rpc_url = rpc_url;
    let shared_ctx = Arc::new(ctx);

    // 3. Build Axum Router with CORS & 250ms timeout protection
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/assess-wallet-login", post(handle_assess_wallet_login))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(shared_ctx);

    // 4. Bind address from env
    let bind_addr = std::env::var("IDENTITY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8088".to_string());
    let addr: SocketAddr = bind_addr.parse()?;

    info!("🚀 auditx-identity-http service listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_assess_wallet_login(
    State(ctx): State<Arc<SiemIdentityContext>>,
    Json(payload): Json<RawLoginRequest>,
) -> impl IntoResponse {
    // Wrap entire handler in 250ms timeout to guarantee headroom under 300ms p95 SLA
    let res = timeout(
        Duration::from_millis(REQUEST_TIMEOUT_MS),
        assess_wallet_login(payload, &ctx),
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
