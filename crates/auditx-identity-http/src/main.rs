use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use auditx_identity::{InMemoryStore, SiemIdentityContext};
use auditx_identity_http::{create_router, AppState};

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
    let service_key = std::env::var("IDENTITY_SERVICE_KEY").ok();

    let mut ctx = SiemIdentityContext::new(store, &expected_domain);
    ctx.rpc_url = rpc_url;

    let state = AppState {
        ctx: Arc::new(ctx),
        service_key,
    };

    let app = create_router(state);

    // 3. Bind address from env
    let bind_addr = std::env::var("IDENTITY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8088".to_string());
    let addr: SocketAddr = bind_addr.parse()?;

    info!("🚀 auditx-identity-http service listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
