use anyhow::Result;
use atlas_api::{router::build_router, state::AppState};
use atlas_config::AppConfig;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load_from_default_locations()?;
    config.validate()?;

    let filter =
        EnvFilter::try_new(config.logging.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.logging.json {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    let state = AppState::from_config(config.clone())?;
    let app = build_router(state);

    let addr: SocketAddr = config.server.bind.parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("atlas-api escuchando en {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
