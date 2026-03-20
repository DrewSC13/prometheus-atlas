mod error;
mod handlers;
mod router;
mod state;

use anyhow::Result;
use atlas_config::AppConfig;
use router::build_router;
use state::AppState;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load_from_default_locations()?;
    config.validate()?;
    init_tracing(&config)?;

    let db_path = PathBuf::from(&config.storage.path);
    let snapshot_dir = env::var("ATLAS_SNAPSHOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".snapshots"));

    let bind_addr = env::var("ATLAS_API_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    let state = Arc::new(AppState::new(config, db_path, snapshot_dir));
    state.open_store()?.initialize()?;

    let app = build_router(state);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!("atlas-api listening on http://{}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing(config: &AppConfig) -> Result<()> {
    let filter =
        EnvFilter::try_new(config.logging.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.logging.json {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    Ok(())
}
