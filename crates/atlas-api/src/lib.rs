pub mod auth;
pub mod handlers;
pub mod models;
pub mod router;

use anyhow::Result;
use atlas_config::AppConfig;
use atlas_store::AtlasStore;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub store: Arc<Mutex<AtlasStore>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self> {
        let store = AtlasStore::open(Path::new(&config.storage.path))?;
        store.initialize()?;

        Ok(Self {
            config,
            store: Arc::new(Mutex::new(store)),
        })
    }
}
