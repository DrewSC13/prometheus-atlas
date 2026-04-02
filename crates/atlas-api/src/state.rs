use anyhow::Result;
use atlas_config::AppConfig;
use atlas_store::AtlasStore;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub config: AppConfig,
    pub store: Mutex<AtlasStore>,
}

impl AppState {
    pub fn from_config(config: AppConfig) -> Result<Arc<Self>> {
        let storage_path = Path::new(&config.storage.path);

        let store = AtlasStore::open(storage_path)?;
        store.initialize()?;

        Ok(Arc::new(Self {
            config,
            store: Mutex::new(store),
        }))
    }

    pub fn default_scope(&self) -> atlas_core::AtlasScope {
        atlas_core::AtlasScope::global()
    }
}
