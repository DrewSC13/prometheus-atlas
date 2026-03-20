use anyhow::Result;
use atlas_config::AppConfig;
use atlas_store::AtlasStore;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db_path: PathBuf,
    pub snapshot_dir: PathBuf,
}

impl AppState {
    pub fn new(config: AppConfig, db_path: PathBuf, snapshot_dir: PathBuf) -> Self {
        Self {
            config,
            db_path,
            snapshot_dir,
        }
    }

    pub fn open_store(&self) -> Result<AtlasStore> {
        AtlasStore::open(&self.db_path)
    }

    pub fn snapshot_dir(&self) -> &Path {
        &self.snapshot_dir
    }

    pub fn should_persist(&self, requested: Option<bool>) -> bool {
        requested.unwrap_or(self.config.drift.persist_by_default)
    }

    pub fn record_telemetry(
        &self,
        name: &str,
        target: Option<&str>,
        duration_ms: u128,
        metadata: &Value,
    ) -> Result<()> {
        if !self.config.telemetry.enabled {
            return Ok(());
        }

        let store = self.open_store()?;
        store.initialize()?;
        store.record_telemetry(name, target, duration_ms, metadata)?;
        Ok(())
    }
}
