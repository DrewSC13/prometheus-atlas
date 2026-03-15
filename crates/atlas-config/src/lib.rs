use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub telemetry: TelemetryConfig,
    pub drift: DriftConfig,
    pub plugins: PluginConfig,
    pub jobs: JobConfig,
    pub profiles: Vec<ScanProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftConfig {
    pub persist_by_default: bool,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobConfig {
    pub default_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

impl AppConfig {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_from_default_locations() -> Result<Self> {
        let path = PathBuf::from("atlas.toml");

        if path.exists() {
            Self::load_from_path(&path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn write_default_to_path(path: &Path) -> Result<()> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.storage.path.trim().is_empty() {
            bail!("storage.path no puede estar vacío");
        }

        if self.jobs.default_interval_seconds == 0 {
            bail!("jobs.default_interval_seconds debe ser > 0");
        }

        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&ScanProfile> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("profile no encontrado: {name}"))
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig {
                path: ".atlas/atlas.db".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                json: false,
            },
            telemetry: TelemetryConfig { enabled: true },
            drift: DriftConfig {
                persist_by_default: true,
                profile: "standard".to_string(),
            },
            plugins: PluginConfig { enabled: vec![] },
            jobs: JobConfig {
                default_interval_seconds: 3600,
            },
            profiles: vec![
                ScanProfile {
                    name: "standard".to_string(),
                    ports: vec![80, 443],
                    timeout_ms: 3000,
                },
                ScanProfile {
                    name: "deep".to_string(),
                    ports: vec![80, 443, 8080, 8443],
                    timeout_ms: 5000,
                },
            ],
        }
    }
}
