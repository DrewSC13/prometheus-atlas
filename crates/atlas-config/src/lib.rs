use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub backend: String,
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "sqlite".to_string(),
            path: ".atlas/atlas.db".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub timeout_seconds: u64,
    pub follow_redirects: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 5,
            follow_redirects: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DriftConfig {
    pub profile: String,
    pub persist_by_default: bool,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            profile: "standard".to_string(),
            persist_by_default: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub default_format: String,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            default_format: "human".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsConfig {
    pub enabled: Vec<String>,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            enabled: vec![
                "criticality-tag".to_string(),
                "state-tag".to_string(),
                "normalize-tags".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub logging: LoggingConfig,
    pub storage: StorageConfig,
    pub scanner: ScannerConfig,
    pub drift: DriftConfig,
    pub output: OutputConfig,
    pub telemetry: TelemetryConfig,
    pub plugins: PluginsConfig,
}

impl AppConfig {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("no se pudo leer la configuración {}", path.display()))?;

        let config = toml::from_str::<AppConfig>(&content)
            .with_context(|| format!("no se pudo parsear {}", path.display()))?;

        Ok(config)
    }

    pub fn load_from_default_locations() -> Result<Self> {
        if let Ok(path) = env::var("ATLAS_CONFIG") {
            return Self::load_from_path(Path::new(&path));
        }

        let local = PathBuf::from("atlas.toml");
        if local.exists() {
            return Self::load_from_path(&local);
        }

        Ok(Self::default())
    }

    pub fn write_default_to_path(path: &Path) -> Result<()> {
        let cfg = Self::default();
        let content = toml::to_string_pretty(&cfg)
            .context("no se pudo serializar la configuración por defecto")?;
        fs::write(path, content)
            .with_context(|| format!("no se pudo escribir {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.storage.backend != "sqlite" {
            bail!("backend de storage no soportado: {}", self.storage.backend);
        }

        if self.logging.level.trim().is_empty() {
            bail!("logging.level no puede estar vacío");
        }

        if self.output.default_format != "human" && self.output.default_format != "json" {
            bail!("output.default_format debe ser 'human' o 'json'");
        }

        Ok(())
    }
}
