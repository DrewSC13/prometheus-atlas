use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub telemetry: TelemetryConfig,
    pub drift: DriftConfig,
    pub plugins: PluginConfig,
    pub jobs: JobConfig,
    pub profiles: Vec<ScanProfile>,
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub saas: SaasConfig,
    pub pagination: PaginationConfig,
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: ".atlas/atlas.db".to_string(),
        }
    }
}

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
pub struct DriftConfig {
    pub persist_by_default: bool,
    pub profile: String,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            persist_by_default: true,
            profile: "standard".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JobConfig {
    pub default_interval_seconds: u64,
}

impl Default for JobConfig {
    fn default() -> Self {
        Self {
            default_interval_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanProfile {
    pub name: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self {
            name: "standard".to_string(),
            ports: vec![80, 443],
            timeout_ms: 3000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub request_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_string(),
            request_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub issuer: String,
    pub jwt_secret: String,
    pub jwt_expiration_seconds: u64,
    pub bootstrap_token: String,
    pub api_keys: Vec<ApiKeyConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: "prometheus-atlas".to_string(),
            jwt_secret: "change-me-super-secret-atlas-key".to_string(),
            jwt_expiration_seconds: 86_400,
            bootstrap_token: "atlas-bootstrap-admin".to_string(),
            api_keys: vec![ApiKeyConfig::default()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiKeyConfig {
    pub key_id: String,
    pub secret: String,
    pub tenant_id: String,
    pub project_id: String,
    pub role: String,
    pub enabled: bool,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            key_id: "local-admin".to_string(),
            secret: "atlas-local-admin-key".to_string(),
            tenant_id: "local".to_string(),
            project_id: "default".to_string(),
            role: "admin".to_string(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SaasConfig {
    pub default_tenant_id: String,
    pub default_project_id: String,
    pub default_environment: String,
}

impl Default for SaasConfig {
    fn default() -> Self {
        Self {
            default_tenant_id: "local".to_string(),
            default_project_id: "default".to_string(),
            default_environment: "local".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PaginationConfig {
    pub default_limit: usize,
    pub max_limit: usize,
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            default_limit: 25,
            max_limit: 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    pub enabled: bool,
    pub default_severity_threshold: String,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_severity_threshold: "medium".to_string(),
        }
    }
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

        if self.server.bind.trim().is_empty() {
            bail!("server.bind no puede estar vacío");
        }

        if self.auth.jwt_secret.trim().len() < 16 {
            bail!("auth.jwt_secret debe tener al menos 16 caracteres");
        }

        if self.auth.bootstrap_token.trim().is_empty() {
            bail!("auth.bootstrap_token no puede estar vacío");
        }

        if self.pagination.default_limit == 0 {
            bail!("pagination.default_limit debe ser > 0");
        }

        if self.pagination.max_limit < self.pagination.default_limit {
            bail!("pagination.max_limit debe ser >= pagination.default_limit");
        }

        if self.saas.default_tenant_id.trim().is_empty() {
            bail!("saas.default_tenant_id no puede estar vacío");
        }

        if self.saas.default_project_id.trim().is_empty() {
            bail!("saas.default_project_id no puede estar vacío");
        }

        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&ScanProfile> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow!("profile no encontrado: {name}"))
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            telemetry: TelemetryConfig::default(),
            drift: DriftConfig::default(),
            plugins: PluginConfig::default(),
            jobs: JobConfig::default(),
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
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            saas: SaasConfig::default(),
            pagination: PaginationConfig::default(),
            alerts: AlertConfig::default(),
        }
    }
}
