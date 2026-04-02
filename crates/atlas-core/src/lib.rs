use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityHeaders {
    pub strict_transport_security: bool,
    pub content_security_policy: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub referrer_policy: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpService {
    pub host: String,
    pub url: String,
    pub scheme: String,
    pub status: u16,
    pub server: Option<String>,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub technologies: Vec<String>,
    pub provider: Option<String>,
    pub tls_enabled: bool,
    pub security_headers: SecurityHeaders,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanResult {
    pub target: String,
    pub resolved_ips: Vec<String>,
    pub subdomains: Vec<String>,
    pub services: Vec<HttpService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasScope {
    pub tenant_id: String,
    pub project_id: String,
}

impl AtlasScope {
    pub fn new(tenant_id: impl Into<String>, project_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
        }
    }

    pub fn global() -> Self {
        Self {
            tenant_id: "default".to_string(),
            project_id: "default".to_string(),
        }
    }

    pub fn is_global(&self) -> bool {
        self.tenant_id == "default" && self.project_id == "default"
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tenant_id.trim().is_empty() {
            return Err("tenant_id no puede estar vacío".to_string());
        }

        if self.project_id.trim().is_empty() {
            return Err("project_id no puede estar vacío".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalState {
    Open,
    Accepted,
    Mitigated,
    FalsePositive,
}

impl OperationalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Mitigated => "mitigated",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Mitigated | Self::FalsePositive)
    }

    pub fn normalize_str(input: &str) -> Result<&'static str, String> {
        Ok(Self::from_str(input)?.as_str())
    }
}

impl Display for OperationalState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OperationalState {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),

            // canon
            "accepted" => Ok(Self::Accepted),
            "mitigated" => Ok(Self::Mitigated),
            "false_positive" => Ok(Self::FalsePositive),

            // legacy compatibility aliases
            "ack" | "acknowledged" => Ok(Self::Accepted),
            "resolve" | "resolved" => Ok(Self::Mitigated),
            "false-positive" => Ok(Self::FalsePositive),
            "falsepositive" => Ok(Self::FalsePositive),

            other => Err(format!("operational_state no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingTriagePatch {
    pub operational_state: Option<OperationalState>,
    pub owner: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AssetBusinessContext {
    pub owner: Option<String>,
    pub team: Option<String>,
    pub business_service: Option<String>,
    pub criticality: Option<String>,
    pub environment: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Open,
    Acknowledged,
    Resolved,
}

impl IncidentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
        }
    }
}

impl Display for IncidentState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IncidentState {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "ack" | "acknowledged" => Ok(Self::Acknowledged),
            "resolve" | "resolved" => Ok(Self::Resolved),
            other => Err(format!("incident_state no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertChannelKind {
    Webhook,
    Slack,
    Email,
    Unknown,
}

impl AlertChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Slack => "slack",
            Self::Email => "email",
            Self::Unknown => "unknown",
        }
    }
}

impl Display for AlertChannelKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AlertChannelKind {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "webhook" => Ok(Self::Webhook),
            "slack" => Ok(Self::Slack),
            "email" => Ok(Self::Email),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("alert channel no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertDeliveryStatus {
    Pending,
    Sent,
    Failed,
    Retrying,
    DeadLetter,
    Delivered,
}

impl AlertDeliveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Retrying => "retrying",
            Self::DeadLetter => "dead_letter",
            Self::Delivered => "delivered",
        }
    }
}

impl Display for AlertDeliveryStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AlertDeliveryStatus {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "sent" => Ok(Self::Sent),
            "failed" => Ok(Self::Failed),
            "retrying" => Ok(Self::Retrying),
            "dead_letter" | "dead-letter" => Ok(Self::DeadLetter),
            "delivered" => Ok(Self::Delivered),
            other => Err(format!("alert delivery status no soportado: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_scope_global_is_stable() {
        let scope = AtlasScope::global();
        assert_eq!(scope.tenant_id, "default");
        assert_eq!(scope.project_id, "default");
        assert!(scope.is_global());
    }

    #[test]
    fn operational_state_parses_canonical_values() {
        assert_eq!(
            OperationalState::from_str("open").unwrap(),
            OperationalState::Open
        );
        assert_eq!(
            OperationalState::from_str("accepted").unwrap(),
            OperationalState::Accepted
        );
        assert_eq!(
            OperationalState::from_str("mitigated").unwrap(),
            OperationalState::Mitigated
        );
        assert_eq!(
            OperationalState::from_str("false_positive").unwrap(),
            OperationalState::FalsePositive
        );
    }

    #[test]
    fn operational_state_accepts_legacy_aliases() {
        assert_eq!(
            OperationalState::from_str("ack").unwrap(),
            OperationalState::Accepted
        );
        assert_eq!(
            OperationalState::from_str("acknowledged").unwrap(),
            OperationalState::Accepted
        );
        assert_eq!(
            OperationalState::from_str("resolve").unwrap(),
            OperationalState::Mitigated
        );
        assert_eq!(
            OperationalState::from_str("resolved").unwrap(),
            OperationalState::Mitigated
        );
    }

    #[test]
    fn incident_state_accepts_legacy_aliases() {
        assert_eq!(
            IncidentState::from_str("ack").unwrap(),
            IncidentState::Acknowledged
        );
        assert_eq!(
            IncidentState::from_str("resolved").unwrap(),
            IncidentState::Resolved
        );
    }

    #[test]
    fn alert_status_parses_values() {
        assert_eq!(
            AlertDeliveryStatus::from_str("pending").unwrap(),
            AlertDeliveryStatus::Pending
        );
        assert_eq!(
            AlertDeliveryStatus::from_str("dead-letter").unwrap(),
            AlertDeliveryStatus::DeadLetter
        );
    }
}
