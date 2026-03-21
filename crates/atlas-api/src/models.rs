use atlas_jobs::AtlasJob;
use atlas_store::{
    StoredAuditEvent, StoredCurrentFinding, StoredFinding, StoredSavedQuery, StoredSnapshot,
    StoredTelemetryEvent,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

#[derive(Debug, Clone, Serialize)]
pub struct PagedEnvelope<T> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaginationMeta {
    pub limit: usize,
    pub returned: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotRequest {
    pub target: String,
    pub persist: Option<bool>,
    pub dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DriftRequest {
    pub target: String,
    pub older_snapshot_path: Option<String>,
    pub newer_snapshot_path: Option<String>,
    pub persist: Option<bool>,
    pub policy_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingsQuery {
    pub target: String,
    pub severity: Option<String>,
    pub state: Option<String>,
    pub operational_state: Option<String>,
    pub owner: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingPatchRequest {
    pub operational_state: Option<String>,
    pub owner: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryRequestBody {
    pub target: String,
    pub expression: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveQueryRequest {
    pub name: String,
    pub expression: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JobCreateRequest {
    pub target: String,
    pub profile: String,
    pub interval_seconds: u64,
    pub policy_path: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JobRunRequest {
    pub persist: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapTokenRequest {
    pub subject: String,
    pub tenant_id: String,
    pub project_id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionResponse {
    pub name: String,
    pub version: String,
    pub api_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadyResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

pub type FindingsResponse = PagedEnvelope<StoredCurrentFinding>;
pub type JobsResponse = PagedEnvelope<AtlasJob>;
pub type SnapshotsResponse = PagedEnvelope<StoredSnapshot>;
pub type RawFindingsResponse = PagedEnvelope<StoredFinding>;
pub type AuditResponse = PagedEnvelope<StoredAuditEvent>;
pub type QueriesResponse = PagedEnvelope<StoredSavedQuery>;
pub type TelemetryResponse = PagedEnvelope<StoredTelemetryEvent>;
