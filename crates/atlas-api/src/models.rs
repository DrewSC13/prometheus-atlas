use atlas_jobs::AtlasJob;
use atlas_queue::{JobExecutionRecord, JobQueueItem};
use atlas_risk::{
    IncidentOperationsIntelligence, OwnershipIntelligenceReport, RiskReport, SummaryReport,
};
use atlas_store::{
    StoredAlertDelivery, StoredAssetOwner, StoredAuditEvent, StoredCurrentFinding, StoredFinding,
    StoredIncident, StoredSavedQuery, StoredSnapshot, StoredTelemetryEvent,
};
use atlas_tenancy::{AtlasUser, Membership, Organization, Workspace};
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
pub struct IncidentPatchRequest {
    pub state: Option<String>,
    pub owner: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetOwnerUpsertRequest {
    pub resource: String,
    pub owner: String,
    pub team: Option<String>,
    pub business_service: Option<String>,
    pub criticality: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrganizationRequest {
    pub organization_id: Option<String>,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub workspace_id: Option<String>,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub environment: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    pub user_id: Option<String>,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateMembershipRequest {
    pub membership_id: Option<String>,
    pub organization_id: String,
    pub workspace_id: String,
    pub user_id: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct IncidentDetailResponse {
    pub incident: StoredIncident,
    pub related_findings: Vec<StoredCurrentFinding>,
    pub related_owners: Vec<StoredAssetOwner>,
    pub related_executions: Vec<JobExecutionRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnerOperationalSummary {
    pub owner: String,
    pub team: Option<String>,
    pub open_findings: usize,
    pub open_incidents: usize,
    pub total_risk_score: u32,
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrichedTargetReport {
    pub target: String,
    pub summary: SummaryReport,
    pub risk: RiskReport,
    pub ownership: OwnershipIntelligenceReport,
    pub incident_operations: IncidentOperationsIntelligence,
    pub current_incidents: Vec<StoredIncident>,
    pub owner_summaries: Vec<OwnerOperationalSummary>,
}

pub type FindingsResponse = PagedEnvelope<StoredCurrentFinding>;
pub type JobsResponse = PagedEnvelope<AtlasJob>;
pub type JobQueueResponse = PagedEnvelope<JobQueueItem>;
pub type JobExecutionsResponse = PagedEnvelope<JobExecutionRecord>;
pub type SnapshotsResponse = PagedEnvelope<StoredSnapshot>;
pub type RawFindingsResponse = PagedEnvelope<StoredFinding>;
pub type AuditResponse = PagedEnvelope<StoredAuditEvent>;
pub type QueriesResponse = PagedEnvelope<StoredSavedQuery>;
pub type TelemetryResponse = PagedEnvelope<StoredTelemetryEvent>;
pub type OrganizationsResponse = PagedEnvelope<Organization>;
pub type WorkspacesResponse = PagedEnvelope<Workspace>;
pub type UsersResponse = PagedEnvelope<AtlasUser>;
pub type MembershipsResponse = PagedEnvelope<Membership>;
pub type AssetOwnersResponse = PagedEnvelope<StoredAssetOwner>;
pub type IncidentsResponse = PagedEnvelope<StoredIncident>;
pub type AlertDeliveriesResponse = PagedEnvelope<StoredAlertDelivery>;
pub type OwnershipIntelligenceResponse = ApiEnvelope<OwnershipIntelligenceReport>;
pub type IncidentOperationsIntelligenceResponse = ApiEnvelope<IncidentOperationsIntelligence>;
pub type EnrichedTargetReportResponse = ApiEnvelope<EnrichedTargetReport>;
