use anyhow::{anyhow, Result};
use atlas_drift::DriftReport;
use atlas_episodes::RiskEpisode;
use atlas_graph::{EdgeKind, ExposureGraph, GraphEdge, GraphNode, NodeKind};
use atlas_jobs::{AtlasJob, JobDispatchRequest};
use atlas_queue::{JobExecutionRecord, JobQueueItem, JobQueueStatus};
use atlas_snapshot::Snapshot;
use atlas_tenancy::{AtlasUser, Membership, Organization, Workspace, WorkspaceRole};
use chrono::{DateTime, Utc};
use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageScope {
    pub tenant_id: String,
    pub project_id: String,
}

impl StorageScope {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Ndjson,
    Csv,
}

impl FromStr for ExportFormat {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "ndjson" => Ok(Self::Ndjson),
            "csv" => Ok(Self::Csv),
            other => Err(anyhow!("formato no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHistoryItem {
    pub run_id: String,
    pub target: String,
    pub older_snapshot_path: String,
    pub newer_snapshot_path: String,
    pub policy_path: Option<String>,
    pub total_findings: usize,
    pub total_score: u32,
    pub overall_severity: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub finding_id: String,
    pub run_id: String,
    pub target: String,
    pub severity: String,
    pub state: String,
    pub category: String,
    pub title: String,
    pub resource: String,
    pub asset_type: String,
    pub environment: String,
    pub criticality: String,
    pub score: u32,
    pub tags_json: String,
    pub description: String,
    pub is_suppressed: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSnapshot {
    pub snapshot_id: String,
    pub target: String,
    pub timestamp: String,
    pub snapshot_version: u32,
    pub file_hash: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTelemetryEvent {
    pub telemetry_id: String,
    pub name: String,
    pub target: Option<String>,
    pub duration_ms: u128,
    pub metadata_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuditEvent {
    pub audit_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub details_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEpisode {
    pub episode_id: String,
    pub target: String,
    pub title: String,
    pub kind: String,
    pub severity: String,
    pub criticality: String,
    pub score: u32,
    pub state: String,
    pub resource_count: usize,
    pub resources_json: String,
    pub cluster_ids_json: String,
    pub started_at: String,
    pub ended_at: String,
    pub summary: String,
    pub explanation_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGraphRecord {
    pub graph_id: String,
    pub target: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub generated_at: String,
    pub summary_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSavedQuery {
    pub name: String,
    pub expression: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFindingOperationalState {
    pub finding_id: String,
    pub operational_state: String,
    pub owner: Option<String>,
    pub notes: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCurrentFinding {
    pub finding_id: String,
    pub run_id: String,
    pub target: String,
    pub severity: String,
    pub state: String,
    pub category: String,
    pub title: String,
    pub resource: String,
    pub asset_type: String,
    pub environment: String,
    pub criticality: String,
    pub score: u32,
    pub tags_json: String,
    pub description: String,
    pub is_suppressed: bool,
    pub created_at: String,
    pub operational_state: String,
    pub owner: Option<String>,
    pub notes: Option<String>,
    pub operational_updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAssetOwner {
    pub resource: String,
    pub owner: String,
    pub team: Option<String>,
    pub business_service: Option<String>,
    pub criticality: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIncident {
    pub incident_id: String,
    pub target: String,
    pub source_kind: String,
    pub source_id: String,
    pub title: String,
    pub severity: String,
    pub score: u32,
    pub state: String,
    pub owner: Option<String>,
    pub notes: Option<String>,
    pub resource: String,
    pub context_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlertDelivery {
    pub delivery_id: String,
    pub channel: String,
    pub destination: String,
    pub event_type: String,
    pub status: String,
    pub payload_json: String,
    pub response_body: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDeliveryRequest {
    pub channel: String,
    pub destination: String,
    pub event_type: String,
    pub status: String,
    pub payload: Value,
    pub response_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedJob {
    pub scope: StorageScope,
    pub job: AtlasJob,
}

#[derive(Debug, Clone)]
struct TableColumn {
    name: String,
    pk: i64,
}

pub struct AtlasStore {
    conn: Connection,
    db_path: PathBuf,
}

impl AtlasStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        Ok(Self {
            conn,
            db_path: path.to_path_buf(),
        })
    }

    pub fn initialize(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS organizations (
                organization_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspaces (
                workspace_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                environment TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL UNIQUE,
                email TEXT,
                display_name TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS memberships (
                membership_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                snapshot_id TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, snapshot_id)
            );

            CREATE TABLE IF NOT EXISTS drift_runs (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                run_id TEXT NOT NULL,
                target TEXT NOT NULL,
                older_snapshot_path TEXT NOT NULL,
                newer_snapshot_path TEXT NOT NULL,
                policy_path TEXT,
                total_findings INTEGER NOT NULL,
                total_score INTEGER NOT NULL,
                overall_severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, run_id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                finding_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                state TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                resource TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                environment TEXT NOT NULL,
                criticality TEXT NOT NULL,
                score INTEGER NOT NULL,
                tags_json TEXT NOT NULL,
                description TEXT NOT NULL,
                is_suppressed INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, finding_id, run_id)
            );

            CREATE TABLE IF NOT EXISTS telemetry (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                telemetry_id TEXT NOT NULL,
                name TEXT NOT NULL,
                target TEXT,
                duration_ms TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, telemetry_id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                audit_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                job_id TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                policy_path TEXT,
                last_run_at TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, job_id)
            );

            CREATE TABLE IF NOT EXISTS baseline_entries (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                resource TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, resource)
            );

            CREATE TABLE IF NOT EXISTS episodes (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                episode_id TEXT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                criticality TEXT NOT NULL,
                score INTEGER NOT NULL,
                state TEXT NOT NULL,
                resource_count INTEGER NOT NULL,
                resources_json TEXT NOT NULL,
                cluster_ids_json TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                explanation_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, episode_id)
            );

            CREATE TABLE IF NOT EXISTS graphs (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                graph_id TEXT NOT NULL,
                target TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, graph_id)
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                graph_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, graph_id, node_id)
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                graph_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                target TEXT NOT NULL,
                from_node TEXT NOT NULL,
                to_node TEXT NOT NULL,
                kind TEXT NOT NULL,
                weight INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, graph_id, edge_id)
            );

            CREATE TABLE IF NOT EXISTS saved_queries (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                expression TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, name)
            );

            CREATE TABLE IF NOT EXISTS finding_state (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                finding_id TEXT NOT NULL,
                operational_state TEXT NOT NULL,
                owner TEXT,
                notes TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, finding_id)
            );

            CREATE TABLE IF NOT EXISTS job_queue (
                queue_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                policy_path TEXT,
                trigger TEXT NOT NULL,
                requested_by TEXT,
                persist_artifacts INTEGER NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                available_at TEXT NOT NULL,
                claimed_by TEXT,
                claimed_at TEXT,
                lease_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS job_executions (
                execution_id TEXT PRIMARY KEY,
                queue_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                worker_id TEXT,
                status TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asset_owners (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                owner TEXT NOT NULL,
                team TEXT,
                business_service TEXT,
                criticality TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, resource)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                target TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                state TEXT NOT NULL,
                owner TEXT,
                notes TEXT,
                resource TEXT NOT NULL,
                context_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, incident_id)
            );

            CREATE TABLE IF NOT EXISTS alert_deliveries (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                delivery_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                response_body TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, delivery_id)
            );
            "#,
        )?;

        self.repair_legacy_tables_if_needed()?;
        self.bootstrap_default_tenancy()?;
        self.create_indexes()?;
        Ok(())
    }

    fn create_indexes(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_jobs_scope_created_at
            ON jobs (tenant_id, project_id, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_findings_scope_target
            ON findings (tenant_id, project_id, target, score DESC, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_snapshots_scope_target
            ON snapshots (tenant_id, project_id, target, timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_job_queue_scope_status
            ON job_queue (tenant_id, project_id, status, available_at ASC, created_at ASC);

            CREATE INDEX IF NOT EXISTS idx_job_queue_job
            ON job_queue (tenant_id, project_id, job_id, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_saved_queries_scope
            ON saved_queries (tenant_id, project_id, name ASC);

            CREATE INDEX IF NOT EXISTS idx_finding_state_scope
            ON finding_state (tenant_id, project_id, finding_id);

            CREATE INDEX IF NOT EXISTS idx_audit_scope
            ON audit_events (tenant_id, project_id, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_job_executions_scope_job
            ON job_executions (tenant_id, project_id, job_id, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_job_executions_queue
            ON job_executions (queue_id, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_asset_owners_scope
            ON asset_owners (tenant_id, project_id, resource ASC);

            CREATE INDEX IF NOT EXISTS idx_incidents_scope
            ON incidents (tenant_id, project_id, state, score DESC, updated_at DESC);

            CREATE INDEX IF NOT EXISTS idx_alert_deliveries_scope
            ON alert_deliveries (tenant_id, project_id, created_at DESC);
            "#,
        )?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn bootstrap_default_tenancy(&self) -> Result<()> {
        let org = Organization {
            organization_id: "default".to_string(),
            name: "Default".to_string(),
            slug: "default".to_string(),
            created_at: Utc::now(),
        };
        self.upsert_organization(&org)?;

        let workspace = Workspace {
            workspace_id: "default".to_string(),
            organization_id: "default".to_string(),
            name: "Default".to_string(),
            slug: "default".to_string(),
            environment: "default".to_string(),
            created_at: Utc::now(),
        };
        self.upsert_workspace(&workspace)?;

        Ok(())
    }

    pub fn upsert_organization(&self, org: &Organization) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO organizations (
                organization_id,
                name,
                slug,
                created_at
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(organization_id) DO UPDATE SET
                name = excluded.name,
                slug = excluded.slug
            "#,
            params![
                org.organization_id,
                org.name,
                org.slug,
                org.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_organizations(&self) -> Result<Vec<Organization>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT organization_id, name, slug, created_at
            FROM organizations
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Organization {
                organization_id: row_string(row, 0)?,
                name: row_string(row, 1)?,
                slug: row_string(row, 2)?,
                created_at: parse_datetime(row_string(row, 3)?)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn upsert_workspace(&self, workspace: &Workspace) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO workspaces (
                workspace_id,
                organization_id,
                name,
                slug,
                environment,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(workspace_id) DO UPDATE SET
                organization_id = excluded.organization_id,
                name = excluded.name,
                slug = excluded.slug,
                environment = excluded.environment
            "#,
            params![
                workspace.workspace_id,
                workspace.organization_id,
                workspace.name,
                workspace.slug,
                workspace.environment,
                workspace.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_workspaces_by_org(&self, organization_id: &str) -> Result<Vec<Workspace>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT workspace_id, organization_id, name, slug, environment, created_at
            FROM workspaces
            WHERE organization_id = ?1
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map([organization_id], |row| {
            Ok(Workspace {
                workspace_id: row_string(row, 0)?,
                organization_id: row_string(row, 1)?,
                name: row_string(row, 2)?,
                slug: row_string(row, 3)?,
                environment: row_string(row, 4)?,
                created_at: parse_datetime(row_string(row, 5)?)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn upsert_user(&self, user: &AtlasUser) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO users (
                user_id,
                subject,
                email,
                display_name,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(subject) DO UPDATE SET
                email = excluded.email,
                display_name = excluded.display_name
            "#,
            params![
                user.user_id,
                user.subject,
                user.email,
                user.display_name,
                user.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<AtlasUser>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT user_id, subject, email, display_name, created_at
            FROM users
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AtlasUser {
                user_id: row_string(row, 0)?,
                subject: row_string(row, 1)?,
                email: row_optional_string(row, 2)?,
                display_name: row_optional_string(row, 3)?,
                created_at: parse_datetime(row_string(row, 4)?)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn upsert_membership(&self, membership: &Membership) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO memberships (
                membership_id,
                organization_id,
                workspace_id,
                user_id,
                role,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(membership_id) DO UPDATE SET
                role = excluded.role
            "#,
            params![
                membership.membership_id,
                membership.organization_id,
                membership.workspace_id,
                membership.user_id,
                membership.role.to_string(),
                membership.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_memberships_scoped(&self, scope: &StorageScope) -> Result<Vec<Membership>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT membership_id, organization_id, workspace_id, user_id, role, created_at
            FROM memberships
            WHERE organization_id = ?1 AND workspace_id = ?2
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id], |row| {
            let role = WorkspaceRole::from_str(&row_string(row, 4)?)
                .map_err(|e| to_sql_err(anyhow!(e)))?;
            Ok(Membership {
                membership_id: row_string(row, 0)?,
                organization_id: row_string(row, 1)?,
                workspace_id: row_string(row, 2)?,
                user_id: row_string(row, 3)?,
                role,
                created_at: parse_datetime(row_string(row, 5)?)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn register_snapshot(&self, path: &Path, snapshot: &Snapshot) -> Result<()> {
        self.register_snapshot_scoped(&StorageScope::global(), path, snapshot)
    }

    pub fn register_snapshot_scoped(
        &self,
        scope: &StorageScope,
        path: &Path,
        snapshot: &Snapshot,
    ) -> Result<()> {
        let snapshot_id = format!(
            "{}:{}",
            snapshot.target,
            snapshot
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );

        let file_hash = compute_snapshot_hash(path)?;

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO snapshots (
                tenant_id,
                project_id,
                snapshot_id,
                target,
                timestamp,
                snapshot_version,
                file_hash,
                path,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                snapshot_id,
                snapshot.target,
                snapshot.timestamp.to_rfc3339(),
                snapshot.snapshot_version,
                file_hash,
                path.display().to_string(),
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn register_drift_report(
        &self,
        target: &str,
        older_snapshot: &Path,
        newer_snapshot: &Path,
        policy_path: Option<&Path>,
        report: &DriftReport,
    ) -> Result<()> {
        self.register_drift_report_scoped(
            &StorageScope::global(),
            target,
            older_snapshot,
            newer_snapshot,
            policy_path,
            report,
        )
    }

    pub fn register_drift_report_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
        older_snapshot: &Path,
        newer_snapshot: &Path,
        policy_path: Option<&Path>,
        report: &DriftReport,
    ) -> Result<()> {
        let run_id = format!(
            "{}:{}:{}",
            target,
            report.older_timestamp.to_rfc3339(),
            report.newer_timestamp.to_rfc3339()
        );

        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO drift_runs (
                tenant_id,
                project_id,
                run_id,
                target,
                older_snapshot_path,
                newer_snapshot_path,
                policy_path,
                total_findings,
                total_score,
                overall_severity,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                run_id,
                target,
                older_snapshot.display().to_string(),
                newer_snapshot.display().to_string(),
                policy_path.map(|p| p.display().to_string()),
                report.findings.len(),
                report.summary.total_score,
                report.summary.overall_severity.to_string(),
                now,
            ],
        )?;

        for finding in &report.findings {
            self.insert_finding(scope, &run_id, target, finding, false)?;
        }

        for finding in &report.suppressed_findings {
            self.insert_finding(scope, &run_id, target, finding, true)?;
        }

        Ok(())
    }

    fn insert_finding(
        &self,
        scope: &StorageScope,
        run_id: &str,
        target: &str,
        finding: &atlas_drift::DriftFinding,
        is_suppressed: bool,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO findings (
                tenant_id,
                project_id,
                finding_id,
                run_id,
                target,
                severity,
                state,
                category,
                title,
                resource,
                asset_type,
                environment,
                criticality,
                score,
                tags_json,
                description,
                is_suppressed,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                finding.finding_id,
                run_id,
                target,
                finding.severity.to_string(),
                finding.state.to_string(),
                finding.category,
                finding.title,
                finding.resource,
                finding.asset_type.to_string(),
                finding.environment.to_string(),
                finding.criticality.to_string(),
                finding.score,
                serde_json::to_string(&finding.tags)?,
                finding.description,
                if is_suppressed { 1 } else { 0 },
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn list_history(&self, target: &str) -> Result<Vec<StoredHistoryItem>> {
        self.list_history_scoped(&StorageScope::global(), target)
    }

    pub fn list_history_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
    ) -> Result<Vec<StoredHistoryItem>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                run_id,
                target,
                older_snapshot_path,
                newer_snapshot_path,
                policy_path,
                total_findings,
                total_score,
                overall_severity,
                created_at
            FROM drift_runs
            WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
            ORDER BY created_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id, target], |row| {
            Ok(StoredHistoryItem {
                run_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                older_snapshot_path: row_string(row, 2)?,
                newer_snapshot_path: row_string(row, 3)?,
                policy_path: row_optional_string(row, 4)?,
                total_findings: row_u64(row, 5)? as usize,
                total_score: row_u64(row, 6)? as u32,
                overall_severity: row_string(row, 7)?,
                created_at: row_string(row, 8)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn list_findings(
        &self,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
    ) -> Result<Vec<StoredFinding>> {
        self.list_findings_scoped(&StorageScope::global(), target, severity, state)
    }

    pub fn list_findings_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
    ) -> Result<Vec<StoredFinding>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                finding_id,
                run_id,
                target,
                severity,
                state,
                category,
                title,
                resource,
                asset_type,
                environment,
                criticality,
                score,
                tags_json,
                description,
                is_suppressed,
                created_at
            FROM findings
            WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
            ORDER BY score DESC, created_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id, target], |row| {
            Ok(StoredFinding {
                finding_id: row_string(row, 0)?,
                run_id: row_string(row, 1)?,
                target: row_string(row, 2)?,
                severity: row_string(row, 3)?,
                state: row_string(row, 4)?,
                category: row_string(row, 5)?,
                title: row_string(row, 6)?,
                resource: row_string(row, 7)?,
                asset_type: row_string(row, 8)?,
                environment: row_string(row, 9)?,
                criticality: row_string(row, 10)?,
                score: row_u64(row, 11)? as u32,
                tags_json: row_string(row, 12)?,
                description: row_string(row, 13)?,
                is_suppressed: row_bool(row, 14)?,
                created_at: row_string(row, 15)?,
            })
        })?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row?);
        }

        if let Some(severity_filter) = severity {
            findings.retain(|f| f.severity.eq_ignore_ascii_case(severity_filter));
        }

        if let Some(state_filter) = state {
            findings.retain(|f| f.state.eq_ignore_ascii_case(state_filter));
        }

        Ok(findings)
    }

    pub fn finding_exists_scoped(&self, scope: &StorageScope, finding_id: &str) -> Result<bool> {
        let found = self.conn.query_row(
            r#"
            SELECT 1
            FROM findings
            WHERE tenant_id = ?1 AND project_id = ?2 AND finding_id = ?3
            LIMIT 1
            "#,
            params![scope.tenant_id, scope.project_id, finding_id],
            |_row| Ok(true),
        );

        match found {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub fn get_finding_operational_state(
        &self,
        finding_id: &str,
    ) -> Result<Option<StoredFindingOperationalState>> {
        self.get_finding_operational_state_scoped(&StorageScope::global(), finding_id)
    }

    pub fn get_finding_operational_state_scoped(
        &self,
        scope: &StorageScope,
        finding_id: &str,
    ) -> Result<Option<StoredFindingOperationalState>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT
                    finding_id,
                    operational_state,
                    owner,
                    notes,
                    updated_at
                FROM finding_state
                WHERE tenant_id = ?1 AND project_id = ?2 AND finding_id = ?3
                "#,
                params![scope.tenant_id, scope.project_id, finding_id],
                |row| {
                    Ok(StoredFindingOperationalState {
                        finding_id: row_string(row, 0)?,
                        operational_state: row_string(row, 1)?,
                        owner: row_optional_string(row, 2)?,
                        notes: row_optional_string(row, 3)?,
                        updated_at: row_string(row, 4)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    pub fn set_finding_operational_state(
        &self,
        finding_id: &str,
        operational_state: &str,
    ) -> Result<()> {
        self.set_finding_operational_state_scoped(
            &StorageScope::global(),
            finding_id,
            operational_state,
        )
    }

    pub fn set_finding_operational_state_scoped(
        &self,
        scope: &StorageScope,
        finding_id: &str,
        operational_state: &str,
    ) -> Result<()> {
        self.ensure_finding_for_triage(scope, finding_id)?;
        let current = self.get_finding_operational_state_scoped(scope, finding_id)?;
        let owner = current.as_ref().and_then(|c| c.owner.clone());
        let notes = current.as_ref().and_then(|c| c.notes.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                tenant_id,
                project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(tenant_id, project_id, finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn assign_finding_owner(&self, finding_id: &str, owner: &str) -> Result<()> {
        self.assign_finding_owner_scoped(&StorageScope::global(), finding_id, owner)
    }

    pub fn assign_finding_owner_scoped(
        &self,
        scope: &StorageScope,
        finding_id: &str,
        owner: &str,
    ) -> Result<()> {
        self.ensure_finding_for_triage(scope, finding_id)?;
        let current = self.get_finding_operational_state_scoped(scope, finding_id)?;
        let operational_state = current
            .as_ref()
            .map(|c| c.operational_state.clone())
            .unwrap_or_else(|| "open".to_string());
        let notes = current.as_ref().and_then(|c| c.notes.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                tenant_id,
                project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(tenant_id, project_id, finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn set_finding_note(&self, finding_id: &str, notes: &str) -> Result<()> {
        self.set_finding_note_scoped(&StorageScope::global(), finding_id, notes)
    }

    pub fn set_finding_note_scoped(
        &self,
        scope: &StorageScope,
        finding_id: &str,
        notes: &str,
    ) -> Result<()> {
        self.ensure_finding_for_triage(scope, finding_id)?;
        let current = self.get_finding_operational_state_scoped(scope, finding_id)?;
        let operational_state = current
            .as_ref()
            .map(|c| c.operational_state.clone())
            .unwrap_or_else(|| "open".to_string());
        let owner = current.as_ref().and_then(|c| c.owner.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                tenant_id,
                project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(tenant_id, project_id, finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn list_current_findings_operational(
        &self,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
        operational_state: Option<&str>,
        owner: Option<&str>,
    ) -> Result<Vec<StoredCurrentFinding>> {
        self.list_current_findings_operational_scoped(
            &StorageScope::global(),
            target,
            severity,
            state,
            operational_state,
            owner,
        )
    }

    pub fn list_current_findings_operational_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
        operational_state: Option<&str>,
        owner: Option<&str>,
    ) -> Result<Vec<StoredCurrentFinding>> {
        let findings = self.list_findings_scoped(scope, target, severity, state)?;
        let mut latest_by_finding: BTreeMap<String, StoredFinding> = BTreeMap::new();

        for finding in findings {
            latest_by_finding
                .entry(finding.finding_id.clone())
                .or_insert(finding);
        }

        let asset_owners = self.list_asset_owners_scoped(scope, None)?;
        let asset_owner_map = asset_owners
            .into_iter()
            .map(|item| (item.resource, item.owner))
            .collect::<BTreeMap<_, _>>();

        let mut items = Vec::new();

        for (_, finding) in latest_by_finding {
            let triage = self.get_finding_operational_state_scoped(scope, &finding.finding_id)?;
            let op_state = triage
                .as_ref()
                .map(|t| t.operational_state.clone())
                .unwrap_or_else(|| "open".to_string());
            let op_owner = triage
                .as_ref()
                .and_then(|t| t.owner.clone())
                .or_else(|| asset_owner_map.get(&finding.resource).cloned());
            let op_notes = triage.as_ref().and_then(|t| t.notes.clone());
            let op_updated_at = triage.as_ref().map(|t| t.updated_at.clone());

            items.push(StoredCurrentFinding {
                finding_id: finding.finding_id,
                run_id: finding.run_id,
                target: finding.target,
                severity: finding.severity,
                state: finding.state,
                category: finding.category,
                title: finding.title,
                resource: finding.resource,
                asset_type: finding.asset_type,
                environment: finding.environment,
                criticality: finding.criticality,
                score: finding.score,
                tags_json: finding.tags_json,
                description: finding.description,
                is_suppressed: finding.is_suppressed,
                created_at: finding.created_at,
                operational_state: op_state,
                owner: op_owner,
                notes: op_notes,
                operational_updated_at: op_updated_at,
            });
        }

        if let Some(filter) = operational_state {
            items.retain(|f| f.operational_state.eq_ignore_ascii_case(filter));
        }

        if let Some(filter) = owner {
            items.retain(|f| {
                f.owner
                    .as_deref()
                    .map(|owner_value| owner_value.eq_ignore_ascii_case(filter))
                    .unwrap_or(false)
            });
        }

        items.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.operational_state.cmp(&b.operational_state))
                .then_with(|| a.finding_id.cmp(&b.finding_id))
        });

        Ok(items)
    }

    fn ensure_finding_for_triage(&self, scope: &StorageScope, finding_id: &str) -> Result<()> {
        if !self.finding_exists_scoped(scope, finding_id)? {
            return Err(anyhow!("finding no encontrado: {finding_id}"));
        }
        Ok(())
    }

    pub fn list_snapshots(&self, target: &str) -> Result<Vec<StoredSnapshot>> {
        self.list_snapshots_scoped(&StorageScope::global(), target)
    }

    pub fn list_snapshots_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
    ) -> Result<Vec<StoredSnapshot>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                snapshot_id,
                target,
                timestamp,
                snapshot_version,
                file_hash,
                path,
                created_at
            FROM snapshots
            WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
            ORDER BY timestamp DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id, target], |row| {
            Ok(StoredSnapshot {
                snapshot_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                timestamp: row_string(row, 2)?,
                snapshot_version: row_u64(row, 3)? as u32,
                file_hash: row_string(row, 4)?,
                path: row_string(row, 5)?,
                created_at: row_string(row, 6)?,
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }
        Ok(snapshots)
    }

    pub fn record_telemetry(
        &self,
        name: &str,
        target: Option<&str>,
        duration_ms: u128,
        metadata: &Value,
    ) -> Result<()> {
        self.record_telemetry_scoped(&StorageScope::global(), name, target, duration_ms, metadata)
    }

    pub fn record_telemetry_scoped(
        &self,
        scope: &StorageScope,
        name: &str,
        target: Option<&str>,
        duration_ms: u128,
        metadata: &Value,
    ) -> Result<()> {
        let telemetry_id = format!("{}:{}", name, Utc::now().timestamp_nanos_opt().unwrap_or(0));

        self.conn.execute(
            r#"
            INSERT INTO telemetry (
                tenant_id,
                project_id,
                telemetry_id,
                name,
                target,
                duration_ms,
                metadata_json,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                telemetry_id,
                name,
                target,
                duration_ms.to_string(),
                serde_json::to_string(metadata)?,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn list_telemetry(&self, limit: usize) -> Result<Vec<StoredTelemetryEvent>> {
        self.list_telemetry_scoped(&StorageScope::global(), limit)
    }

    pub fn list_telemetry_scoped(
        &self,
        scope: &StorageScope,
        limit: usize,
    ) -> Result<Vec<StoredTelemetryEvent>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                telemetry_id,
                name,
                target,
                duration_ms,
                metadata_json,
                created_at
            FROM telemetry
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY created_at DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(
            params![scope.tenant_id, scope.project_id, limit as i64],
            |row| {
                let duration_raw = row_string(row, 3)?;
                let duration_ms = duration_raw.parse::<u128>().unwrap_or(0);

                Ok(StoredTelemetryEvent {
                    telemetry_id: row_string(row, 0)?,
                    name: row_string(row, 1)?,
                    target: row_optional_string(row, 2)?,
                    duration_ms,
                    metadata_json: row_string(row, 4)?,
                    created_at: row_string(row, 5)?,
                })
            },
        )?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn record_audit_event(
        &self,
        actor: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        details: &Value,
    ) -> Result<()> {
        self.record_audit_event_scoped(
            &StorageScope::global(),
            actor,
            action,
            resource_type,
            resource_id,
            details,
        )
    }

    pub fn record_audit_event_scoped(
        &self,
        scope: &StorageScope,
        actor: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        details: &Value,
    ) -> Result<()> {
        let audit_id = format!(
            "{}:{}:{}:{}",
            scope.tenant_id,
            action,
            resource_id,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        self.conn.execute(
            r#"
            INSERT INTO audit_events (
                audit_id,
                tenant_id,
                project_id,
                actor,
                action,
                resource_type,
                resource_id,
                details_json,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                audit_id,
                scope.tenant_id,
                scope.project_id,
                actor,
                action,
                resource_type,
                resource_id,
                serde_json::to_string(details)?,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn list_audit_events(&self, limit: usize) -> Result<Vec<StoredAuditEvent>> {
        self.list_audit_events_scoped(&StorageScope::global(), limit)
    }

    pub fn list_audit_events_scoped(
        &self,
        scope: &StorageScope,
        limit: usize,
    ) -> Result<Vec<StoredAuditEvent>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                audit_id,
                tenant_id,
                project_id,
                actor,
                action,
                resource_type,
                resource_id,
                details_json,
                created_at
            FROM audit_events
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY created_at DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(
            params![scope.tenant_id, scope.project_id, limit as i64],
            |row| {
                Ok(StoredAuditEvent {
                    audit_id: row_string(row, 0)?,
                    tenant_id: row_string(row, 1)?,
                    project_id: row_string(row, 2)?,
                    actor: row_string(row, 3)?,
                    action: row_string(row, 4)?,
                    resource_type: row_string(row, 5)?,
                    resource_id: row_string(row, 6)?,
                    details_json: row_string(row, 7)?,
                    created_at: row_string(row, 8)?,
                })
            },
        )?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn export_findings(
        &self,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
        format: ExportFormat,
        output: &Path,
    ) -> Result<()> {
        let findings = self.list_findings(target, severity, state)?;

        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }

        match format {
            ExportFormat::Json => {
                let content = serde_json::to_string_pretty(&findings)?;
                fs::write(output, content)?;
            }
            ExportFormat::Ndjson => {
                let mut out = String::new();
                for finding in findings {
                    out.push_str(&serde_json::to_string(&finding)?);
                    out.push('\n');
                }
                fs::write(output, out)?;
            }
            ExportFormat::Csv => {
                let mut out = String::from(
                    "finding_id,run_id,target,severity,state,category,title,resource,asset_type,environment,criticality,score,is_suppressed,created_at\n",
                );
                for finding in findings {
                    out.push_str(&format!(
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"\n",
                        escape_csv(&finding.finding_id),
                        escape_csv(&finding.run_id),
                        escape_csv(&finding.target),
                        escape_csv(&finding.severity),
                        escape_csv(&finding.state),
                        escape_csv(&finding.category),
                        escape_csv(&finding.title),
                        escape_csv(&finding.resource),
                        escape_csv(&finding.asset_type),
                        escape_csv(&finding.environment),
                        escape_csv(&finding.criticality),
                        finding.score,
                        if finding.is_suppressed { "true" } else { "false" },
                        escape_csv(&finding.created_at),
                    ));
                }
                fs::write(output, out)?;
            }
        }

        Ok(())
    }

    pub fn list_jobs(&self) -> Result<Vec<AtlasJob>> {
        self.list_jobs_scoped(&StorageScope::global())
    }

    pub fn list_jobs_scoped(&self, scope: &StorageScope) -> Result<Vec<AtlasJob>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                job_id,
                target,
                profile,
                interval_seconds,
                enabled,
                policy_path,
                last_run_at,
                created_at
            FROM jobs
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY created_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id], |row| {
            Ok(AtlasJob {
                job_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                profile: row_string(row, 2)?,
                interval_seconds: row_u64(row, 3)? as u64,
                enabled: row_bool(row, 4)?,
                policy_path: row_optional_string(row, 5)?,
                last_run_at: parse_optional_datetime(row_optional_string(row, 6)?),
                created_at: parse_datetime(row_string(row, 7)?)?,
            })
        })?;

        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    pub fn list_all_jobs_with_scope(&self) -> Result<Vec<ScopedJob>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                tenant_id,
                project_id,
                job_id,
                target,
                profile,
                interval_seconds,
                enabled,
                policy_path,
                last_run_at,
                created_at
            FROM jobs
            ORDER BY created_at DESC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ScopedJob {
                scope: StorageScope::new(row_string(row, 0)?, row_string(row, 1)?),
                job: AtlasJob {
                    job_id: row_string(row, 2)?,
                    target: row_string(row, 3)?,
                    profile: row_string(row, 4)?,
                    interval_seconds: row_u64(row, 5)? as u64,
                    enabled: row_bool(row, 6)?,
                    policy_path: row_optional_string(row, 7)?,
                    last_run_at: parse_optional_datetime(row_optional_string(row, 8)?),
                    created_at: parse_datetime(row_string(row, 9)?)?,
                },
            })
        })?;

        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    pub fn load_job_scoped(&self, scope: &StorageScope, job_id: &str) -> Result<Option<AtlasJob>> {
        self.list_jobs_scoped(scope)
            .map(|items| items.into_iter().find(|item| item.job_id == job_id))
    }

    pub fn insert_job(&self, job: &AtlasJob) -> Result<()> {
        self.insert_job_scoped(&StorageScope::global(), job)
    }

    pub fn insert_job_scoped(&self, scope: &StorageScope, job: &AtlasJob) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO jobs (
                tenant_id,
                project_id,
                job_id,
                target,
                profile,
                interval_seconds,
                enabled,
                policy_path,
                last_run_at,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                job.job_id,
                job.target,
                job.profile,
                job.interval_seconds,
                if job.enabled { 1 } else { 0 },
                job.policy_path,
                job.last_run_at.map(|d| d.to_rfc3339()),
                job.created_at.to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn touch_job_run(&self, job_id: &str) -> Result<()> {
        self.touch_job_run_scoped(&StorageScope::global(), job_id)
    }

    pub fn touch_job_run_scoped(&self, scope: &StorageScope, job_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE jobs
            SET last_run_at = ?1
            WHERE tenant_id = ?2 AND project_id = ?3 AND job_id = ?4
            "#,
            params![
                Utc::now().to_rfc3339(),
                scope.tenant_id,
                scope.project_id,
                job_id
            ],
        )?;

        Ok(())
    }

    pub fn delete_job_scoped(&self, scope: &StorageScope, job_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM jobs
            WHERE tenant_id = ?1 AND project_id = ?2 AND job_id = ?3
            "#,
            params![scope.tenant_id, scope.project_id, job_id],
        )?;
        Ok(())
    }

    pub fn enqueue_job_dispatch_scoped(
        &self,
        scope: &StorageScope,
        dispatch: &JobDispatchRequest,
    ) -> Result<JobQueueItem> {
        let mut scoped_dispatch = dispatch.clone();
        scoped_dispatch.tenant_id = scope.tenant_id.clone();
        scoped_dispatch.project_id = scope.project_id.clone();

        let item = JobQueueItem::from_dispatch(scoped_dispatch);

        self.conn.execute(
            r#"
            INSERT INTO job_queue (
                queue_id,
                tenant_id,
                project_id,
                job_id,
                target,
                profile,
                policy_path,
                trigger,
                requested_by,
                persist_artifacts,
                status,
                attempts,
                max_attempts,
                available_at,
                claimed_by,
                claimed_at,
                lease_expires_at,
                created_at,
                updated_at,
                last_error
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
            )
            "#,
            params![
                item.queue_id,
                item.tenant_id,
                item.project_id,
                item.job_id,
                item.target,
                item.profile,
                item.policy_path,
                item.trigger,
                item.requested_by,
                if item.persist_artifacts { 1 } else { 0 },
                item.status.to_string(),
                item.attempts,
                item.max_attempts,
                item.available_at.to_rfc3339(),
                item.claimed_by,
                item.claimed_at.map(|d| d.to_rfc3339()),
                item.lease_expires_at.map(|d| d.to_rfc3339()),
                item.created_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
                item.last_error,
            ],
        )?;

        self.append_job_execution_from_queue(&item, None, None, None)?;
        Ok(item)
    }

    pub fn list_job_queue_scoped(
        &self,
        scope: &StorageScope,
        limit: usize,
    ) -> Result<Vec<JobQueueItem>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                queue_id,
                tenant_id,
                project_id,
                job_id,
                target,
                profile,
                policy_path,
                trigger,
                requested_by,
                persist_artifacts,
                status,
                attempts,
                max_attempts,
                available_at,
                claimed_by,
                claimed_at,
                lease_expires_at,
                created_at,
                updated_at,
                last_error
            FROM job_queue
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY created_at DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(
            params![scope.tenant_id, scope.project_id, limit as i64],
            map_job_queue_item,
        )?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn get_job_queue_item_scoped(
        &self,
        scope: &StorageScope,
        queue_id: &str,
    ) -> Result<Option<JobQueueItem>> {
        let item = self
            .conn
            .query_row(
                r#"
                SELECT
                    queue_id,
                    tenant_id,
                    project_id,
                    job_id,
                    target,
                    profile,
                    policy_path,
                    trigger,
                    requested_by,
                    persist_artifacts,
                    status,
                    attempts,
                    max_attempts,
                    available_at,
                    claimed_by,
                    claimed_at,
                    lease_expires_at,
                    created_at,
                    updated_at,
                    last_error
                FROM job_queue
                WHERE tenant_id = ?1 AND project_id = ?2 AND queue_id = ?3
                "#,
                params![scope.tenant_id, scope.project_id, queue_id],
                map_job_queue_item,
            )
            .optional()?;

        Ok(item)
    }

    pub fn get_job_queue_item(&self, queue_id: &str) -> Result<Option<JobQueueItem>> {
        let item = self
            .conn
            .query_row(
                r#"
                SELECT
                    queue_id,
                    tenant_id,
                    project_id,
                    job_id,
                    target,
                    profile,
                    policy_path,
                    trigger,
                    requested_by,
                    persist_artifacts,
                    status,
                    attempts,
                    max_attempts,
                    available_at,
                    claimed_by,
                    claimed_at,
                    lease_expires_at,
                    created_at,
                    updated_at,
                    last_error
                FROM job_queue
                WHERE queue_id = ?1
                "#,
                [queue_id],
                map_job_queue_item,
            )
            .optional()?;

        Ok(item)
    }

    pub fn job_has_active_queue_item_scoped(
        &self,
        scope: &StorageScope,
        job_id: &str,
    ) -> Result<bool> {
        let found = self.conn.query_row(
            r#"
            SELECT 1
            FROM job_queue
            WHERE tenant_id = ?1
              AND project_id = ?2
              AND job_id = ?3
              AND status IN ('pending', 'claimed', 'running')
            LIMIT 1
            "#,
            params![scope.tenant_id, scope.project_id, job_id],
            |_row| Ok(true),
        );

        match found {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub fn claim_next_job_queue_item(
        &self,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<JobQueueItem>> {
        let now = Utc::now().to_rfc3339();

        let candidate = self
            .conn
            .query_row(
                r#"
                SELECT
                    queue_id,
                    tenant_id,
                    project_id,
                    job_id,
                    target,
                    profile,
                    policy_path,
                    trigger,
                    requested_by,
                    persist_artifacts,
                    status,
                    attempts,
                    max_attempts,
                    available_at,
                    claimed_by,
                    claimed_at,
                    lease_expires_at,
                    created_at,
                    updated_at,
                    last_error
                FROM job_queue
                WHERE status = 'pending' AND available_at <= ?1
                ORDER BY available_at ASC, created_at ASC
                LIMIT 1
                "#,
                [now],
                map_job_queue_item,
            )
            .optional()?;

        let Some(mut item) = candidate else {
            return Ok(None);
        };

        item.claim(worker_id.to_string(), lease_seconds);

        let updated = self.conn.execute(
            r#"
            UPDATE job_queue
            SET
                status = ?1,
                claimed_by = ?2,
                claimed_at = ?3,
                lease_expires_at = ?4,
                updated_at = ?5
            WHERE queue_id = ?6 AND status = 'pending'
            "#,
            params![
                item.status.to_string(),
                item.claimed_by,
                item.claimed_at.map(|d| d.to_rfc3339()),
                item.lease_expires_at.map(|d| d.to_rfc3339()),
                item.updated_at.to_rfc3339(),
                item.queue_id
            ],
        )?;

        if updated == 0 {
            return Ok(None);
        }

        self.append_job_execution_from_queue(&item, None, None, None)?;
        Ok(Some(item))
    }

    pub fn mark_job_queue_running(&self, queue_id: &str) -> Result<Option<JobQueueItem>> {
        let Some(mut item) = self.get_job_queue_item(queue_id)? else {
            return Ok(None);
        };

        item.start();

        self.conn.execute(
            r#"
            UPDATE job_queue
            SET status = ?1, updated_at = ?2
            WHERE queue_id = ?3
            "#,
            params![
                item.status.to_string(),
                item.updated_at.to_rfc3339(),
                item.queue_id
            ],
        )?;

        self.append_job_execution_from_queue(&item, None, None, None)?;
        Ok(Some(item))
    }

    pub fn mark_job_queue_succeeded(
        &self,
        queue_id: &str,
        result: &Value,
    ) -> Result<Option<JobQueueItem>> {
        let Some(mut item) = self.get_job_queue_item(queue_id)? else {
            return Ok(None);
        };

        item.succeed();

        self.conn.execute(
            r#"
            UPDATE job_queue
            SET
                status = ?1,
                updated_at = ?2,
                lease_expires_at = NULL
            WHERE queue_id = ?3
            "#,
            params![
                item.status.to_string(),
                item.updated_at.to_rfc3339(),
                item.queue_id
            ],
        )?;

        self.append_job_execution_from_queue(&item, Some(result), None, Some(Utc::now()))?;
        Ok(Some(item))
    }

    pub fn mark_job_queue_failed(
        &self,
        queue_id: &str,
        error_message: &str,
        retry_delay_seconds: Option<u64>,
    ) -> Result<Option<JobQueueItem>> {
        let Some(mut item) = self.get_job_queue_item(queue_id)? else {
            return Ok(None);
        };

        item.fail(error_message.to_string(), retry_delay_seconds);

        self.conn.execute(
            r#"
            UPDATE job_queue
            SET
                status = ?1,
                attempts = ?2,
                available_at = ?3,
                claimed_by = NULL,
                claimed_at = NULL,
                lease_expires_at = NULL,
                updated_at = ?4,
                last_error = ?5
            WHERE queue_id = ?6
            "#,
            params![
                item.status.to_string(),
                item.attempts,
                item.available_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
                item.last_error,
                item.queue_id
            ],
        )?;

        self.append_job_execution_from_queue(
            &item,
            None,
            Some(error_message.to_string()),
            Some(Utc::now()),
        )?;
        Ok(Some(item))
    }

    fn append_job_execution_from_queue(
        &self,
        item: &JobQueueItem,
        result_json: Option<&Value>,
        error_message: Option<String>,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let execution = JobExecutionRecord {
            execution_id: format!(
                "{}:{}",
                item.queue_id,
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            queue_id: item.queue_id.clone(),
            tenant_id: item.tenant_id.clone(),
            project_id: item.project_id.clone(),
            job_id: item.job_id.clone(),
            worker_id: item.claimed_by.clone(),
            status: item.status,
            started_at: item.claimed_at,
            finished_at,
            result_json: result_json.map(serde_json::to_string).transpose()?,
            error_message,
            created_at: Utc::now(),
        };

        self.conn.execute(
            r#"
            INSERT INTO job_executions (
                execution_id,
                queue_id,
                tenant_id,
                project_id,
                job_id,
                worker_id,
                status,
                started_at,
                finished_at,
                result_json,
                error_message,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                execution.execution_id,
                execution.queue_id,
                execution.tenant_id,
                execution.project_id,
                execution.job_id,
                execution.worker_id,
                execution.status.to_string(),
                execution.started_at.map(|d| d.to_rfc3339()),
                execution.finished_at.map(|d| d.to_rfc3339()),
                execution.result_json,
                execution.error_message,
                execution.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_job_executions_scoped(
        &self,
        scope: &StorageScope,
        job_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<JobExecutionRecord>> {
        let mut items = Vec::new();

        if let Some(job_id) = job_id {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT
                    execution_id,
                    queue_id,
                    tenant_id,
                    project_id,
                    job_id,
                    worker_id,
                    status,
                    started_at,
                    finished_at,
                    result_json,
                    error_message,
                    created_at
                FROM job_executions
                WHERE tenant_id = ?1 AND project_id = ?2 AND job_id = ?3
                ORDER BY created_at DESC
                LIMIT ?4
                "#,
            )?;

            let rows = stmt.query_map(
                params![scope.tenant_id, scope.project_id, job_id, limit as i64],
                map_job_execution_record,
            )?;

            for row in rows {
                items.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT
                    execution_id,
                    queue_id,
                    tenant_id,
                    project_id,
                    job_id,
                    worker_id,
                    status,
                    started_at,
                    finished_at,
                    result_json,
                    error_message,
                    created_at
                FROM job_executions
                WHERE tenant_id = ?1 AND project_id = ?2
                ORDER BY created_at DESC
                LIMIT ?3
                "#,
            )?;

            let rows = stmt.query_map(
                params![scope.tenant_id, scope.project_id, limit as i64],
                map_job_execution_record,
            )?;

            for row in rows {
                items.push(row?);
            }
        }

        Ok(items)
    }

    pub fn baseline_approve(&self, resource: &str) -> Result<()> {
        self.baseline_approve_scoped(&StorageScope::global(), resource)
    }

    pub fn baseline_approve_scoped(&self, scope: &StorageScope, resource: &str) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO baseline_entries (tenant_id, project_id, resource, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                resource,
                Utc::now().to_rfc3339()
            ],
        )?;

        Ok(())
    }

    pub fn baseline_revoke(&self, resource: &str) -> Result<()> {
        self.baseline_revoke_scoped(&StorageScope::global(), resource)
    }

    pub fn baseline_revoke_scoped(&self, scope: &StorageScope, resource: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM baseline_entries
            WHERE tenant_id = ?1 AND project_id = ?2 AND resource = ?3
            "#,
            params![scope.tenant_id, scope.project_id, resource],
        )?;

        Ok(())
    }

    pub fn baseline_list(&self) -> Result<Vec<String>> {
        self.baseline_list_scoped(&StorageScope::global())
    }

    pub fn baseline_list_scoped(&self, scope: &StorageScope) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT resource
            FROM baseline_entries
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY resource ASC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id], |row| {
            row_string(row, 0)
        })?;

        let mut resources = Vec::new();
        for row in rows {
            resources.push(row?);
        }

        Ok(resources)
    }

    pub fn store_episodes(&self, target: &str, episodes: &[RiskEpisode]) -> Result<()> {
        self.store_episodes_scoped(&StorageScope::global(), target, episodes)
    }

    pub fn store_episodes_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
        episodes: &[RiskEpisode],
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        for episode in episodes {
            self.conn.execute(
                r#"
                INSERT OR REPLACE INTO episodes (
                    tenant_id,
                    project_id,
                    episode_id,
                    target,
                    title,
                    kind,
                    severity,
                    criticality,
                    score,
                    state,
                    resource_count,
                    resources_json,
                    cluster_ids_json,
                    started_at,
                    ended_at,
                    summary,
                    explanation_json,
                    created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                "#,
                params![
                    scope.tenant_id,
                    scope.project_id,
                    episode.episode_id,
                    target,
                    episode.title,
                    episode.kind.to_string(),
                    episode.severity.to_string(),
                    episode.criticality.to_string(),
                    episode.score,
                    episode.state.to_string(),
                    episode.resource_count,
                    serde_json::to_string(&episode.resources)?,
                    serde_json::to_string(&episode.cluster_ids)?,
                    episode.started_at.to_rfc3339(),
                    episode.ended_at.to_rfc3339(),
                    episode.summary,
                    serde_json::to_string(&episode.explanation)?,
                    now,
                ],
            )?;
        }

        Ok(())
    }

    pub fn list_episodes(&self, target: &str) -> Result<Vec<StoredEpisode>> {
        self.list_episodes_scoped(&StorageScope::global(), target)
    }

    pub fn list_episodes_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
    ) -> Result<Vec<StoredEpisode>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                episode_id,
                target,
                title,
                kind,
                severity,
                criticality,
                score,
                state,
                resource_count,
                resources_json,
                cluster_ids_json,
                started_at,
                ended_at,
                summary,
                explanation_json,
                created_at
            FROM episodes
            WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
            ORDER BY score DESC, started_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id, target], |row| {
            Ok(StoredEpisode {
                episode_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                title: row_string(row, 2)?,
                kind: row_string(row, 3)?,
                severity: row_string(row, 4)?,
                criticality: row_string(row, 5)?,
                score: row_u64(row, 6)? as u32,
                state: row_string(row, 7)?,
                resource_count: row_u64(row, 8)? as usize,
                resources_json: row_string(row, 9)?,
                cluster_ids_json: row_string(row, 10)?,
                started_at: row_string(row, 11)?,
                ended_at: row_string(row, 12)?,
                summary: row_string(row, 13)?,
                explanation_json: row_string(row, 14)?,
                created_at: row_string(row, 15)?,
            })
        })?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row?);
        }

        Ok(episodes)
    }

    pub fn store_graph(&self, target: &str, graph: &ExposureGraph) -> Result<()> {
        self.store_graph_scoped(&StorageScope::global(), target, graph)
    }

    pub fn store_graph_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
        graph: &ExposureGraph,
    ) -> Result<()> {
        let graph_id = format!(
            "{}:{}",
            target,
            graph
                .generated_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );

        let summary_json = serde_json::to_string(&serde_json::json!({
            "stats": graph.stats,
            "topology": graph.topology,
        }))?;

        let created_at = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO graphs (
                tenant_id,
                project_id,
                graph_id,
                target,
                node_count,
                edge_count,
                generated_at,
                summary_json,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                graph_id,
                target,
                graph.node_count,
                graph.edge_count,
                graph.generated_at.to_rfc3339(),
                summary_json,
                created_at,
            ],
        )?;

        self.conn.execute(
            "DELETE FROM graph_nodes WHERE tenant_id = ?1 AND project_id = ?2 AND graph_id = ?3",
            params![scope.tenant_id, scope.project_id, graph_id.clone()],
        )?;
        self.conn.execute(
            "DELETE FROM graph_edges WHERE tenant_id = ?1 AND project_id = ?2 AND graph_id = ?3",
            params![scope.tenant_id, scope.project_id, graph_id.clone()],
        )?;

        for node in &graph.nodes {
            self.conn.execute(
                r#"
                INSERT INTO graph_nodes (
                    tenant_id,
                    project_id,
                    graph_id,
                    node_id,
                    target,
                    kind,
                    label,
                    first_seen,
                    last_seen,
                    attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    scope.tenant_id,
                    scope.project_id,
                    graph_id,
                    node.node_id,
                    node.target,
                    node.kind.to_string(),
                    node.label,
                    node.first_seen.map(|d| d.to_rfc3339()),
                    node.last_seen.map(|d| d.to_rfc3339()),
                    serde_json::to_string(&node.attributes)?,
                ],
            )?;
        }

        for edge in &graph.edges {
            self.conn.execute(
                r#"
                INSERT INTO graph_edges (
                    tenant_id,
                    project_id,
                    graph_id,
                    edge_id,
                    target,
                    from_node,
                    to_node,
                    kind,
                    weight,
                    first_seen,
                    last_seen,
                    attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "#,
                params![
                    scope.tenant_id,
                    scope.project_id,
                    graph_id,
                    edge.edge_id,
                    edge.target,
                    edge.from,
                    edge.to,
                    edge.kind.to_string(),
                    edge.weight,
                    edge.first_seen.map(|d| d.to_rfc3339()),
                    edge.last_seen.map(|d| d.to_rfc3339()),
                    serde_json::to_string(&edge.attributes)?,
                ],
            )?;
        }

        Ok(())
    }

    pub fn list_graphs(&self, target: &str) -> Result<Vec<StoredGraphRecord>> {
        self.list_graphs_scoped(&StorageScope::global(), target)
    }

    pub fn list_graphs_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
    ) -> Result<Vec<StoredGraphRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                graph_id,
                target,
                node_count,
                edge_count,
                generated_at,
                summary_json,
                created_at
            FROM graphs
            WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
            ORDER BY generated_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id, target], |row| {
            Ok(StoredGraphRecord {
                graph_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                node_count: row_u64(row, 2)? as usize,
                edge_count: row_u64(row, 3)? as usize,
                generated_at: row_string(row, 4)?,
                summary_json: row_string(row, 5)?,
                created_at: row_string(row, 6)?,
            })
        })?;

        let mut graphs = Vec::new();
        for row in rows {
            graphs.push(row?);
        }

        Ok(graphs)
    }

    pub fn load_latest_graph(&self, target: &str) -> Result<Option<ExposureGraph>> {
        self.load_latest_graph_scoped(&StorageScope::global(), target)
    }

    pub fn load_latest_graph_scoped(
        &self,
        scope: &StorageScope,
        target: &str,
    ) -> Result<Option<ExposureGraph>> {
        let graph_row = self
            .conn
            .query_row(
                r#"
                SELECT graph_id, generated_at
                FROM graphs
                WHERE tenant_id = ?1 AND project_id = ?2 AND target = ?3
                ORDER BY generated_at DESC
                LIMIT 1
                "#,
                params![scope.tenant_id, scope.project_id, target],
                |row| Ok((row_string(row, 0)?, row_string(row, 1)?)),
            )
            .optional()?;

        let (graph_id, generated_at_str) = match graph_row {
            Some(row) => row,
            None => return Ok(None),
        };

        let mut nodes_stmt = self.conn.prepare(
            r#"
            SELECT
                node_id,
                target,
                kind,
                label,
                first_seen,
                last_seen,
                attributes_json
            FROM graph_nodes
            WHERE tenant_id = ?1 AND project_id = ?2 AND graph_id = ?3
            ORDER BY node_id ASC
            "#,
        )?;

        let node_rows = nodes_stmt.query_map(
            params![scope.tenant_id, scope.project_id, graph_id.clone()],
            |row| {
                let kind_str = row_string(row, 2)?;
                let attrs_json = row_string(row, 6)?;
                let attrs = serde_json::from_str(&attrs_json).unwrap_or_default();

                Ok(GraphNode {
                    node_id: row_string(row, 0)?,
                    target: row_string(row, 1)?,
                    kind: NodeKind::from_str(&kind_str).map_err(to_sql_err)?,
                    label: row_string(row, 3)?,
                    first_seen: parse_optional_datetime(row_optional_string(row, 4)?),
                    last_seen: parse_optional_datetime(row_optional_string(row, 5)?),
                    attributes: attrs,
                })
            },
        )?;

        let mut nodes = Vec::new();
        for row in node_rows {
            nodes.push(row?);
        }

        let mut edges_stmt = self.conn.prepare(
            r#"
            SELECT
                edge_id,
                target,
                from_node,
                to_node,
                kind,
                weight,
                first_seen,
                last_seen,
                attributes_json
            FROM graph_edges
            WHERE tenant_id = ?1 AND project_id = ?2 AND graph_id = ?3
            ORDER BY edge_id ASC
            "#,
        )?;

        let edge_rows = edges_stmt.query_map(
            params![scope.tenant_id, scope.project_id, graph_id],
            |row| {
                let kind_str = row_string(row, 4)?;
                let attrs_json = row_string(row, 8)?;
                let attrs = serde_json::from_str(&attrs_json).unwrap_or_default();

                Ok(GraphEdge {
                    edge_id: row_string(row, 0)?,
                    target: row_string(row, 1)?,
                    from: row_string(row, 2)?,
                    to: row_string(row, 3)?,
                    kind: EdgeKind::from_str(&kind_str).map_err(to_sql_err)?,
                    weight: row_u64(row, 5)? as u32,
                    first_seen: parse_optional_datetime(row_optional_string(row, 6)?),
                    last_seen: parse_optional_datetime(row_optional_string(row, 7)?),
                    attributes: attrs,
                })
            },
        )?;

        let mut edges = Vec::new();
        for row in edge_rows {
            edges.push(row?);
        }

        let mut graph = ExposureGraph {
            target: target.to_string(),
            generated_at: parse_datetime(generated_at_str)?,
            node_count: nodes.len(),
            edge_count: edges.len(),
            nodes,
            edges,
            stats: atlas_graph::GraphStats::default(),
            topology: atlas_graph::GraphTopologySummary::default(),
        };

        graph.recompute_metadata();
        Ok(Some(graph))
    }

    pub fn save_saved_query(&self, name: &str, expression: &str) -> Result<()> {
        self.save_saved_query_scoped(&StorageScope::global(), name, expression)
    }

    pub fn save_saved_query_scoped(
        &self,
        scope: &StorageScope,
        name: &str,
        expression: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO saved_queries (
                tenant_id,
                project_id,
                name,
                expression,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(tenant_id, project_id, name) DO UPDATE SET
                expression = excluded.expression,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                name,
                expression,
                now,
                now
            ],
        )?;

        Ok(())
    }

    pub fn list_saved_queries(&self) -> Result<Vec<StoredSavedQuery>> {
        self.list_saved_queries_scoped(&StorageScope::global())
    }

    pub fn list_saved_queries_scoped(&self, scope: &StorageScope) -> Result<Vec<StoredSavedQuery>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                name,
                expression,
                created_at,
                updated_at
            FROM saved_queries
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY name ASC
            "#,
        )?;

        let rows = stmt.query_map(params![scope.tenant_id, scope.project_id], |row| {
            Ok(StoredSavedQuery {
                name: row_string(row, 0)?,
                expression: row_string(row, 1)?,
                created_at: row_string(row, 2)?,
                updated_at: row_string(row, 3)?,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }

        Ok(items)
    }

    pub fn load_saved_query(&self, name: &str) -> Result<Option<StoredSavedQuery>> {
        self.load_saved_query_scoped(&StorageScope::global(), name)
    }

    pub fn load_saved_query_scoped(
        &self,
        scope: &StorageScope,
        name: &str,
    ) -> Result<Option<StoredSavedQuery>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT
                    name,
                    expression,
                    created_at,
                    updated_at
                FROM saved_queries
                WHERE tenant_id = ?1 AND project_id = ?2 AND name = ?3
                "#,
                params![scope.tenant_id, scope.project_id, name],
                |row| {
                    Ok(StoredSavedQuery {
                        name: row_string(row, 0)?,
                        expression: row_string(row, 1)?,
                        created_at: row_string(row, 2)?,
                        updated_at: row_string(row, 3)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    pub fn delete_saved_query(&self, name: &str) -> Result<()> {
        self.delete_saved_query_scoped(&StorageScope::global(), name)
    }

    pub fn delete_saved_query_scoped(&self, scope: &StorageScope, name: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM saved_queries
            WHERE tenant_id = ?1 AND project_id = ?2 AND name = ?3
            "#,
            params![scope.tenant_id, scope.project_id, name],
        )?;

        Ok(())
    }

    pub fn upsert_asset_owner_scoped(
        &self,
        scope: &StorageScope,
        resource: &str,
        owner: &str,
        team: Option<&str>,
        business_service: Option<&str>,
        criticality: Option<&str>,
    ) -> Result<StoredAssetOwner> {
        let now = Utc::now().to_rfc3339();

        let existing_created_at = self
            .conn
            .query_row(
                r#"
                SELECT created_at
                FROM asset_owners
                WHERE tenant_id = ?1 AND project_id = ?2 AND resource = ?3
                "#,
                params![scope.tenant_id, scope.project_id, resource],
                |row| row_string(row, 0),
            )
            .optional()?;

        let created_at = existing_created_at.unwrap_or_else(|| now.clone());

        self.conn.execute(
            r#"
            INSERT INTO asset_owners (
                tenant_id,
                project_id,
                resource,
                owner,
                team,
                business_service,
                criticality,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(tenant_id, project_id, resource) DO UPDATE SET
                owner = excluded.owner,
                team = excluded.team,
                business_service = excluded.business_service,
                criticality = excluded.criticality,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                resource,
                owner,
                team,
                business_service,
                criticality,
                created_at,
                now
            ],
        )?;

        Ok(StoredAssetOwner {
            resource: resource.to_string(),
            owner: owner.to_string(),
            team: team.map(str::to_string),
            business_service: business_service.map(str::to_string),
            criticality: criticality.map(str::to_string),
            created_at,
            updated_at: now,
        })
    }

    pub fn list_asset_owners_scoped(
        &self,
        scope: &StorageScope,
        resource: Option<&str>,
    ) -> Result<Vec<StoredAssetOwner>> {
        let mut items = Vec::new();

        if let Some(resource) = resource {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT resource, owner, team, business_service, criticality, created_at, updated_at
                FROM asset_owners
                WHERE tenant_id = ?1 AND project_id = ?2 AND resource = ?3
                ORDER BY resource ASC
                "#,
            )?;

            let rows = stmt.query_map(
                params![scope.tenant_id, scope.project_id, resource],
                |row| {
                    Ok(StoredAssetOwner {
                        resource: row_string(row, 0)?,
                        owner: row_string(row, 1)?,
                        team: row_optional_string(row, 2)?,
                        business_service: row_optional_string(row, 3)?,
                        criticality: row_optional_string(row, 4)?,
                        created_at: row_string(row, 5)?,
                        updated_at: row_string(row, 6)?,
                    })
                },
            )?;

            for row in rows {
                items.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT resource, owner, team, business_service, criticality, created_at, updated_at
                FROM asset_owners
                WHERE tenant_id = ?1 AND project_id = ?2
                ORDER BY resource ASC
                "#,
            )?;

            let rows = stmt.query_map(params![scope.tenant_id, scope.project_id], |row| {
                Ok(StoredAssetOwner {
                    resource: row_string(row, 0)?,
                    owner: row_string(row, 1)?,
                    team: row_optional_string(row, 2)?,
                    business_service: row_optional_string(row, 3)?,
                    criticality: row_optional_string(row, 4)?,
                    created_at: row_string(row, 5)?,
                    updated_at: row_string(row, 6)?,
                })
            })?;

            for row in rows {
                items.push(row?);
            }
        }

        Ok(items)
    }

    pub fn upsert_incident_scoped(
        &self,
        scope: &StorageScope,
        incident: &StoredIncident,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO incidents (
                tenant_id,
                project_id,
                incident_id,
                target,
                source_kind,
                source_id,
                title,
                severity,
                score,
                state,
                owner,
                notes,
                resource,
                context_json,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(tenant_id, project_id, incident_id) DO UPDATE SET
                target = excluded.target,
                source_kind = excluded.source_kind,
                source_id = excluded.source_id,
                title = excluded.title,
                severity = excluded.severity,
                score = excluded.score,
                state = excluded.state,
                owner = excluded.owner,
                notes = excluded.notes,
                resource = excluded.resource,
                context_json = excluded.context_json,
                updated_at = excluded.updated_at
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                incident.incident_id,
                incident.target,
                incident.source_kind,
                incident.source_id,
                incident.title,
                incident.severity,
                incident.score,
                incident.state,
                incident.owner,
                incident.notes,
                incident.resource,
                incident.context_json,
                incident.created_at,
                incident.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_incident_scoped(
        &self,
        scope: &StorageScope,
        incident_id: &str,
    ) -> Result<Option<StoredIncident>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT
                    incident_id,
                    target,
                    source_kind,
                    source_id,
                    title,
                    severity,
                    score,
                    state,
                    owner,
                    notes,
                    resource,
                    context_json,
                    created_at,
                    updated_at
                FROM incidents
                WHERE tenant_id = ?1 AND project_id = ?2 AND incident_id = ?3
                "#,
                params![scope.tenant_id, scope.project_id, incident_id],
                |row| {
                    Ok(StoredIncident {
                        incident_id: row_string(row, 0)?,
                        target: row_string(row, 1)?,
                        source_kind: row_string(row, 2)?,
                        source_id: row_string(row, 3)?,
                        title: row_string(row, 4)?,
                        severity: row_string(row, 5)?,
                        score: row_u64(row, 6)? as u32,
                        state: row_string(row, 7)?,
                        owner: row_optional_string(row, 8)?,
                        notes: row_optional_string(row, 9)?,
                        resource: row_string(row, 10)?,
                        context_json: row_string(row, 11)?,
                        created_at: row_string(row, 12)?,
                        updated_at: row_string(row, 13)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    pub fn list_incidents_scoped(
        &self,
        scope: &StorageScope,
        state: Option<&str>,
        owner: Option<&str>,
        limit: usize,
    ) -> Result<Vec<StoredIncident>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                incident_id,
                target,
                source_kind,
                source_id,
                title,
                severity,
                score,
                state,
                owner,
                notes,
                resource,
                context_json,
                created_at,
                updated_at
            FROM incidents
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY score DESC, updated_at DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(
            params![scope.tenant_id, scope.project_id, limit as i64],
            |row| {
                Ok(StoredIncident {
                    incident_id: row_string(row, 0)?,
                    target: row_string(row, 1)?,
                    source_kind: row_string(row, 2)?,
                    source_id: row_string(row, 3)?,
                    title: row_string(row, 4)?,
                    severity: row_string(row, 5)?,
                    score: row_u64(row, 6)? as u32,
                    state: row_string(row, 7)?,
                    owner: row_optional_string(row, 8)?,
                    notes: row_optional_string(row, 9)?,
                    resource: row_string(row, 10)?,
                    context_json: row_string(row, 11)?,
                    created_at: row_string(row, 12)?,
                    updated_at: row_string(row, 13)?,
                })
            },
        )?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }

        if let Some(state_filter) = state {
            items.retain(|i| i.state.eq_ignore_ascii_case(state_filter));
        }

        if let Some(owner_filter) = owner {
            items.retain(|i| {
                i.owner
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(owner_filter))
                    .unwrap_or(false)
            });
        }

        Ok(items)
    }

    pub fn set_incident_state_scoped(
        &self,
        scope: &StorageScope,
        incident_id: &str,
        incident_state: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE incidents
            SET state = ?1, updated_at = ?2
            WHERE tenant_id = ?3 AND project_id = ?4 AND incident_id = ?5
            "#,
            params![
                incident_state,
                Utc::now().to_rfc3339(),
                scope.tenant_id,
                scope.project_id,
                incident_id
            ],
        )?;
        Ok(())
    }

    pub fn assign_incident_owner_scoped(
        &self,
        scope: &StorageScope,
        incident_id: &str,
        owner: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE incidents
            SET owner = ?1, updated_at = ?2
            WHERE tenant_id = ?3 AND project_id = ?4 AND incident_id = ?5
            "#,
            params![
                owner,
                Utc::now().to_rfc3339(),
                scope.tenant_id,
                scope.project_id,
                incident_id
            ],
        )?;
        Ok(())
    }

    pub fn set_incident_note_scoped(
        &self,
        scope: &StorageScope,
        incident_id: &str,
        notes: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE incidents
            SET notes = ?1, updated_at = ?2
            WHERE tenant_id = ?3 AND project_id = ?4 AND incident_id = ?5
            "#,
            params![
                notes,
                Utc::now().to_rfc3339(),
                scope.tenant_id,
                scope.project_id,
                incident_id
            ],
        )?;
        Ok(())
    }

    pub fn record_alert_delivery_scoped(
        &self,
        scope: &StorageScope,
        request: &AlertDeliveryRequest,
    ) -> Result<StoredAlertDelivery> {
        let delivery_id = format!(
            "{}:{}:{}",
            request.channel,
            request.destination,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let created_at = Utc::now().to_rfc3339();
        let payload_json = serde_json::to_string(&request.payload)?;

        self.conn.execute(
            r#"
            INSERT INTO alert_deliveries (
                tenant_id,
                project_id,
                delivery_id,
                channel,
                destination,
                event_type,
                status,
                payload_json,
                response_body,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                scope.tenant_id,
                scope.project_id,
                delivery_id,
                request.channel,
                request.destination,
                request.event_type,
                request.status,
                payload_json,
                request.response_body,
                created_at
            ],
        )?;

        Ok(StoredAlertDelivery {
            delivery_id,
            channel: request.channel.clone(),
            destination: request.destination.clone(),
            event_type: request.event_type.clone(),
            status: request.status.clone(),
            payload_json,
            response_body: request.response_body.clone(),
            created_at,
        })
    }

    pub fn list_alert_deliveries_scoped(
        &self,
        scope: &StorageScope,
        limit: usize,
    ) -> Result<Vec<StoredAlertDelivery>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                delivery_id,
                channel,
                destination,
                event_type,
                status,
                payload_json,
                response_body,
                created_at
            FROM alert_deliveries
            WHERE tenant_id = ?1 AND project_id = ?2
            ORDER BY created_at DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(
            params![scope.tenant_id, scope.project_id, limit as i64],
            |row| {
                Ok(StoredAlertDelivery {
                    delivery_id: row_string(row, 0)?,
                    channel: row_string(row, 1)?,
                    destination: row_string(row, 2)?,
                    event_type: row_string(row, 3)?,
                    status: row_string(row, 4)?,
                    payload_json: row_string(row, 5)?,
                    response_body: row_optional_string(row, 6)?,
                    created_at: row_string(row, 7)?,
                })
            },
        )?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    fn repair_legacy_tables_if_needed(&self) -> Result<()> {
        for table in [
            "snapshots",
            "drift_runs",
            "findings",
            "telemetry",
            "jobs",
            "baseline_entries",
            "episodes",
            "graphs",
            "graph_nodes",
            "graph_edges",
            "saved_queries",
            "finding_state",
            "job_queue",
            "job_executions",
            "asset_owners",
            "incidents",
            "alert_deliveries",
        ] {
            self.ensure_scope_columns(table)?;
        }

        self.rebuild_saved_queries_if_needed()?;
        self.rebuild_finding_state_if_needed()?;
        Ok(())
    }

    fn ensure_scope_columns(&self, table: &str) -> Result<()> {
        let columns = self.read_table_info(table)?;
        let has_tenant = columns.iter().any(|c| c.name == "tenant_id");
        let has_project = columns.iter().any(|c| c.name == "project_id");

        if !has_tenant {
            self.conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';"
            ))?;
        }

        if !has_project {
            self.conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';"
            ))?;
        }

        Ok(())
    }

    fn rebuild_saved_queries_if_needed(&self) -> Result<()> {
        let columns = self.read_table_info("saved_queries")?;
        let tenant_pk = columns.iter().find(|c| c.name == "tenant_id").map(|c| c.pk);
        let project_pk = columns
            .iter()
            .find(|c| c.name == "project_id")
            .map(|c| c.pk);
        let name_pk = columns.iter().find(|c| c.name == "name").map(|c| c.pk);

        let already_composite = matches!(tenant_pk, Some(v) if v > 0)
            && matches!(project_pk, Some(v) if v > 0)
            && matches!(name_pk, Some(v) if v > 0);

        if already_composite {
            return Ok(());
        }

        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS saved_queries_v026 (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                name TEXT NOT NULL,
                expression TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, name)
            );

            INSERT OR IGNORE INTO saved_queries_v026 (
                tenant_id, project_id, name, expression, created_at, updated_at
            )
            SELECT
                COALESCE(tenant_id, 'default'),
                COALESCE(project_id, 'default'),
                name,
                expression,
                created_at,
                updated_at
            FROM saved_queries;

            DROP TABLE saved_queries;
            ALTER TABLE saved_queries_v026 RENAME TO saved_queries;
            "#,
        )?;
        Ok(())
    }

    fn rebuild_finding_state_if_needed(&self) -> Result<()> {
        let columns = self.read_table_info("finding_state")?;
        let tenant_pk = columns.iter().find(|c| c.name == "tenant_id").map(|c| c.pk);
        let project_pk = columns
            .iter()
            .find(|c| c.name == "project_id")
            .map(|c| c.pk);
        let finding_pk = columns
            .iter()
            .find(|c| c.name == "finding_id")
            .map(|c| c.pk);

        let already_composite = matches!(tenant_pk, Some(v) if v > 0)
            && matches!(project_pk, Some(v) if v > 0)
            && matches!(finding_pk, Some(v) if v > 0);

        if already_composite {
            return Ok(());
        }

        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS finding_state_v026 (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                operational_state TEXT NOT NULL,
                owner TEXT,
                notes TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, finding_id)
            );

            INSERT OR IGNORE INTO finding_state_v026 (
                tenant_id, project_id, finding_id, operational_state, owner, notes, updated_at
            )
            SELECT
                COALESCE(tenant_id, 'default'),
                COALESCE(project_id, 'default'),
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            FROM finding_state;

            DROP TABLE finding_state;
            ALTER TABLE finding_state_v026 RENAME TO finding_state;
            "#,
        )?;
        Ok(())
    }

    fn read_table_info(&self, table: &str) -> Result<Vec<TableColumn>> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = self.conn.prepare(&pragma)?;
        let rows = stmt.query_map([], |row| {
            Ok(TableColumn {
                name: row.get(1)?,
                pk: row.get::<_, i64>(5)?,
            })
        })?;

        let mut columns = Vec::new();
        for row in rows {
            columns.push(row?);
        }
        Ok(columns)
    }
}

fn map_job_queue_item(row: &Row<'_>) -> rusqlite::Result<JobQueueItem> {
    let status =
        JobQueueStatus::from_str(&row_string(row, 10)?).map_err(|e| to_sql_err(anyhow!(e)))?;

    Ok(JobQueueItem {
        queue_id: row_string(row, 0)?,
        tenant_id: row_string(row, 1)?,
        project_id: row_string(row, 2)?,
        job_id: row_string(row, 3)?,
        target: row_string(row, 4)?,
        profile: row_string(row, 5)?,
        policy_path: row_optional_string(row, 6)?,
        trigger: row_string(row, 7)?,
        requested_by: row_optional_string(row, 8)?,
        persist_artifacts: row_bool(row, 9)?,
        status,
        attempts: row_u64(row, 11)? as u32,
        max_attempts: row_u64(row, 12)? as u32,
        available_at: parse_datetime(row_string(row, 13)?)?,
        claimed_by: row_optional_string(row, 14)?,
        claimed_at: parse_optional_datetime(row_optional_string(row, 15)?),
        lease_expires_at: parse_optional_datetime(row_optional_string(row, 16)?),
        created_at: parse_datetime(row_string(row, 17)?)?,
        updated_at: parse_datetime(row_string(row, 18)?)?,
        last_error: row_optional_string(row, 19)?,
    })
}

fn map_job_execution_record(row: &Row<'_>) -> rusqlite::Result<JobExecutionRecord> {
    let status =
        JobQueueStatus::from_str(&row_string(row, 6)?).map_err(|e| to_sql_err(anyhow!(e)))?;

    Ok(JobExecutionRecord {
        execution_id: row_string(row, 0)?,
        queue_id: row_string(row, 1)?,
        tenant_id: row_string(row, 2)?,
        project_id: row_string(row, 3)?,
        job_id: row_string(row, 4)?,
        worker_id: row_optional_string(row, 5)?,
        status,
        started_at: parse_optional_datetime(row_optional_string(row, 7)?),
        finished_at: parse_optional_datetime(row_optional_string(row, 8)?),
        result_json: row_optional_string(row, 9)?,
        error_message: row_optional_string(row, 10)?,
        created_at: parse_datetime(row_string(row, 11)?)?,
    })
}

fn compute_snapshot_hash(path: &Path) -> Result<String> {
    let content = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(content);
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

fn parse_datetime(value: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                value.len(),
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
}

fn parse_optional_datetime(value: Option<String>) -> Option<DateTime<Utc>> {
    value
        .and_then(|v| DateTime::parse_from_rfc3339(&v).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn escape_csv(input: &str) -> String {
    input.replace('"', "\"\"")
}

fn to_sql_err(err: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        )),
    )
}

fn row_string(row: &Row<'_>, index: usize) -> rusqlite::Result<String> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(String::new()),
        ValueRef::Text(value) => Ok(String::from_utf8_lossy(value).to_string()),
        ValueRef::Integer(value) => Ok(value.to_string()),
        ValueRef::Real(value) => Ok(value.to_string()),
        ValueRef::Blob(value) => Ok(String::from_utf8_lossy(value).to_string()),
    }
}

fn row_optional_string(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<String>> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(value) => Ok(Some(String::from_utf8_lossy(value).to_string())),
        ValueRef::Integer(value) => Ok(Some(value.to_string())),
        ValueRef::Real(value) => Ok(Some(value.to_string())),
        ValueRef::Blob(value) => Ok(Some(String::from_utf8_lossy(value).to_string())),
    }
}

fn row_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(0),
        ValueRef::Integer(value) => Ok(value.max(0) as u64),
        ValueRef::Real(value) => Ok(value.max(0.0) as u64),
        ValueRef::Text(value) => Ok(String::from_utf8_lossy(value).parse::<u64>().unwrap_or(0)),
        ValueRef::Blob(_) => Ok(0),
    }
}

fn row_bool(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(false),
        ValueRef::Integer(value) => Ok(value != 0),
        ValueRef::Real(value) => Ok(value != 0.0),
        ValueRef::Text(value) => {
            let raw = String::from_utf8_lossy(value).to_ascii_lowercase();
            Ok(matches!(raw.as_str(), "1" | "true" | "yes"))
        }
        ValueRef::Blob(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_graph::{EdgeKind, ExposureGraph, GraphNode, NodeKind};
    use atlas_jobs::{JobDispatchRequest, JobTrigger};
    use std::collections::BTreeMap;

    #[test]
    fn stores_and_loads_graph() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-graph-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");

        let mut graph = ExposureGraph::empty("example.com");
        graph.nodes.push(GraphNode {
            node_id: "node1".to_string(),
            kind: NodeKind::Subdomain,
            label: "admin.example.com".to_string(),
            target: "example.com".to_string(),
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        });
        graph.edges.push(GraphEdge {
            edge_id: "edge1".to_string(),
            from: graph.nodes[0].node_id.clone(),
            to: "node1".to_string(),
            kind: EdgeKind::BelongsTo,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        });
        graph.recompute_metadata();

        store
            .store_graph_scoped(&scope, "example.com", &graph)
            .unwrap();
        let loaded = store
            .load_latest_graph_scoped(&scope, "example.com")
            .unwrap()
            .unwrap();

        assert_eq!(loaded.target, "example.com");
        assert!(loaded.node_count >= 1);
    }

    #[test]
    fn stores_and_loads_saved_query_scoped() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-saved-query-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");

        store
            .save_saved_query_scoped(&scope, "risky-admin", "services label~admin")
            .unwrap();

        let item = store
            .load_saved_query_scoped(&scope, "risky-admin")
            .unwrap()
            .unwrap();
        assert_eq!(item.name, "risky-admin");
        assert_eq!(item.expression, "services label~admin");

        let list = store.list_saved_queries_scoped(&scope).unwrap();
        assert_eq!(list.len(), 1);

        store
            .delete_saved_query_scoped(&scope, "risky-admin")
            .unwrap();
        assert!(store
            .load_saved_query_scoped(&scope, "risky-admin")
            .unwrap()
            .is_none());
    }

    #[test]
    fn sets_and_reads_finding_operational_state_scoped() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-finding-state-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");

        store
            .conn
            .execute(
                r#"
                INSERT INTO findings (
                    tenant_id,
                    project_id,
                    finding_id,
                    run_id,
                    target,
                    severity,
                    state,
                    category,
                    title,
                    resource,
                    asset_type,
                    environment,
                    criticality,
                    score,
                    tags_json,
                    description,
                    is_suppressed,
                    created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                "#,
                params![
                    scope.tenant_id,
                    scope.project_id,
                    "f1",
                    "r1",
                    "example.com",
                    "HIGH",
                    "New",
                    "new_admin_subdomain",
                    "Nuevo subdominio administrativo",
                    "admin.example.com",
                    "Subdomain",
                    "Admin",
                    "CRITICAL",
                    95u32,
                    "[]",
                    "desc",
                    0,
                    Utc::now().to_rfc3339(),
                ],
            )
            .unwrap();

        store
            .set_finding_operational_state_scoped(&scope, "f1", "acknowledged")
            .unwrap();
        store
            .assign_finding_owner_scoped(&scope, "f1", "claudio")
            .unwrap();
        store
            .set_finding_note_scoped(&scope, "f1", "en revisión")
            .unwrap();

        let state = store
            .get_finding_operational_state_scoped(&scope, "f1")
            .unwrap()
            .unwrap();
        assert_eq!(state.operational_state, "acknowledged");
        assert_eq!(state.owner.as_deref(), Some("claudio"));
        assert_eq!(state.notes.as_deref(), Some("en revisión"));
    }

    #[test]
    fn records_scoped_audit_event() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-audit-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");

        store
            .record_audit_event_scoped(
                &scope,
                "claudio",
                "finding.ack",
                "finding",
                "f-123",
                &serde_json::json!({"state": "acknowledged"}),
            )
            .unwrap();

        let events = store.list_audit_events_scoped(&scope, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant_id, "tenant-a");
        assert_eq!(events[0].project_id, "project-x");
    }

    #[test]
    fn enqueues_job_dispatch_scoped() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-queue-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");
        let dispatch = JobDispatchRequest::new(
            "tenant-a",
            "project-x",
            "job-1",
            "example.com",
            "standard",
            JobTrigger::Manual,
        )
        .requested_by("claudio")
        .persist_artifacts(true);

        let item = store
            .enqueue_job_dispatch_scoped(&scope, &dispatch)
            .unwrap();

        assert_eq!(item.tenant_id, "tenant-a");
        assert_eq!(item.project_id, "project-x");
        assert_eq!(item.job_id, "job-1");

        let listed = store.list_job_queue_scoped(&scope, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].queue_id, item.queue_id);
    }

    #[test]
    fn queue_lifecycle_works() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-queue-lifecycle-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");
        let dispatch = JobDispatchRequest::new(
            "tenant-a",
            "project-x",
            "job-1",
            "example.com",
            "standard",
            JobTrigger::Manual,
        );

        let queued = store
            .enqueue_job_dispatch_scoped(&scope, &dispatch)
            .unwrap();
        assert_eq!(queued.status, JobQueueStatus::Pending);

        let claimed = store
            .claim_next_job_queue_item("worker-test", 30)
            .unwrap()
            .unwrap();
        assert_eq!(claimed.status, JobQueueStatus::Claimed);

        let running = store
            .mark_job_queue_running(&claimed.queue_id)
            .unwrap()
            .unwrap();
        assert_eq!(running.status, JobQueueStatus::Running);

        let done = store
            .mark_job_queue_succeeded(&running.queue_id, &serde_json::json!({"ok": true}))
            .unwrap()
            .unwrap();
        assert_eq!(done.status, JobQueueStatus::Succeeded);
    }

    #[test]
    fn stores_incident_and_alert_delivery() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-incident-alert-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        let scope = StorageScope::new("tenant-a", "project-x");

        let incident = StoredIncident {
            incident_id: "incident-1".to_string(),
            target: "example.com".to_string(),
            source_kind: "finding".to_string(),
            source_id: "f-1".to_string(),
            title: "Incident seed".to_string(),
            severity: "HIGH".to_string(),
            score: 90,
            state: "open".to_string(),
            owner: Some("claudio".to_string()),
            notes: None,
            resource: "admin.example.com".to_string(),
            context_json: "{}".to_string(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        };

        store.upsert_incident_scoped(&scope, &incident).unwrap();
        let loaded = store
            .get_incident_scoped(&scope, "incident-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.incident_id, "incident-1");

        let delivery = store
            .record_alert_delivery_scoped(
                &scope,
                &AlertDeliveryRequest {
                    channel: "webhook".to_string(),
                    destination: "https://example.test/webhook".to_string(),
                    event_type: "incident.opened".to_string(),
                    status: "delivered".to_string(),
                    payload: serde_json::json!({"ok": true}),
                    response_body: Some("accepted".to_string()),
                },
            )
            .unwrap();

        assert_eq!(delivery.channel, "webhook");
        let deliveries = store.list_alert_deliveries_scoped(&scope, 10).unwrap();
        assert_eq!(deliveries.len(), 1);
    }
}
