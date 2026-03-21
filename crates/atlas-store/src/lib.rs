use anyhow::{anyhow, Result};
use atlas_drift::DriftReport;
use atlas_episodes::RiskEpisode;
use atlas_graph::{EdgeKind, ExposureGraph, GraphEdge, GraphNode, NodeKind};
use atlas_jobs::AtlasJob;
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use rusqlite::{params, types::ValueRef, Connection, Row};
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

#[derive(Debug, Clone)]
struct TableColumn {
    name: String,
    declared_type: String,
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

            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS drift_runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                older_snapshot_path TEXT NOT NULL,
                newer_snapshot_path TEXT NOT NULL,
                policy_path TEXT,
                total_findings INTEGER NOT NULL,
                total_score INTEGER NOT NULL,
                overall_severity TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
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
                PRIMARY KEY (finding_id, run_id)
            );

            CREATE TABLE IF NOT EXISTS telemetry (
                telemetry_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT,
                duration_ms TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
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
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                policy_path TEXT,
                last_run_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baseline_entries (
                resource TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS episodes (
                episode_id TEXT PRIMARY KEY,
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
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS graphs (
                graph_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                graph_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (graph_id, node_id)
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
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
                PRIMARY KEY (graph_id, edge_id)
            );

            CREATE TABLE IF NOT EXISTS saved_queries (
                name TEXT PRIMARY KEY,
                expression TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS finding_state (
                finding_id TEXT PRIMARY KEY,
                operational_state TEXT NOT NULL,
                owner TEXT,
                notes TEXT,
                updated_at TEXT NOT NULL
            );
            "#,
        )?;

        self.repair_legacy_tables_if_needed()?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn register_snapshot(&self, path: &Path, snapshot: &Snapshot) -> Result<()> {
        self.register_snapshot_scoped(&StorageScope::global(), path, snapshot)
    }

    pub fn register_snapshot_scoped(
        &self,
        _scope: &StorageScope,
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
                snapshot_id,
                target,
                timestamp,
                snapshot_version,
                file_hash,
                path,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
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
        _scope: &StorageScope,
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
                run_id,
                target,
                older_snapshot_path,
                newer_snapshot_path,
                policy_path,
                total_findings,
                total_score,
                overall_severity,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
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
            self.insert_finding(&run_id, target, finding, false)?;
        }

        for finding in &report.suppressed_findings {
            self.insert_finding(&run_id, target, finding, true)?;
        }

        Ok(())
    }

    fn insert_finding(
        &self,
        run_id: &str,
        target: &str,
        finding: &atlas_drift::DriftFinding,
        is_suppressed: bool,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO findings (
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
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
        _scope: &StorageScope,
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
            WHERE target = ?1
            ORDER BY created_at DESC
            "#,
        )?;

        let rows = stmt.query_map([target], |row| {
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
        _scope: &StorageScope,
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
            WHERE target = ?1
            ORDER BY score DESC, created_at DESC
            "#,
        )?;

        let rows = stmt.query_map([target], |row| {
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

    pub fn finding_exists(&self, finding_id: &str) -> Result<bool> {
        let found = self.conn.query_row(
            r#"
            SELECT 1
            FROM findings
            WHERE finding_id = ?1
            LIMIT 1
            "#,
            [finding_id],
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
        let result = self.conn.query_row(
            r#"
            SELECT
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            FROM finding_state
            WHERE finding_id = ?1
            "#,
            [finding_id],
            |row| {
                Ok(StoredFindingOperationalState {
                    finding_id: row_string(row, 0)?,
                    operational_state: row_string(row, 1)?,
                    owner: row_optional_string(row, 2)?,
                    notes: row_optional_string(row, 3)?,
                    updated_at: row_string(row, 4)?,
                })
            },
        );

        match result {
            Ok(item) => Ok(Some(item)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn set_finding_operational_state(
        &self,
        finding_id: &str,
        operational_state: &str,
    ) -> Result<()> {
        self.ensure_finding_for_triage(finding_id)?;
        let current = self.get_finding_operational_state(finding_id)?;
        let owner = current.as_ref().and_then(|c| c.owner.clone());
        let notes = current.as_ref().and_then(|c| c.notes.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn set_finding_operational_state_scoped(
        &self,
        _scope: &StorageScope,
        finding_id: &str,
        operational_state: &str,
    ) -> Result<()> {
        self.set_finding_operational_state(finding_id, operational_state)
    }

    pub fn assign_finding_owner(&self, finding_id: &str, owner: &str) -> Result<()> {
        self.ensure_finding_for_triage(finding_id)?;
        let current = self.get_finding_operational_state(finding_id)?;
        let operational_state = current
            .as_ref()
            .map(|c| c.operational_state.clone())
            .unwrap_or_else(|| "open".to_string());
        let notes = current.as_ref().and_then(|c| c.notes.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn assign_finding_owner_scoped(
        &self,
        _scope: &StorageScope,
        finding_id: &str,
        owner: &str,
    ) -> Result<()> {
        self.assign_finding_owner(finding_id, owner)
    }

    pub fn set_finding_note(&self, finding_id: &str, notes: &str) -> Result<()> {
        self.ensure_finding_for_triage(finding_id)?;
        let current = self.get_finding_operational_state(finding_id)?;
        let operational_state = current
            .as_ref()
            .map(|c| c.operational_state.clone())
            .unwrap_or_else(|| "open".to_string());
        let owner = current.as_ref().and_then(|c| c.owner.clone());

        self.conn.execute(
            r#"
            INSERT INTO finding_state (
                finding_id,
                operational_state,
                owner,
                notes,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(finding_id) DO UPDATE SET
                operational_state = excluded.operational_state,
                owner = excluded.owner,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            "#,
            params![
                finding_id,
                operational_state,
                owner,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn set_finding_note_scoped(
        &self,
        _scope: &StorageScope,
        finding_id: &str,
        notes: &str,
    ) -> Result<()> {
        self.set_finding_note(finding_id, notes)
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
        _scope: &StorageScope,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
        operational_state: Option<&str>,
        owner: Option<&str>,
    ) -> Result<Vec<StoredCurrentFinding>> {
        let findings = self.list_findings(target, severity, state)?;
        let mut latest_by_finding: BTreeMap<String, StoredFinding> = BTreeMap::new();

        for finding in findings {
            latest_by_finding
                .entry(finding.finding_id.clone())
                .or_insert(finding);
        }

        let mut items = Vec::new();

        for (_, finding) in latest_by_finding {
            let triage = self.get_finding_operational_state(&finding.finding_id)?;
            let op_state = triage
                .as_ref()
                .map(|t| t.operational_state.clone())
                .unwrap_or_else(|| "open".to_string());
            let op_owner = triage.as_ref().and_then(|t| t.owner.clone());
            let op_notes = triage.as_ref().and_then(|t| t.notes.clone());
            let op_updated_at = triage.as_ref().map(|t| t.updated_at.clone());

            let item = StoredCurrentFinding {
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
            };

            items.push(item);
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

    fn ensure_finding_for_triage(&self, finding_id: &str) -> Result<()> {
        if !self.finding_exists(finding_id)? {
            return Err(anyhow!("finding no encontrado: {finding_id}"));
        }
        Ok(())
    }

    pub fn list_snapshots(&self, target: &str) -> Result<Vec<StoredSnapshot>> {
        self.list_snapshots_scoped(&StorageScope::global(), target)
    }

    pub fn list_snapshots_scoped(
        &self,
        _scope: &StorageScope,
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
            WHERE target = ?1
            ORDER BY timestamp DESC
            "#,
        )?;

        let rows = stmt.query_map([target], |row| {
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
        let telemetry_id = format!("{}:{}", name, Utc::now().timestamp_nanos_opt().unwrap_or(0));

        self.conn.execute(
            r#"
            INSERT INTO telemetry (
                telemetry_id,
                name,
                target,
                duration_ms,
                metadata_json,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
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
        _scope: &StorageScope,
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
            ORDER BY created_at DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map([limit as i64], |row| {
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
        })?;

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
            "{}:{}:{}",
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

    pub fn list_jobs_scoped(&self, _scope: &StorageScope) -> Result<Vec<AtlasJob>> {
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
            ORDER BY created_at DESC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            let enabled_value = row_bool(row, 4)?;
            let policy_path = row_optional_string(row, 5)?;
            let last_run_at = row_optional_string(row, 6)?;
            let created_at = row_string(row, 7)?;

            Ok(AtlasJob {
                job_id: row_string(row, 0)?,
                target: row_string(row, 1)?,
                profile: row_string(row, 2)?,
                interval_seconds: row_u64(row, 3)? as u64,
                enabled: enabled_value,
                policy_path,
                last_run_at: parse_optional_datetime(last_run_at),
                created_at: parse_datetime(created_at)?,
            })
        })?;

        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    pub fn insert_job(&self, job: &AtlasJob) -> Result<()> {
        self.insert_job_scoped(&StorageScope::global(), job)
    }

    pub fn insert_job_scoped(&self, _scope: &StorageScope, job: &AtlasJob) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO jobs (
                job_id,
                target,
                profile,
                interval_seconds,
                enabled,
                policy_path,
                last_run_at,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
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

    pub fn touch_job_run_scoped(&self, _scope: &StorageScope, job_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE jobs
            SET last_run_at = ?1
            WHERE job_id = ?2
            "#,
            params![Utc::now().to_rfc3339(), job_id],
        )?;

        Ok(())
    }

    pub fn delete_job_scoped(&self, _scope: &StorageScope, job_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM jobs
            WHERE job_id = ?1
            "#,
            params![job_id],
        )?;
        Ok(())
    }

    pub fn baseline_approve(&self, resource: &str) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO baseline_entries (resource, created_at)
            VALUES (?1, ?2)
            "#,
            params![resource, Utc::now().to_rfc3339()],
        )?;

        Ok(())
    }

    pub fn baseline_revoke(&self, resource: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM baseline_entries
            WHERE resource = ?1
            "#,
            params![resource],
        )?;

        Ok(())
    }

    pub fn baseline_list(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT resource
            FROM baseline_entries
            ORDER BY resource ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| row_string(row, 0))?;

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
        _scope: &StorageScope,
        target: &str,
        episodes: &[RiskEpisode],
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        for episode in episodes {
            self.conn.execute(
                r#"
                INSERT OR REPLACE INTO episodes (
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                "#,
                params![
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
        _scope: &StorageScope,
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
            WHERE target = ?1
            ORDER BY score DESC, started_at DESC
            "#,
        )?;

        let rows = stmt.query_map([target], |row| {
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
        _scope: &StorageScope,
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
                graph_id,
                target,
                node_count,
                edge_count,
                generated_at,
                summary_json,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
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
            "DELETE FROM graph_nodes WHERE graph_id = ?1",
            params![graph_id.clone()],
        )?;
        self.conn.execute(
            "DELETE FROM graph_edges WHERE graph_id = ?1",
            params![graph_id.clone()],
        )?;

        for node in &graph.nodes {
            self.conn.execute(
                r#"
                INSERT INTO graph_nodes (
                    graph_id,
                    node_id,
                    target,
                    kind,
                    label,
                    first_seen,
                    last_seen,
                    attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
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
        _scope: &StorageScope,
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
            WHERE target = ?1
            ORDER BY generated_at DESC
            "#,
        )?;

        let rows = stmt.query_map([target], |row| {
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
        _scope: &StorageScope,
        target: &str,
    ) -> Result<Option<ExposureGraph>> {
        let graph_row = self.conn.query_row(
            r#"
            SELECT graph_id, generated_at
            FROM graphs
            WHERE target = ?1
            ORDER BY generated_at DESC
            LIMIT 1
            "#,
            [target],
            |row| Ok((row_string(row, 0)?, row_string(row, 1)?)),
        );

        let (graph_id, generated_at_str) = match graph_row {
            Ok(row) => row,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err.into()),
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
            WHERE graph_id = ?1
            ORDER BY node_id ASC
            "#,
        )?;

        let node_rows = nodes_stmt.query_map([graph_id.clone()], |row| {
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
        })?;

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
            WHERE graph_id = ?1
            ORDER BY edge_id ASC
            "#,
        )?;

        let edge_rows = edges_stmt.query_map([graph_id], |row| {
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
        })?;

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
        _scope: &StorageScope,
        name: &str,
        expression: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO saved_queries (
                name,
                expression,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(name) DO UPDATE SET
                expression = excluded.expression,
                updated_at = excluded.updated_at
            "#,
            params![name, expression, now, now],
        )?;

        Ok(())
    }

    pub fn list_saved_queries(&self) -> Result<Vec<StoredSavedQuery>> {
        self.list_saved_queries_scoped(&StorageScope::global())
    }

    pub fn list_saved_queries_scoped(
        &self,
        _scope: &StorageScope,
    ) -> Result<Vec<StoredSavedQuery>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                name,
                expression,
                created_at,
                updated_at
            FROM saved_queries
            ORDER BY name ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
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
        _scope: &StorageScope,
        name: &str,
    ) -> Result<Option<StoredSavedQuery>> {
        let result = self.conn.query_row(
            r#"
            SELECT
                name,
                expression,
                created_at,
                updated_at
            FROM saved_queries
            WHERE name = ?1
            "#,
            [name],
            |row| {
                Ok(StoredSavedQuery {
                    name: row_string(row, 0)?,
                    expression: row_string(row, 1)?,
                    created_at: row_string(row, 2)?,
                    updated_at: row_string(row, 3)?,
                })
            },
        );

        match result {
            Ok(item) => Ok(Some(item)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn delete_saved_query(&self, name: &str) -> Result<()> {
        self.delete_saved_query_scoped(&StorageScope::global(), name)
    }

    pub fn delete_saved_query_scoped(&self, _scope: &StorageScope, name: &str) -> Result<()> {
        self.conn.execute(
            r#"
            DELETE FROM saved_queries
            WHERE name = ?1
            "#,
            [name],
        )?;

        Ok(())
    }

    fn repair_legacy_tables_if_needed(&self) -> Result<()> {
        self.repair_table_if_needed(
            "snapshots",
            &[
                ("snapshot_id", "TEXT"),
                ("target", "TEXT"),
                ("timestamp", "TEXT"),
                ("snapshot_version", "INTEGER"),
                ("file_hash", "TEXT"),
                ("path", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE snapshots (
                snapshot_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO snapshots (
                    snapshot_id,
                    target,
                    timestamp,
                    snapshot_version,
                    file_hash,
                    path,
                    created_at
                )
                SELECT
                    CAST(snapshot_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(timestamp AS TEXT),
                    CAST(snapshot_version AS INTEGER),
                    CAST(file_hash AS TEXT),
                    CAST(path AS TEXT),
                    CAST(created_at AS TEXT)
                FROM snapshots_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "drift_runs",
            &[
                ("run_id", "TEXT"),
                ("target", "TEXT"),
                ("older_snapshot_path", "TEXT"),
                ("newer_snapshot_path", "TEXT"),
                ("policy_path", "TEXT"),
                ("total_findings", "INTEGER"),
                ("total_score", "INTEGER"),
                ("overall_severity", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE drift_runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                older_snapshot_path TEXT NOT NULL,
                newer_snapshot_path TEXT NOT NULL,
                policy_path TEXT,
                total_findings INTEGER NOT NULL,
                total_score INTEGER NOT NULL,
                overall_severity TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO drift_runs (
                    run_id,
                    target,
                    older_snapshot_path,
                    newer_snapshot_path,
                    policy_path,
                    total_findings,
                    total_score,
                    overall_severity,
                    created_at
                )
                SELECT
                    CAST(run_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(older_snapshot_path AS TEXT),
                    CAST(newer_snapshot_path AS TEXT),
                    CAST(policy_path AS TEXT),
                    CAST(total_findings AS INTEGER),
                    CAST(total_score AS INTEGER),
                    CAST(overall_severity AS TEXT),
                    CAST(created_at AS TEXT)
                FROM drift_runs_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "findings",
            &[
                ("finding_id", "TEXT"),
                ("run_id", "TEXT"),
                ("target", "TEXT"),
                ("severity", "TEXT"),
                ("state", "TEXT"),
                ("category", "TEXT"),
                ("title", "TEXT"),
                ("resource", "TEXT"),
                ("asset_type", "TEXT"),
                ("environment", "TEXT"),
                ("criticality", "TEXT"),
                ("score", "INTEGER"),
                ("tags_json", "TEXT"),
                ("description", "TEXT"),
                ("is_suppressed", "INTEGER"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE findings (
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
                PRIMARY KEY (finding_id, run_id)
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO findings (
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
                )
                SELECT
                    CAST(finding_id AS TEXT),
                    CAST(run_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(severity AS TEXT),
                    CAST(state AS TEXT),
                    CAST(category AS TEXT),
                    CAST(title AS TEXT),
                    CAST(resource AS TEXT),
                    CAST(asset_type AS TEXT),
                    CAST(environment AS TEXT),
                    CAST(criticality AS TEXT),
                    CAST(score AS INTEGER),
                    CAST(tags_json AS TEXT),
                    CAST(description AS TEXT),
                    CAST(is_suppressed AS INTEGER),
                    CAST(created_at AS TEXT)
                FROM findings_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "telemetry",
            &[
                ("telemetry_id", "TEXT"),
                ("name", "TEXT"),
                ("target", "TEXT"),
                ("duration_ms", "TEXT"),
                ("metadata_json", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE telemetry (
                telemetry_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT,
                duration_ms TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO telemetry (
                    telemetry_id,
                    name,
                    target,
                    duration_ms,
                    metadata_json,
                    created_at
                )
                SELECT
                    CAST(telemetry_id AS TEXT),
                    CAST(name AS TEXT),
                    CAST(target AS TEXT),
                    CAST(duration_ms AS TEXT),
                    CAST(metadata_json AS TEXT),
                    CAST(created_at AS TEXT)
                FROM telemetry_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "jobs",
            &[
                ("job_id", "TEXT"),
                ("target", "TEXT"),
                ("profile", "TEXT"),
                ("interval_seconds", "INTEGER"),
                ("enabled", "INTEGER"),
                ("policy_path", "TEXT"),
                ("last_run_at", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                policy_path TEXT,
                last_run_at TEXT,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO jobs (
                    job_id,
                    target,
                    profile,
                    interval_seconds,
                    enabled,
                    policy_path,
                    last_run_at,
                    created_at
                )
                SELECT
                    CAST(job_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(profile AS TEXT),
                    CAST(interval_seconds AS INTEGER),
                    CAST(enabled AS INTEGER),
                    CAST(policy_path AS TEXT),
                    CAST(last_run_at AS TEXT),
                    CAST(created_at AS TEXT)
                FROM jobs_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "baseline_entries",
            &[("resource", "TEXT"), ("created_at", "TEXT")],
            r#"
            CREATE TABLE baseline_entries (
                resource TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO baseline_entries (
                    resource,
                    created_at
                )
                SELECT
                    CAST(resource AS TEXT),
                    CAST(created_at AS TEXT)
                FROM baseline_entries_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "episodes",
            &[
                ("episode_id", "TEXT"),
                ("target", "TEXT"),
                ("title", "TEXT"),
                ("kind", "TEXT"),
                ("severity", "TEXT"),
                ("criticality", "TEXT"),
                ("score", "INTEGER"),
                ("state", "TEXT"),
                ("resource_count", "INTEGER"),
                ("resources_json", "TEXT"),
                ("cluster_ids_json", "TEXT"),
                ("started_at", "TEXT"),
                ("ended_at", "TEXT"),
                ("summary", "TEXT"),
                ("explanation_json", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE episodes (
                episode_id TEXT PRIMARY KEY,
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
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO episodes (
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
                )
                SELECT
                    CAST(episode_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(title AS TEXT),
                    CAST(kind AS TEXT),
                    CAST(severity AS TEXT),
                    CAST(criticality AS TEXT),
                    CAST(score AS INTEGER),
                    CAST(state AS TEXT),
                    CAST(resource_count AS INTEGER),
                    CAST(resources_json AS TEXT),
                    CAST(cluster_ids_json AS TEXT),
                    CAST(started_at AS TEXT),
                    CAST(ended_at AS TEXT),
                    CAST(summary AS TEXT),
                    CAST(explanation_json AS TEXT),
                    CAST(created_at AS TEXT)
                FROM episodes_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "graphs",
            &[
                ("graph_id", "TEXT"),
                ("target", "TEXT"),
                ("node_count", "INTEGER"),
                ("edge_count", "INTEGER"),
                ("generated_at", "TEXT"),
                ("summary_json", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE graphs (
                graph_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO graphs (
                    graph_id,
                    target,
                    node_count,
                    edge_count,
                    generated_at,
                    summary_json,
                    created_at
                )
                SELECT
                    CAST(graph_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(node_count AS INTEGER),
                    CAST(edge_count AS INTEGER),
                    CAST(generated_at AS TEXT),
                    CAST(summary_json AS TEXT),
                    CAST(created_at AS TEXT)
                FROM graphs_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "graph_nodes",
            &[
                ("graph_id", "TEXT"),
                ("node_id", "TEXT"),
                ("target", "TEXT"),
                ("kind", "TEXT"),
                ("label", "TEXT"),
                ("first_seen", "TEXT"),
                ("last_seen", "TEXT"),
                ("attributes_json", "TEXT"),
            ],
            r#"
            CREATE TABLE graph_nodes (
                graph_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (graph_id, node_id)
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO graph_nodes (
                    graph_id,
                    node_id,
                    target,
                    kind,
                    label,
                    first_seen,
                    last_seen,
                    attributes_json
                )
                SELECT
                    CAST(graph_id AS TEXT),
                    CAST(node_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(kind AS TEXT),
                    CAST(label AS TEXT),
                    CAST(first_seen AS TEXT),
                    CAST(last_seen AS TEXT),
                    CAST(attributes_json AS TEXT)
                FROM graph_nodes_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "graph_edges",
            &[
                ("graph_id", "TEXT"),
                ("edge_id", "TEXT"),
                ("target", "TEXT"),
                ("from_node", "TEXT"),
                ("to_node", "TEXT"),
                ("kind", "TEXT"),
                ("weight", "INTEGER"),
                ("first_seen", "TEXT"),
                ("last_seen", "TEXT"),
                ("attributes_json", "TEXT"),
            ],
            r#"
            CREATE TABLE graph_edges (
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
                PRIMARY KEY (graph_id, edge_id)
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO graph_edges (
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
                )
                SELECT
                    CAST(graph_id AS TEXT),
                    CAST(edge_id AS TEXT),
                    CAST(target AS TEXT),
                    CAST(from_node AS TEXT),
                    CAST(to_node AS TEXT),
                    CAST(kind AS TEXT),
                    CAST(weight AS INTEGER),
                    CAST(first_seen AS TEXT),
                    CAST(last_seen AS TEXT),
                    CAST(attributes_json AS TEXT)
                FROM graph_edges_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "saved_queries",
            &[
                ("name", "TEXT"),
                ("expression", "TEXT"),
                ("created_at", "TEXT"),
                ("updated_at", "TEXT"),
            ],
            r#"
            CREATE TABLE saved_queries (
                name TEXT PRIMARY KEY,
                expression TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
            Some(
                r#"
                INSERT OR IGNORE INTO saved_queries (
                    name,
                    expression,
                    created_at,
                    updated_at
                )
                SELECT
                    CAST(name AS TEXT),
                    CAST(expression AS TEXT),
                    CAST(created_at AS TEXT),
                    CAST(updated_at AS TEXT)
                FROM saved_queries_legacy_incompatible
                "#,
            ),
        )?;

        self.repair_table_if_needed(
            "audit_events",
            &[
                ("audit_id", "TEXT"),
                ("tenant_id", "TEXT"),
                ("project_id", "TEXT"),
                ("actor", "TEXT"),
                ("action", "TEXT"),
                ("resource_type", "TEXT"),
                ("resource_id", "TEXT"),
                ("details_json", "TEXT"),
                ("created_at", "TEXT"),
            ],
            r#"
            CREATE TABLE audit_events (
                audit_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
            None,
        )?;

        Ok(())
    }

    fn repair_table_if_needed(
        &self,
        table: &str,
        expected: &[(&str, &str)],
        create_sql: &str,
        copy_sql: Option<&str>,
    ) -> Result<()> {
        let columns = self.read_table_info(table)?;
        if columns.is_empty() {
            return Ok(());
        }

        let compatible = expected.iter().all(|(name, expected_type)| {
            columns.iter().any(|column| {
                column.name == *name
                    && column
                        .declared_type
                        .to_ascii_uppercase()
                        .contains(&expected_type.to_ascii_uppercase())
            })
        });

        if compatible {
            return Ok(());
        }

        let legacy = format!("{table}_legacy_incompatible");
        self.conn
            .execute_batch(&format!("DROP TABLE IF EXISTS {legacy};"))?;
        self.conn
            .execute_batch(&format!("ALTER TABLE {table} RENAME TO {legacy};"))?;
        self.conn.execute_batch(create_sql)?;

        if let Some(copy_sql) = copy_sql {
            self.conn.execute_batch(copy_sql)?;
        }

        Ok(())
    }

    fn read_table_info(&self, table: &str) -> Result<Vec<TableColumn>> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = self.conn.prepare(&pragma)?;
        let rows = stmt.query_map([], |row| {
            Ok(TableColumn {
                name: row.get(1)?,
                declared_type: row.get(2)?,
            })
        })?;

        let mut columns = Vec::new();
        for row in rows {
            columns.push(row?);
        }
        Ok(columns)
    }
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
    use std::collections::BTreeMap;

    #[test]
    fn stores_and_loads_graph() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-graph-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

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

        store.store_graph("example.com", &graph).unwrap();
        let loaded = store.load_latest_graph("example.com").unwrap().unwrap();

        assert_eq!(loaded.target, "example.com");
        assert!(loaded.node_count >= 1);
    }

    #[test]
    fn stores_and_loads_saved_query() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-saved-query-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        store
            .save_saved_query("risky-admin", "services label~admin")
            .unwrap();

        let item = store.load_saved_query("risky-admin").unwrap().unwrap();
        assert_eq!(item.name, "risky-admin");
        assert_eq!(item.expression, "services label~admin");

        let list = store.list_saved_queries().unwrap();
        assert_eq!(list.len(), 1);

        store.delete_saved_query("risky-admin").unwrap();
        assert!(store.load_saved_query("risky-admin").unwrap().is_none());
    }

    #[test]
    fn sets_and_reads_finding_operational_state() {
        let db_path = std::env::temp_dir().join(format!(
            "atlas-store-finding-state-test-{}.db",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let store = AtlasStore::open(&db_path).unwrap();
        store.initialize().unwrap();

        store
            .conn
            .execute(
                r#"
            INSERT INTO findings (
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
                params![
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
            .set_finding_operational_state("f1", "acknowledged")
            .unwrap();
        store.assign_finding_owner("f1", "claudio").unwrap();
        store.set_finding_note("f1", "en revisión").unwrap();

        let state = store.get_finding_operational_state("f1").unwrap().unwrap();
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
}
