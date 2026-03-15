use anyhow::{bail, Result};
use atlas_drift::{DriftFinding, DriftReport};
use atlas_jobs::AtlasJob;
use atlas_snapshot::{snapshot_file_hash, Snapshot};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone)]
pub struct StoredSnapshotMeta {
    pub snapshot_id: i64,
    pub target: String,
    pub timestamp: String,
    pub path: String,
    pub file_hash: String,
    pub snapshot_version: u32,
}

#[derive(Debug, Clone)]
pub struct StoredDriftRunMeta {
    pub run_id: i64,
    pub target: String,
    pub older_snapshot_path: String,
    pub newer_snapshot_path: String,
    pub total_findings: usize,
    pub total_score: u32,
    pub overall_severity: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct StoredFindingRecord {
    pub finding_id: String,
    pub drift_run_id: i64,
    pub target: String,
    pub resource: String,
    pub category: String,
    pub severity: String,
    pub criticality: String,
    pub state: String,
    pub score: u32,
    pub asset_type: String,
    pub environment: String,
    pub tags: Vec<String>,
    pub description: String,
    pub created_at: String,
    pub suppressed: bool,
}

#[derive(Debug, Clone)]
pub struct BaselineRecord {
    pub resource: String,
    pub approved: bool,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct TelemetryRecord {
    pub name: String,
    pub target: Option<String>,
    pub duration_ms: u128,
    pub metadata_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy)]
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
            _ => bail!("formato de exportación no soportado"),
        }
    }
}

pub struct AtlasStore {
    db_path: PathBuf,
    conn: Connection,
}

impl AtlasStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        Ok(Self {
            db_path: path.to_path_buf(),
            conn,
        })
    }

    pub fn initialize(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_meta (
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                file_hash TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS drift_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                drift_run_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                resource TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                criticality TEXT NOT NULL,
                state TEXT NOT NULL,
                score INTEGER NOT NULL,
                asset_type TEXT NOT NULL,
                environment TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                description TEXT NOT NULL,
                suppressed INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telemetry_events (
                telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target TEXT,
                duration_ms TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                policy_path TEXT,
                profile TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                last_run_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baseline_entries (
                resource TEXT PRIMARY KEY,
                approved INTEGER NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );
            "#,
        )?;

        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM schema_meta", [], |row| row.get(0))?;

        if count == 0 {
            self.conn.execute(
                "INSERT INTO schema_meta(version) VALUES (?1)",
                params![SCHEMA_VERSION],
            )?;
        } else {
            self.conn.execute(
                "UPDATE schema_meta SET version = ?1",
                params![SCHEMA_VERSION],
            )?;
        }

        Ok(())
    }

    pub fn current_schema_version(&self) -> Result<i64> {
        let version =
            self.conn
                .query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| {
                    row.get(0)
                })?;
        Ok(version)
    }

    pub fn register_snapshot(&self, snapshot_path: &Path, snapshot: &Snapshot) -> Result<i64> {
        let file_hash = snapshot_file_hash(snapshot_path)?;
        let created_at = now_rfc3339();

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO snapshots (
                target, timestamp, path, file_hash, snapshot_version, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                snapshot.target,
                snapshot.timestamp.to_rfc3339(),
                snapshot_path.display().to_string(),
                file_hash,
                snapshot.snapshot_version,
                created_at
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn register_drift_report(
        &self,
        target: &str,
        older_snapshot_path: &Path,
        newer_snapshot_path: &Path,
        policy_path: Option<&Path>,
        report: &DriftReport,
    ) -> Result<i64> {
        let created_at = now_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO drift_runs (
                target, older_snapshot_path, newer_snapshot_path, policy_path,
                total_findings, total_score, overall_severity, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                target,
                older_snapshot_path.display().to_string(),
                newer_snapshot_path.display().to_string(),
                policy_path.map(|p| p.display().to_string()),
                report.findings.len(),
                report.summary.total_score,
                report.summary.overall_severity.to_string(),
                created_at
            ],
        )?;

        let run_id = self.conn.last_insert_rowid();

        for finding in &report.findings {
            self.insert_finding(run_id, target, finding, false)?;
        }

        for finding in &report.suppressed_findings {
            self.insert_finding(run_id, target, finding, true)?;
        }

        Ok(run_id)
    }

    fn insert_finding(
        &self,
        run_id: i64,
        target: &str,
        finding: &DriftFinding,
        suppressed: bool,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO findings (
                finding_id, drift_run_id, target, resource, category, severity, criticality,
                state, score, asset_type, environment, tags_json, description, suppressed, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            params![
                finding.finding_id,
                run_id,
                target,
                finding.resource,
                finding.category,
                finding.severity.to_string(),
                finding.criticality.to_string(),
                finding.state.to_string(),
                finding.score,
                finding.asset_type.to_string(),
                finding.environment.to_string(),
                serde_json::to_string(&finding.tags)?,
                finding.description,
                if suppressed { 1 } else { 0 },
                now_rfc3339()
            ],
        )?;

        Ok(())
    }

    pub fn list_snapshots(&self, target: &str) -> Result<Vec<StoredSnapshotMeta>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT snapshot_id, target, timestamp, path, file_hash, snapshot_version
            FROM snapshots
            WHERE target = ?1
            ORDER BY timestamp ASC
            "#,
        )?;

        let rows = stmt.query_map(params![target], |row| {
            Ok(StoredSnapshotMeta {
                snapshot_id: row.get(0)?,
                target: row.get(1)?,
                timestamp: row.get(2)?,
                path: row.get(3)?,
                file_hash: row.get(4)?,
                snapshot_version: row.get(5)?,
            })
        })?;

        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }

        Ok(output)
    }

    pub fn list_history(&self, target: &str) -> Result<Vec<StoredDriftRunMeta>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT run_id, target, older_snapshot_path, newer_snapshot_path,
                   total_findings, total_score, overall_severity, created_at
            FROM drift_runs
            WHERE target = ?1
            ORDER BY run_id DESC
            "#,
        )?;

        let rows = stmt.query_map(params![target], |row| {
            Ok(StoredDriftRunMeta {
                run_id: row.get(0)?,
                target: row.get(1)?,
                older_snapshot_path: row.get(2)?,
                newer_snapshot_path: row.get(3)?,
                total_findings: row.get(4)?,
                total_score: row.get(5)?,
                overall_severity: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }

        Ok(output)
    }

    pub fn list_findings(
        &self,
        target: &str,
        severity: Option<&str>,
        state: Option<&str>,
    ) -> Result<Vec<StoredFindingRecord>> {
        let mut all = self.list_findings_internal(target)?;

        if let Some(severity) = severity {
            let severity_lower = severity.to_ascii_lowercase();
            all.retain(|f| f.severity.eq_ignore_ascii_case(&severity_lower));
        }

        if let Some(state) = state {
            let state_lower = state.to_ascii_lowercase();
            all.retain(|f| f.state.eq_ignore_ascii_case(&state_lower));
        }

        Ok(all)
    }

    fn list_findings_internal(&self, target: &str) -> Result<Vec<StoredFindingRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT finding_id, drift_run_id, target, resource, category, severity, criticality,
                   state, score, asset_type, environment, tags_json, description, created_at, suppressed
            FROM findings
            WHERE target = ?1
            ORDER BY row_id DESC
            "#,
        )?;

        let rows = stmt.query_map(params![target], |row| {
            let tags_json: String = row.get(11)?;
            let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();

            Ok(StoredFindingRecord {
                finding_id: row.get(0)?,
                drift_run_id: row.get(1)?,
                target: row.get(2)?,
                resource: row.get(3)?,
                category: row.get(4)?,
                severity: row.get(5)?,
                criticality: row.get(6)?,
                state: row.get(7)?,
                score: row.get(8)?,
                asset_type: row.get(9)?,
                environment: row.get(10)?,
                tags,
                description: row.get(12)?,
                created_at: row.get(13)?,
                suppressed: row.get::<_, i64>(14)? == 1,
            })
        })?;

        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }

        Ok(output)
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

        match format {
            ExportFormat::Json => {
                let payload = serde_json::to_string_pretty(
                    &findings
                        .iter()
                        .map(|f| {
                            serde_json::json!({
                                "finding_id": f.finding_id,
                                "drift_run_id": f.drift_run_id,
                                "target": f.target,
                                "resource": f.resource,
                                "category": f.category,
                                "severity": f.severity,
                                "criticality": f.criticality,
                                "state": f.state,
                                "score": f.score,
                                "asset_type": f.asset_type,
                                "environment": f.environment,
                                "tags": f.tags,
                                "description": f.description,
                                "created_at": f.created_at,
                                "suppressed": f.suppressed
                            })
                        })
                        .collect::<Vec<_>>(),
                )?;
                fs::write(output, payload)?;
            }
            ExportFormat::Ndjson => {
                let mut content = String::new();
                for f in &findings {
                    let line = serde_json::to_string(&serde_json::json!({
                        "finding_id": f.finding_id,
                        "drift_run_id": f.drift_run_id,
                        "target": f.target,
                        "resource": f.resource,
                        "category": f.category,
                        "severity": f.severity,
                        "criticality": f.criticality,
                        "state": f.state,
                        "score": f.score,
                        "asset_type": f.asset_type,
                        "environment": f.environment,
                        "tags": f.tags,
                        "description": f.description,
                        "created_at": f.created_at,
                        "suppressed": f.suppressed
                    }))?;
                    content.push_str(&line);
                    content.push('\n');
                }
                fs::write(output, content)?;
            }
            ExportFormat::Csv => {
                let mut content = String::from(
                    "finding_id,drift_run_id,target,resource,category,severity,criticality,state,score,asset_type,environment,tags,description,created_at,suppressed\n",
                );

                for f in &findings {
                    content.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                        csv_escape(&f.finding_id),
                        f.drift_run_id,
                        csv_escape(&f.target),
                        csv_escape(&f.resource),
                        csv_escape(&f.category),
                        csv_escape(&f.severity),
                        csv_escape(&f.criticality),
                        csv_escape(&f.state),
                        f.score,
                        csv_escape(&f.asset_type),
                        csv_escape(&f.environment),
                        csv_escape(&f.tags.join("|")),
                        csv_escape(&f.description),
                        csv_escape(&f.created_at),
                        f.suppressed
                    ));
                }

                fs::write(output, content)?;
            }
        }

        Ok(())
    }

    pub fn record_telemetry(
        &self,
        name: &str,
        target: Option<&str>,
        duration_ms: u128,
        metadata: &Value,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO telemetry_events (name, target, duration_ms, metadata_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                name,
                target,
                duration_ms.to_string(),
                serde_json::to_string(metadata)?,
                now_rfc3339()
            ],
        )?;

        Ok(())
    }

    pub fn list_telemetry(&self, limit: usize) -> Result<Vec<TelemetryRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT name, target, duration_ms, metadata_json, created_at
            FROM telemetry_events
            ORDER BY telemetry_id DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let duration_ms_str: String = row.get(2)?;
            let duration_ms = duration_ms_str.parse::<u128>().unwrap_or_default();

            Ok(TelemetryRecord {
                name: row.get(0)?,
                target: row.get(1)?,
                duration_ms,
                metadata_json: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }

        Ok(output)
    }

    pub fn create_job(&self, job: &AtlasJob) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO jobs (
                job_id, target, policy_path, profile, interval_seconds, enabled, last_run_at, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                job.job_id,
                job.target,
                job.policy_path,
                job.profile,
                job.interval_seconds,
                if job.enabled { 1 } else { 0 },
                job.last_run_at
                    .map(|d: chrono::DateTime<chrono::Utc>| d.to_rfc3339()),
                job.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_jobs(&self) -> Result<Vec<AtlasJob>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT job_id, target, policy_path, profile, interval_seconds, enabled, last_run_at, created_at
            FROM jobs
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            let last_run_at: Option<String> = row.get(6)?;
            let created_at: String = row.get(7)?;

            Ok(AtlasJob {
                job_id: row.get(0)?,
                target: row.get(1)?,
                policy_path: row.get(2)?,
                profile: row.get(3)?,
                interval_seconds: row.get(4)?,
                enabled: row.get::<_, i64>(5)? == 1,
                last_run_at: last_run_at
                    .as_deref()
                    .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }

        Ok(jobs)
    }

    pub fn set_job_enabled(&self, job_id: &str, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE jobs SET enabled = ?1 WHERE job_id = ?2",
            params![if enabled { 1 } else { 0 }, job_id],
        )?;
        Ok(())
    }

    pub fn touch_job_run(&self, job_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE jobs SET last_run_at = ?1 WHERE job_id = ?2",
            params![now_rfc3339(), job_id],
        )?;
        Ok(())
    }

    pub fn approve_baseline(&self, resource: &str, expires_at: Option<&str>) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO baseline_entries(resource, approved, expires_at, created_at)
            VALUES (?1, 1, ?2, ?3)
            ON CONFLICT(resource) DO UPDATE SET approved = 1, expires_at = excluded.expires_at
            "#,
            params![resource, expires_at, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn revoke_baseline(&self, resource: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM baseline_entries WHERE resource = ?1",
            params![resource],
        )?;
        Ok(())
    }

    pub fn list_baseline(&self) -> Result<Vec<BaselineRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT resource, approved, expires_at, created_at
            FROM baseline_entries
            ORDER BY resource ASC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(BaselineRecord {
                resource: row.get(0)?,
                approved: row.get::<_, i64>(1)? == 1,
                expires_at: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }

        Ok(records)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn csv_escape(input: &str) -> String {
    let escaped = input.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
