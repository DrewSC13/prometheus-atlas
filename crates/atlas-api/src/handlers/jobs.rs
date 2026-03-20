use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub target: String,
    pub profile: Option<String>,
    pub interval_seconds: Option<u64>,
    pub policy_path: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RunJobRequest {
    pub persist: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct JobHistoryRequest {
    pub target: Option<String>,
    pub job_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct JobHistoryEntry {
    created_at: String,
    command: String,
    target: Option<String>,
    job_id: Option<String>,
    metadata: Value,
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.open_store()?;
    store.initialize()?;
    let jobs = store.list_jobs()?;

    Ok(Json(json!({
        "jobs": jobs
    })))
}

pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let profile = request
        .profile
        .unwrap_or_else(|| state.config.drift.profile.clone());

    state
        .config
        .profile(&profile)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let interval_seconds = request
        .interval_seconds
        .unwrap_or(state.config.jobs.default_interval_seconds);

    if interval_seconds == 0 {
        return Err(ApiError::bad_request("interval_seconds debe ser > 0"));
    }

    let enabled = request.enabled.unwrap_or(true);

    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;

    let job = atlas_jobs::AtlasJob::new(
        request.target.clone(),
        profile.clone(),
        interval_seconds,
        request.policy_path.clone(),
        enabled,
    );

    store.insert_job(&job)?;

    state.record_telemetry(
        "api-job-create",
        Some(&job.target),
        started.elapsed().as_millis(),
        &json!({
            "job_id": job.job_id,
            "profile": profile,
            "interval_seconds": interval_seconds
        }),
    )?;

    Ok(Json(json!({
        "job": job
    })))
}

pub async fn run_job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
    payload: Option<Json<RunJobRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request = payload.map(|Json(body)| body).unwrap_or_default();
    let started = Instant::now();

    let job = {
        let store = state.open_store()?;
        store.initialize()?;
        load_job_by_id(&store, &job_id)?
    };

    let snapshot_path = run_job_once(&state, &job, request.persist).await?;

    {
        let store = state.open_store()?;
        store.initialize()?;
        store.touch_job_run(&job.job_id)?;
    }

    state.record_telemetry(
        "api-job-run",
        Some(&job.target),
        started.elapsed().as_millis(),
        &json!({
            "job_id": job.job_id,
            "snapshot_path": snapshot_path.display().to_string()
        }),
    )?;

    Ok(Json(json!({
        "job_id": job.job_id,
        "target": job.target,
        "snapshot_path": snapshot_path.display().to_string(),
        "persisted": state.should_persist(request.persist)
    })))
}

pub async fn enable_job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_job_enabled(&state, &job_id, true).await
}

pub async fn disable_job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_job_enabled(&state, &job_id, false).await
}

pub async fn delete_job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;
    let job = load_job_by_id(&store, &job_id)?;

    delete_job_record(&PathBuf::from(&state.config.storage.path), &job_id)?;

    state.record_telemetry(
        "api-job-delete",
        Some(&job.target),
        started.elapsed().as_millis(),
        &json!({
            "job_id": job_id
        }),
    )?;

    Ok(Json(json!({
        "job_id": job_id,
        "deleted": true
    })))
}

pub async fn job_history(
    State(state): State<Arc<AppState>>,
    Query(request): Query<JobHistoryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.open_store()?;
    store.initialize()?;

    let items = build_job_history(
        &store,
        request.limit.unwrap_or(100),
        request.target.as_deref(),
        request.job_id.as_deref(),
    )?;

    Ok(Json(json!({
        "items": items
    })))
}

async fn set_job_enabled(
    state: &AppState,
    job_id: &str,
    enabled: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;

    let mut job = load_job_by_id(&store, job_id)?;
    job.enabled = enabled;
    store.insert_job(&job)?;

    state.record_telemetry(
        if enabled {
            "api-job-enable"
        } else {
            "api-job-disable"
        },
        Some(&job.target),
        started.elapsed().as_millis(),
        &json!({
            "job_id": job_id
        }),
    )?;

    Ok(Json(json!({
        "job_id": job_id,
        "enabled": enabled
    })))
}

fn load_job_by_id(
    store: &atlas_store::AtlasStore,
    job_id: &str,
) -> Result<atlas_jobs::AtlasJob, ApiError> {
    store
        .list_jobs()?
        .into_iter()
        .find(|job| job.job_id == job_id)
        .ok_or_else(|| ApiError::not_found(format!("job no encontrado: {job_id}")))
}

async fn run_job_once(
    state: &AppState,
    job: &atlas_jobs::AtlasJob,
    persist_flag: Option<bool>,
) -> Result<PathBuf, ApiError> {
    state
        .config
        .profile(&job.profile)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let result = atlas_discovery::scan_target(&job.target).await?;
    let snapshot = atlas_snapshot::Snapshot::new(result);
    let snapshot_path = atlas_snapshot::save_snapshot(&snapshot, state.snapshot_dir())?;

    let should_persist = state.should_persist(persist_flag);
    if should_persist {
        let store = state.open_store()?;
        store.initialize()?;
        store.register_snapshot(&snapshot_path, &snapshot)?;
        persist_latest_drift_for_target(state, &job.target, job.policy_path.as_deref())?;
    }

    Ok(snapshot_path)
}

fn persist_latest_drift_for_target(
    state: &AppState,
    target: &str,
    policy_path: Option<&str>,
) -> Result<(), ApiError> {
    let paths = atlas_snapshot::list_snapshots_for_target(state.snapshot_dir(), target)?;
    if paths.len() < 2 {
        return Ok(());
    }

    let older_path = &paths[paths.len() - 2];
    let newer_path = &paths[paths.len() - 1];

    let older = atlas_snapshot::load_snapshot(older_path)?;
    let newer = atlas_snapshot::load_snapshot(newer_path)?;
    let diff = atlas_diff::diff_snapshots(&older, &newer);

    let policy = match policy_path {
        Some(path) => {
            let loaded = atlas_drift::DriftPolicy::load_from_path(FsPath::new(path))?;
            loaded.validate()?;
            Some(loaded)
        }
        None => None,
    };

    let report = atlas_drift::analyze_diff_with_policy(&diff, policy.as_ref());

    let store = state.open_store()?;
    store.initialize()?;
    store.register_drift_report(
        target,
        older_path,
        newer_path,
        policy_path.map(FsPath::new),
        &report,
    )?;

    Ok(())
}

fn delete_job_record(db_path: &PathBuf, job_id: &str) -> Result<(), ApiError> {
    let conn = Connection::open(db_path).map_err(|e| ApiError::internal(e.to_string()))?;
    conn.execute("DELETE FROM jobs WHERE job_id = ?1", params![job_id])
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(())
}

fn build_job_history(
    store: &atlas_store::AtlasStore,
    limit: usize,
    target_filter: Option<&str>,
    job_id_filter: Option<&str>,
) -> Result<Vec<JobHistoryEntry>, ApiError> {
    let events = store.list_telemetry(limit)?;
    let mut items = Vec::new();

    for event in events {
        if !matches!(
            event.name.as_str(),
            "api-job-create"
                | "api-job-enable"
                | "api-job-disable"
                | "api-job-delete"
                | "api-job-run"
        ) {
            continue;
        }

        let metadata =
            serde_json::from_str::<Value>(&event.metadata_json).unwrap_or_else(|_| json!({}));

        let metadata_job_id = metadata
            .get("job_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(filter) = target_filter {
            if event.target.as_deref() != Some(filter) {
                continue;
            }
        }

        if let Some(filter) = job_id_filter {
            if metadata_job_id.as_deref() != Some(filter) {
                continue;
            }
        }

        items.push(JobHistoryEntry {
            created_at: event.created_at,
            command: event.name,
            target: event.target,
            job_id: metadata_job_id,
            metadata,
        });
    }

    Ok(items)
}
