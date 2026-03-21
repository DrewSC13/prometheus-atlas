use crate::{
    auth::{scope_from_auth, AuthContext},
    state::AppState,
};
use atlas_jobs::AtlasJob;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub target: String,
    pub profile: String,
    pub interval_seconds: u64,
    pub policy_path: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RunJobRequest {
    pub persist: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct JobListParams {
    pub limit: Option<usize>,
}

pub async fn create_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(payload): Json<CreateJobRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let job = AtlasJob {
        job_id: format!(
            "job:{}:{}",
            payload.target,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ),
        target: payload.target.clone(),
        profile: payload.profile.clone(),
        interval_seconds: payload.interval_seconds,
        enabled: payload.enabled.unwrap_or(true),
        policy_path: payload.policy_path.clone(),
        last_run_at: None,
        created_at: Utc::now(),
    };

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .insert_job_scoped(&scope, &job)
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "job.create",
            "job",
            &job.job_id,
            &json!({
                "target": job.target,
                "profile": job.profile,
                "interval_seconds": job.interval_seconds
            }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "job": job,
    })))
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(_params): Query<JobListParams>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store.list_jobs_scoped(&scope).map_err(internal_error)?;

    Ok(Json(json!({ "items": items })))
}

pub async fn get_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let job = store
        .list_jobs_scoped(&scope)
        .map_err(internal_error)?
        .into_iter()
        .find(|item| item.job_id == job_id);

    Ok(Json(json!({
        "job_id": job_id,
        "job": job,
    })))
}

pub async fn enable_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    set_job_enabled(state, auth, job_id, true).await
}

pub async fn disable_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    set_job_enabled(state, auth, job_id, false).await
}

async fn set_job_enabled(
    state: Arc<AppState>,
    auth: AuthContext,
    job_id: String,
    enabled: bool,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let mut job = store
        .list_jobs_scoped(&scope)
        .map_err(internal_error)?
        .into_iter()
        .find(|item| item.job_id == job_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "job no encontrado".to_string()))?;

    job.enabled = enabled;

    store
        .insert_job_scoped(&scope, &job)
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            if enabled { "job.enable" } else { "job.disable" },
            "job",
            &job.job_id,
            &json!({ "enabled": enabled }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "job": job,
    })))
}

pub async fn run_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
    Json(payload): Json<RunJobRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let jobs = store.list_jobs_scoped(&scope).map_err(internal_error)?;
    let job = jobs
        .into_iter()
        .find(|item| item.job_id == job_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "job no encontrado".to_string()))?;

    store
        .touch_job_run_scoped(&scope, &job.job_id)
        .map_err(internal_error)?;

    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "job.run",
            "job",
            &job.job_id,
            &json!({ "persist": payload.persist.unwrap_or(false) }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "job_id": job.job_id,
        "target": job.target,
        "persist": payload.persist.unwrap_or(false),
        "executed": false,
        "message": "handler API registrado; ejecución real queda delegada al runtime/CLI"
    })))
}

pub async fn delete_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .delete_job_scoped(&scope, &job_id)
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "job.delete",
            "job",
            &job_id,
            &json!({}),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "job_id": job_id,
    })))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
