use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, JobQueueResponse, JobsResponse, PaginationMeta},
    state::AppState,
};
use atlas_jobs::{AtlasJob, JobDispatchRequest, JobTrigger};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
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

#[derive(Debug, Deserialize)]
pub struct QueueListParams {
    pub limit: Option<usize>,
}

pub async fn create_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(payload): Json<CreateJobRequest>,
) -> ApiResult<Json<ApiEnvelope<AtlasJob>>> {
    auth.require_write()?;

    if payload.interval_seconds == 0 {
        return Err(ApiError::bad_request("interval_seconds debe ser > 0"));
    }

    state
        .config
        .profile(&payload.profile)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

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

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.insert_job_scoped(&scope, &job)?;
    store.record_audit_event_scoped(
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
    )?;

    Ok(Json(ApiEnvelope { data: job }))
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<JobListParams>,
) -> ApiResult<Json<JobsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_jobs_scoped(&scope)?;
    items.truncate(limit);

    Ok(Json(JobsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn get_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<Option<AtlasJob>>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let job = store
        .list_jobs_scoped(&scope)?
        .into_iter()
        .find(|item| item.job_id == job_id);

    Ok(Json(ApiEnvelope { data: job }))
}

pub async fn enable_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<AtlasJob>>> {
    set_job_enabled(state, auth, job_id, true).await
}

pub async fn disable_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<AtlasJob>>> {
    set_job_enabled(state, auth, job_id, false).await
}

async fn set_job_enabled(
    state: Arc<AppState>,
    auth: AuthContext,
    job_id: String,
    enabled: bool,
) -> ApiResult<Json<ApiEnvelope<AtlasJob>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut job = store
        .list_jobs_scoped(&scope)?
        .into_iter()
        .find(|item| item.job_id == job_id)
        .ok_or_else(|| ApiError::not_found("job no encontrado"))?;

    job.enabled = enabled;

    store.insert_job_scoped(&scope, &job)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        if enabled { "job.enable" } else { "job.disable" },
        "job",
        &job.job_id,
        &json!({ "enabled": enabled }),
    )?;

    Ok(Json(ApiEnvelope { data: job }))
}

pub async fn run_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
    payload: Option<Json<RunJobRequest>>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);
    let persist = payload
        .map(|Json(body)| body.persist.unwrap_or(false))
        .unwrap_or(false);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let job = store
        .list_jobs_scoped(&scope)?
        .into_iter()
        .find(|item| item.job_id == job_id)
        .ok_or_else(|| ApiError::not_found("job no encontrado"))?;

    let dispatch = JobDispatchRequest::from_job(
        scope.tenant_id.clone(),
        scope.project_id.clone(),
        &job,
        JobTrigger::Manual,
    )
    .requested_by(auth.subject.clone())
    .persist_artifacts(persist);

    let queue_item = store.enqueue_job_dispatch_scoped(&scope, &dispatch)?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "job.enqueue",
        "job",
        &job.job_id,
        &json!({
            "persist": persist,
            "queue_id": queue_item.queue_id,
            "trigger": "manual"
        }),
    )?;

    Ok(Json(ApiEnvelope {
        data: json!({
            "ok": true,
            "enqueued": true,
            "job_id": job.job_id,
            "target": job.target,
            "persist": persist,
            "queue_item": queue_item
        }),
    }))
}

pub async fn delete_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.delete_job_scoped(&scope, &job_id)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "job.delete",
        "job",
        &job_id,
        &json!({}),
    )?;

    Ok(Json(ApiEnvelope {
        data: json!({
            "ok": true,
            "job_id": job_id
        }),
    }))
}

pub async fn list_job_queue(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<QueueListParams>,
) -> ApiResult<Json<JobQueueResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_job_queue_scoped(&scope, limit)?;
    items.truncate(limit);

    Ok(Json(JobQueueResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn get_queue_item(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(queue_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<Option<atlas_queue::JobQueueItem>>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let item = store.get_job_queue_item_scoped(&scope, &queue_id)?;

    Ok(Json(ApiEnvelope { data: item }))
}
