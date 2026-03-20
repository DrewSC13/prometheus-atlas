use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct ListFindingsRequest {
    pub target: String,
    pub severity: Option<String>,
    pub state: Option<String>,
    pub operational_state: Option<String>,
    pub owner: Option<String>,
    pub current: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AssignFindingRequest {
    pub owner: String,
}

#[derive(Debug, Deserialize)]
pub struct NoteFindingRequest {
    pub note: String,
}

pub async fn list_findings(
    State(state): State<Arc<AppState>>,
    Query(request): Query<ListFindingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let store = state.open_store()?;
    store.initialize()?;

    if request.current.unwrap_or(true) {
        let items = store.list_current_findings_operational(
            &request.target,
            request.severity.as_deref(),
            request.state.as_deref(),
            request.operational_state.as_deref(),
            request.owner.as_deref(),
        )?;

        Ok(Json(json!({
            "target": request.target,
            "items": items
        })))
    } else {
        let items = store.list_findings(
            &request.target,
            request.severity.as_deref(),
            request.state.as_deref(),
        )?;

        Ok(Json(json!({
            "target": request.target,
            "items": items
        })))
    }
}

pub async fn ack_finding(
    State(state): State<Arc<AppState>>,
    Path(finding_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_operational_state(&state, &finding_id, "acknowledged").await
}

pub async fn resolve_finding(
    State(state): State<Arc<AppState>>,
    Path(finding_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_operational_state(&state, &finding_id, "resolved").await
}

pub async fn accept_finding(
    State(state): State<Arc<AppState>>,
    Path(finding_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_operational_state(&state, &finding_id, "accepted").await
}

pub async fn assign_finding(
    State(state): State<Arc<AppState>>,
    Path(finding_id): Path<String>,
    Json(request): Json<AssignFindingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.owner.trim().is_empty() {
        return Err(ApiError::bad_request("owner no puede estar vacío"));
    }

    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;
    store.assign_finding_owner(&finding_id, &request.owner)?;

    state.record_telemetry(
        "api-finding-assign",
        None,
        started.elapsed().as_millis(),
        &json!({
            "finding_id": finding_id,
            "owner": request.owner
        }),
    )?;

    Ok(Json(json!({
        "finding_id": finding_id,
        "owner": request.owner,
        "updated": true
    })))
}

pub async fn note_finding(
    State(state): State<Arc<AppState>>,
    Path(finding_id): Path<String>,
    Json(request): Json<NoteFindingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.note.trim().is_empty() {
        return Err(ApiError::bad_request("note no puede estar vacía"));
    }

    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;
    store.set_finding_note(&finding_id, &request.note)?;

    state.record_telemetry(
        "api-finding-note",
        None,
        started.elapsed().as_millis(),
        &json!({
            "finding_id": finding_id
        }),
    )?;

    Ok(Json(json!({
        "finding_id": finding_id,
        "updated": true
    })))
}

async fn set_operational_state(
    state: &AppState,
    finding_id: &str,
    operational_state: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;
    store.set_finding_operational_state(finding_id, operational_state)?;

    state.record_telemetry(
        "api-finding-state",
        None,
        started.elapsed().as_millis(),
        &json!({
            "finding_id": finding_id,
            "operational_state": operational_state
        }),
    )?;

    Ok(Json(json!({
        "finding_id": finding_id,
        "operational_state": operational_state,
        "updated": true
    })))
}
