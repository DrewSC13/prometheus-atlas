use crate::{
    auth::{scope_from_auth, AuthContext},
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct FindingsParams {
    pub severity: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CurrentFindingsParams {
    pub severity: Option<String>,
    pub state: Option<String>,
    pub operational_state: Option<String>,
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatchFindingRequest {
    pub operational_state: Option<String>,
    pub owner: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignFindingRequest {
    pub owner: String,
}

#[derive(Debug, Deserialize)]
pub struct NoteFindingRequest {
    pub notes: String,
}

pub async fn list_findings(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
    Query(params): Query<FindingsParams>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store
        .list_findings_scoped(
            &scope,
            &target,
            params.severity.as_deref(),
            params.state.as_deref(),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "target": target,
        "items": items,
    })))
}

pub async fn list_current_findings(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
    Query(params): Query<CurrentFindingsParams>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store
        .list_current_findings_operational_scoped(
            &scope,
            &target,
            params.severity.as_deref(),
            params.state.as_deref(),
            params.operational_state.as_deref(),
            params.owner.as_deref(),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "target": target,
        "items": items,
    })))
}

pub async fn patch_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<PatchFindingRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let mut changes = Vec::new();

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    if let Some(op_state) = payload.operational_state.as_deref() {
        store
            .set_finding_operational_state(&finding_id, op_state)
            .map_err(internal_error)?;
        changes.push(format!("operational_state={op_state}"));
    }

    if let Some(owner) = payload.owner.as_deref() {
        store
            .assign_finding_owner(&finding_id, owner)
            .map_err(internal_error)?;
        changes.push(format!("owner={owner}"));
    }

    if let Some(notes) = payload.notes.as_deref() {
        store
            .set_finding_note(&finding_id, notes)
            .map_err(internal_error)?;
        changes.push("notes".to_string());
    }

    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.patch",
            "finding",
            &finding_id,
            &json!({ "changes": changes }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
        "changes": changes,
    })))
}

pub async fn ack_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .set_finding_operational_state(&finding_id, "acknowledged")
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.ack",
            "finding",
            &finding_id,
            &json!({ "operational_state": "acknowledged" }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
        "operational_state": "acknowledged",
    })))
}

pub async fn resolve_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .set_finding_operational_state(&finding_id, "resolved")
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.resolve",
            "finding",
            &finding_id,
            &json!({ "operational_state": "resolved" }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
        "operational_state": "resolved",
    })))
}

pub async fn accept_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .set_finding_operational_state(&finding_id, "accepted")
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.accept",
            "finding",
            &finding_id,
            &json!({ "operational_state": "accepted" }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
        "operational_state": "accepted",
    })))
}

pub async fn assign_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<AssignFindingRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .assign_finding_owner(&finding_id, &payload.owner)
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.assign",
            "finding",
            &finding_id,
            &json!({ "owner": payload.owner }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
        "owner": payload.owner,
    })))
}

pub async fn note_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<NoteFindingRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let scope = scope_from_auth(&auth);

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .set_finding_note(&finding_id, &payload.notes)
        .map_err(internal_error)?;
    store
        .record_audit_event_scoped(
            &scope,
            &auth.subject,
            "finding.note",
            "finding",
            &finding_id,
            &json!({ "notes": payload.notes }),
        )
        .map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "finding_id": finding_id,
    })))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
