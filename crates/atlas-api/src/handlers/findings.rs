use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{
        ApiEnvelope, FindingPatchRequest, FindingsResponse, PaginationMeta, RawFindingsResponse,
    },
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct FindingsParams {
    pub severity: Option<String>,
    pub state: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CurrentFindingsParams {
    pub severity: Option<String>,
    pub state: Option<String>,
    pub operational_state: Option<String>,
    pub owner: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AssignFindingRequest {
    pub owner: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct NoteFindingRequest {
    pub notes: String,
}

pub async fn list_findings(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
    Query(params): Query<FindingsParams>,
) -> ApiResult<Json<RawFindingsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_findings_scoped(
        &scope,
        &target,
        params.severity.as_deref(),
        params.state.as_deref(),
    )?;
    items.truncate(limit);

    Ok(Json(RawFindingsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn list_current_findings(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
    Query(params): Query<CurrentFindingsParams>,
) -> ApiResult<Json<FindingsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_current_findings_operational_scoped(
        &scope,
        &target,
        params.severity.as_deref(),
        params.state.as_deref(),
        params.operational_state.as_deref(),
        params.owner.as_deref(),
    )?;
    items.truncate(limit);

    Ok(Json(FindingsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn patch_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<FindingPatchRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);
    let mut changes = Vec::new();

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    if let Some(op_state) = payload.operational_state.as_deref() {
        store.set_finding_operational_state_scoped(&scope, &finding_id, op_state)?;
        changes.push(format!("operational_state={op_state}"));
    }

    if let Some(owner) = payload.owner.as_deref() {
        store.assign_finding_owner_scoped(&scope, &finding_id, owner)?;
        changes.push(format!("owner={owner}"));
    }

    if let Some(note) = payload.note.as_deref() {
        store.set_finding_note_scoped(&scope, &finding_id, note)?;
        changes.push("note".to_string());
    }

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "finding.patch",
        "finding",
        &finding_id,
        &serde_json::json!({ "changes": changes }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "finding_id": finding_id,
            "changes": changes
        }),
    }))
}

pub async fn ack_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    set_finding_state(state, auth, finding_id, "acknowledged", "finding.ack").await
}

pub async fn resolve_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    set_finding_state(state, auth, finding_id, "resolved", "finding.resolve").await
}

pub async fn accept_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    set_finding_state(state, auth, finding_id, "accepted", "finding.accept").await
}

async fn set_finding_state(
    state: Arc<AppState>,
    auth: AuthContext,
    finding_id: String,
    op_state: &'static str,
    audit_action: &'static str,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.set_finding_operational_state_scoped(&scope, &finding_id, op_state)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        audit_action,
        "finding",
        &finding_id,
        &serde_json::json!({ "operational_state": op_state }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "finding_id": finding_id,
            "operational_state": op_state
        }),
    }))
}

pub async fn assign_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<AssignFindingRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.assign_finding_owner_scoped(&scope, &finding_id, &payload.owner)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "finding.assign",
        "finding",
        &finding_id,
        &serde_json::json!({ "owner": payload.owner }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "finding_id": finding_id,
            "owner": payload.owner
        }),
    }))
}

pub async fn note_finding(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(finding_id): Path<String>,
    Json(payload): Json<NoteFindingRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.set_finding_note_scoped(&scope, &finding_id, &payload.notes)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "finding.note",
        "finding",
        &finding_id,
        &serde_json::json!({ "notes": payload.notes }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "finding_id": finding_id
        }),
    }))
}
