use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, IncidentPatchRequest, IncidentsResponse, PaginationMeta},
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct IncidentParams {
    pub state: Option<String>,
    pub owner: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AssignIncidentRequest {
    pub owner: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct NoteIncidentRequest {
    pub notes: String,
}

pub async fn list_incidents(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<IncidentParams>,
) -> ApiResult<Json<IncidentsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let items = store.list_incidents_scoped(
        &scope,
        params.state.as_deref(),
        params.owner.as_deref(),
        limit,
    )?;

    Ok(Json(IncidentsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn get_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<atlas_store::StoredIncident>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let incident = store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

    Ok(Json(ApiEnvelope { data: incident }))
}

pub async fn patch_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
    Json(body): Json<IncidentPatchRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);
    let mut changes = Vec::new();

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    if let Some(state_value) = body.state.as_deref() {
        store.set_incident_state_scoped(&scope, &incident_id, state_value)?;
        changes.push(format!("state={state_value}"));
    }

    if let Some(owner) = body.owner.as_deref() {
        store.assign_incident_owner_scoped(&scope, &incident_id, owner)?;
        changes.push(format!("owner={owner}"));
    }

    if let Some(notes) = body.notes.as_deref() {
        store.set_incident_note_scoped(&scope, &incident_id, notes)?;
        changes.push("notes".to_string());
    }

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "incident.patch",
        "incident",
        &incident_id,
        &serde_json::json!({ "changes": changes }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "incident_id": incident_id,
            "changes": changes
        }),
    }))
}

pub async fn ack_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    set_incident_state(state, auth, incident_id, "acknowledged", "incident.ack").await
}

pub async fn resolve_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    set_incident_state(state, auth, incident_id, "resolved", "incident.resolve").await
}

pub async fn assign_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
    Json(body): Json<AssignIncidentRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.assign_incident_owner_scoped(&scope, &incident_id, &body.owner)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "incident.assign",
        "incident",
        &incident_id,
        &serde_json::json!({ "owner": body.owner }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "incident_id": incident_id,
            "owner": body.owner
        }),
    }))
}

pub async fn note_incident(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
    Json(body): Json<NoteIncidentRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.set_incident_note_scoped(&scope, &incident_id, &body.notes)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "incident.note",
        "incident",
        &incident_id,
        &serde_json::json!({ "notes": body.notes }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "incident_id": incident_id
        }),
    }))
}

async fn set_incident_state(
    state: Arc<AppState>,
    auth: AuthContext,
    incident_id: String,
    incident_state: &'static str,
    audit_action: &'static str,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.set_incident_state_scoped(&scope, &incident_id, incident_state)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        audit_action,
        "incident",
        &incident_id,
        &serde_json::json!({ "state": incident_state }),
    )?;

    Ok(Json(ApiEnvelope {
        data: serde_json::json!({
            "incident_id": incident_id,
            "state": incident_state
        }),
    }))
}
