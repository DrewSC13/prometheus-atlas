use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{
        ApiEnvelope, IncidentDetailResponse, IncidentOperationsIntelligenceResponse,
        IncidentPatchRequest, IncidentsResponse, PaginationMeta,
    },
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct IncidentParams {
    pub state: Option<String>,
    pub owner: Option<String>,
    pub severity: Option<String>,
    pub source_kind: Option<String>,
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

    let fetch_limit = limit.saturating_mul(5).max(limit).min(1000);

    let mut items = store.list_incidents_scoped(
        &scope,
        params.state.as_deref(),
        params.owner.as_deref(),
        fetch_limit,
    )?;

    if let Some(severity) = params.severity.as_deref() {
        items.retain(|item| item.severity.eq_ignore_ascii_case(severity));
    }

    if let Some(source_kind) = params.source_kind.as_deref() {
        items.retain(|item| item.source_kind.eq_ignore_ascii_case(source_kind));
    }

    items.truncate(limit);

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

pub async fn get_incident_detail(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(incident_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<IncidentDetailResponse>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let incident = store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

    let related_findings = match incident.source_kind.as_str() {
        "finding" => {
            let all = store.list_current_findings_operational_scoped(
                &scope,
                &incident.target,
                None,
                None,
                None,
                None,
            )?;
            all.into_iter()
                .filter(|item| {
                    item.finding_id == incident.source_id || item.resource == incident.resource
                })
                .collect::<Vec<_>>()
        }
        _ => store
            .list_current_findings_operational_scoped(
                &scope,
                &incident.target,
                None,
                None,
                None,
                None,
            )?
            .into_iter()
            .filter(|item| item.resource == incident.resource || item.target == incident.target)
            .take(25)
            .collect::<Vec<_>>(),
    };

    let related_owners = store
        .list_asset_owners_scoped(&scope, Some(&incident.resource))?
        .into_iter()
        .collect::<Vec<_>>();

    let related_executions = store
        .list_job_executions_scoped(&scope, None, 50)?
        .into_iter()
        .filter(|execution| {
            execution
                .result_json
                .as_deref()
                .map(|body| body.contains(&incident.target) || body.contains(&incident.incident_id))
                .unwrap_or(false)
        })
        .take(10)
        .collect::<Vec<_>>();

    Ok(Json(ApiEnvelope {
        data: IncidentDetailResponse {
            incident,
            related_findings,
            related_owners,
            related_executions,
        },
    }))
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

    store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

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

    store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

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

    store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

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

pub async fn get_incident_operations_intelligence(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
) -> ApiResult<Json<IncidentOperationsIntelligenceResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let findings =
        store.list_current_findings_operational_scoped(&scope, &target, None, None, None, None)?;
    let episodes = store.list_episodes_scoped(&scope, &target)?;
    let owners = store.list_asset_owners_scoped(&scope, None)?;
    let graph = store.load_latest_graph_scoped(&scope, &target)?;

    let report = atlas_risk::build_incident_operations_intelligence(
        &target,
        &findings,
        &episodes,
        &owners,
        graph.as_ref(),
    );

    Ok(Json(ApiEnvelope { data: report }))
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

    store
        .get_incident_scoped(&scope, &incident_id)?
        .ok_or_else(|| ApiError::not_found("incident no encontrado"))?;

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
