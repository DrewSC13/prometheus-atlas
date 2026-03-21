use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{AuditResponse, PaginationMeta, TelemetryResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct TelemetryParams {
    pub limit: Option<usize>,
}

pub async fn list_telemetry(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<TelemetryParams>,
) -> ApiResult<Json<TelemetryResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let items = store.list_telemetry_scoped(&scope, limit)?;

    Ok(Json(TelemetryResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<TelemetryParams>,
) -> ApiResult<Json<AuditResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let items = store.list_audit_events_scoped(&scope, limit)?;

    Ok(Json(AuditResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
