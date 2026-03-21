use crate::{
    auth::{scope_from_auth, AuthContext},
    state::AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct TelemetryParams {
    pub limit: Option<usize>,
}

pub async fn list_telemetry(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<TelemetryParams>,
) -> Result<Json<Value>, (axum::http::StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let limit = params.limit.unwrap_or(50);

    let store = state.store.lock().map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store
        .list_telemetry_scoped(&scope, limit)
        .map_err(internal_error)?;

    Ok(Json(json!({
        "limit": limit,
        "items": items,
    })))
}

pub async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<TelemetryParams>,
) -> Result<Json<Value>, (axum::http::StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let limit = params.limit.unwrap_or(50);

    let store = state.store.lock().map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store
        .list_audit_events_scoped(&scope, limit)
        .map_err(internal_error)?;

    Ok(Json(json!({
        "limit": limit,
        "items": items,
    })))
}

fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        err.to_string(),
    )
}
