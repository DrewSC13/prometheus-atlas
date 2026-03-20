use crate::error::ApiError;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct ExecuteQueryRequest {
    pub target: String,
    pub expression: String,
    pub limit: Option<usize>,
}

pub async fn execute_graph_query(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ExecuteQueryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    if request.expression.trim().is_empty() {
        return Err(ApiError::bad_request("expression no puede estar vacía"));
    }

    let started = Instant::now();
    let store = state.open_store()?;
    store.initialize()?;

    let graph = store.load_latest_graph(&request.target)?.ok_or_else(|| {
        ApiError::not_found(format!(
            "no existe un grafo persistido para {}; ejecuta primero `atlas graph {} --persist` o persistencia equivalente",
            request.target, request.target
        ))
    })?;

    let parsed = atlas_query::parse_query(&request.expression, request.limit.unwrap_or(25))
        .map_err(ApiError::from)?;
    let result = atlas_query::execute_query(&graph, &parsed).map_err(ApiError::from)?;

    state.record_telemetry(
        "api-query",
        Some(&request.target),
        started.elapsed().as_millis(),
        &json!({
            "expression": request.expression,
            "matches": result.summary.total_matches
        }),
    )?;

    Ok(Json(json!({
        "target": request.target,
        "result": result
    })))
}
