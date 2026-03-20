use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::json;

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, QueryRequestBody},
    state::AppState,
};

pub async fn run_query(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<QueryRequestBody>,
) -> ApiResult<Json<ApiEnvelope<atlas_query::QueryResult>>> {
    let scope = scope_from_auth(&auth);
    let limit = body
        .limit
        .unwrap_or(state.config.pagination.default_limit)
        .min(state.config.pagination.max_limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let graph = store.load_latest_graph_scoped(&scope, &body.target)?.ok_or_else(|| {
        ApiError::not_found(format!(
            "no existe un grafo persistido para {} en este tenant/project",
            body.target
        ))
    })?;

    let query = atlas_query::parse_query(&body.expression, limit)?;
    let result = atlas_query::execute_query(&graph, &query)?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "query.run",
        "graph",
        Some(&body.target),
        &json!({
            "expression": body.expression,
            "matches": result.summary.total_matches
        }),
    )?;

    Ok(Json(ApiEnvelope { data: result }))
}