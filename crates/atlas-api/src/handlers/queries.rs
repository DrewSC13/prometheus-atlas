use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, PagedEnvelope, PaginationMeta},
    state::AppState,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveQueryRequest {
    pub name: String,
    pub expression: String,
}

pub async fn list_queries(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> ApiResult<Json<PagedEnvelope<atlas_store::StoredSavedQuery>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let items = store.list_saved_queries_scoped(&scope)?;

    Ok(Json(PagedEnvelope {
        data: items.clone(),
        pagination: PaginationMeta {
            limit: items.len(),
            returned: items.len(),
        },
    }))
}

pub async fn get_query(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiEnvelope<atlas_store::StoredSavedQuery>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let item = store
        .load_saved_query_scoped(&scope, &name)?
        .ok_or_else(|| ApiError::not_found(format!("query no encontrada: {name}")))?;

    Ok(Json(ApiEnvelope { data: item }))
}

pub async fn save_query(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(payload): Json<SaveQueryRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_store::StoredSavedQuery>>> {
    auth.require_write()?;

    atlas_query::parse_query(&payload.expression, 25)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.save_saved_query_scoped(&scope, &payload.name, &payload.expression)?;

    let item = store
        .load_saved_query_scoped(&scope, &payload.name)?
        .ok_or_else(|| ApiError::internal("query guardada pero no recuperable"))?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "query.save",
        "saved_query",
        &payload.name,
        &serde_json::json!({
            "expression": payload.expression
        }),
    )?;

    Ok(Json(ApiEnvelope { data: item }))
}

pub async fn run_query(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, target)): Path<(String, String)>,
) -> ApiResult<Json<ApiEnvelope<atlas_query::QueryResult>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let saved = store
        .load_saved_query_scoped(&scope, &name)?
        .ok_or_else(|| ApiError::not_found(format!("query no encontrada: {name}")))?;

    let graph = store
        .load_latest_graph_scoped(&scope, &target)?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "graph no encontrado para {target} en este tenant/project"
            ))
        })?;

    let request =
        atlas_query::parse_query(&saved.expression, state.config.pagination.default_limit)
            .map_err(|err| ApiError::bad_request(err.to_string()))?;

    let result = atlas_query::execute_query(&graph, &request)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "query.run_saved",
        "saved_query",
        &name,
        &serde_json::json!({
            "target": target,
            "expression": saved.expression,
            "matches": result.summary.total_matches
        }),
    )?;

    Ok(Json(ApiEnvelope { data: result }))
}
