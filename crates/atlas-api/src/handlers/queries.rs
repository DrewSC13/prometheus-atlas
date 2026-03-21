use crate::{auth::AuthContext, state::AppState};
use atlas_query::{execute_query, parse_query};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

type ApiResult<T> = Result<T, (StatusCode, String)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveQueryRequest {
    pub name: String,
    pub expression: String,
}

pub async fn list_queries(
    State(state): State<Arc<AppState>>,
    _auth: AuthContext,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store.list_saved_queries().map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "items": items
    })))
}

pub async fn get_query(
    State(state): State<Arc<AppState>>,
    _auth: AuthContext,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let item = store
        .load_saved_query(&name)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("query no encontrada: {name}"),
            )
        })?;

    Ok(Json(json!({
        "ok": true,
        "query": item
    })))
}

pub async fn save_query(
    State(state): State<Arc<AppState>>,
    _auth: AuthContext,
    Json(payload): Json<SaveQueryRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    parse_query(&payload.expression, 25)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    store
        .save_saved_query(&payload.name, &payload.expression)
        .map_err(internal_error)?;

    let item = store
        .load_saved_query(&payload.name)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "query guardada pero no recuperable".to_string(),
            )
        })?;

    Ok(Json(json!({
        "ok": true,
        "query": item
    })))
}

pub async fn run_query(
    State(state): State<Arc<AppState>>,
    _auth: AuthContext,
    Path((name, target)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let saved = store
        .load_saved_query(&name)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("query no encontrada: {name}"),
            )
        })?;

    let graph = store
        .load_latest_graph(&target)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("graph no encontrado para {target}"),
            )
        })?;

    let request = parse_query(&saved.expression, 25)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let result = execute_query(&graph, &request)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "saved_query": saved,
        "result": result
    })))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
