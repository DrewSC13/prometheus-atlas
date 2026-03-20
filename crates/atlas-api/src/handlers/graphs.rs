use crate::auth::AuthContext;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use std::sync::Arc;

type ApiResult<T> = Result<T, (StatusCode, String)>;

pub async fn get_graph(
    State(state): State<Arc<AppState>>,
    _auth: AuthContext,
    Path(target): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
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

    Ok(Json(json!({
        "ok": true,
        "graph": graph
    })))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
