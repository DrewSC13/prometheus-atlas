use crate::auth::{scope_from_auth, AuthContext};
use crate::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, String)> {
    let scope = scope_from_auth(&auth);
    let store = state.store.lock().map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "store lock poisoned".to_string(),
        )
    })?;

    let items = store
        .list_snapshots_scoped(&scope, &target)
        .map_err(internal_error)?;

    Ok(Json(json!({
        "target": target,
        "items": items,
    })))
}

fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        err.to_string(),
    )
}
