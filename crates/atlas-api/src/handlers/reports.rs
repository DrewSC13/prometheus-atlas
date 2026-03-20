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

pub async fn get_report(
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

    let snapshots = store.list_snapshots(&target).map_err(internal_error)?;
    let history = store.list_history(&target).map_err(internal_error)?;
    let findings = store
        .list_current_findings_operational(&target, None, None, None, None)
        .map_err(internal_error)?;
    let episodes = store.list_episodes(&target).map_err(internal_error)?;
    let graphs = store.list_graphs(&target).map_err(internal_error)?;

    Ok(Json(json!({
        "ok": true,
        "target": target,
        "summary": {
            "snapshots": snapshots.len(),
            "history_runs": history.len(),
            "current_findings": findings.len(),
            "episodes": episodes.len(),
            "graphs": graphs.len()
        },
        "latest_snapshot": snapshots.first(),
        "latest_run": history.first(),
        "latest_graph": graphs.first(),
        "current_findings": findings,
        "episodes": episodes
    })))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
