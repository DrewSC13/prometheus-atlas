use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct CreateSnapshotRequest {
    pub target: String,
    pub persist: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ListSnapshotsRequest {
    pub target: String,
}

pub async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateSnapshotRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let started = Instant::now();
    let scan = atlas_discovery::scan_target(&request.target).await?;
    let snapshot = atlas_snapshot::Snapshot::new(scan);
    let path = atlas_snapshot::save_snapshot(&snapshot, state.snapshot_dir())?;

    let persisted = state.should_persist(request.persist);
    if persisted {
        let store = state.open_store()?;
        store.initialize()?;
        store.register_snapshot(&path, &snapshot)?;
    }

    state.record_telemetry(
        "api-snapshot",
        Some(&snapshot.target),
        started.elapsed().as_millis(),
        &json!({
            "path": path.display().to_string(),
            "persisted": persisted
        }),
    )?;

    Ok(Json(json!({
        "target": snapshot.target,
        "snapshot": snapshot,
        "path": path.display().to_string(),
        "persisted": persisted
    })))
}

pub async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    Query(request): Query<ListSnapshotsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let store = state.open_store()?;
    store.initialize()?;
    let snapshots = store.list_snapshots(&request.target)?;

    Ok(Json(json!({
        "target": request.target,
        "snapshots": snapshots
    })))
}
