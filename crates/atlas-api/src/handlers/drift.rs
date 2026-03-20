use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct RunDriftRequest {
    pub target: Option<String>,
    pub older_snapshot_path: Option<String>,
    pub newer_snapshot_path: Option<String>,
    pub policy_path: Option<String>,
    pub persist: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DriftHistoryRequest {
    pub target: String,
}

pub async fn run_drift(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RunDriftRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let started = Instant::now();

    let (older_path, newer_path, target) = resolve_snapshot_pair(&state, &request)?;
    let older = atlas_snapshot::load_snapshot(&older_path)?;
    let newer = atlas_snapshot::load_snapshot(&newer_path)?;
    let diff = atlas_diff::diff_snapshots(&older, &newer);

    let policy = match request.policy_path.as_deref() {
        Some(path) => {
            let loaded = atlas_drift::DriftPolicy::load_from_path(Path::new(path))?;
            loaded.validate()?;
            Some(loaded)
        }
        None => None,
    };

    let report = atlas_drift::analyze_diff_with_policy(&diff, policy.as_ref());
    let persisted = state.should_persist(request.persist);

    if persisted {
        let store = state.open_store()?;
        store.initialize()?;
        store.register_drift_report(
            &target,
            &older_path,
            &newer_path,
            request.policy_path.as_deref().map(Path::new),
            &report,
        )?;
    }

    state.record_telemetry(
        "api-drift",
        Some(&target),
        started.elapsed().as_millis(),
        &json!({
            "older_snapshot_path": older_path.display().to_string(),
            "newer_snapshot_path": newer_path.display().to_string(),
            "persisted": persisted,
            "findings": report.findings.len(),
            "suppressed_findings": report.suppressed_findings.len(),
            "score": report.summary.total_score
        }),
    )?;

    Ok(Json(json!({
        "target": target,
        "older_snapshot_path": older_path.display().to_string(),
        "newer_snapshot_path": newer_path.display().to_string(),
        "persisted": persisted,
        "report": report
    })))
}

pub async fn list_drift_history(
    State(state): State<Arc<AppState>>,
    Query(request): Query<DriftHistoryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let store = state.open_store()?;
    store.initialize()?;
    let history = store.list_history(&request.target)?;

    Ok(Json(json!({
        "target": request.target,
        "history": history
    })))
}

fn resolve_snapshot_pair(
    state: &AppState,
    request: &RunDriftRequest,
) -> Result<(PathBuf, PathBuf, String), ApiError> {
    match (&request.older_snapshot_path, &request.newer_snapshot_path) {
        (Some(older), Some(newer)) => {
            let older_path = PathBuf::from(older);
            let newer_path = PathBuf::from(newer);

            let older_snapshot = atlas_snapshot::load_snapshot(&older_path)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer_path)?;

            if older_snapshot.target != newer_snapshot.target {
                return Err(ApiError::bad_request(
                    "los snapshots no pertenecen al mismo target",
                ));
            }

            Ok((older_path, newer_path, newer_snapshot.target))
        }
        (None, None) => {
            let target = request.target.as_deref().ok_or_else(|| {
                ApiError::bad_request("target es requerido si no envías snapshot paths")
            })?;

            let paths = atlas_snapshot::list_snapshots_for_target(state.snapshot_dir(), target)?;
            if paths.len() < 2 {
                return Err(ApiError::bad_request(
                    "se requieren al menos 2 snapshots para el target",
                ));
            }

            let older_path = paths[paths.len() - 2].clone();
            let newer_path = paths[paths.len() - 1].clone();
            Ok((older_path, newer_path, target.to_string()))
        }
        _ => Err(ApiError::bad_request(
            "debes enviar ambos campos older_snapshot_path y newer_snapshot_path, o solo target",
        )),
    }
}
