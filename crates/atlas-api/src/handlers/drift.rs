use std::{path::Path, sync::Arc};

use axum::{extract::State, Json};
use serde_json::json;

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, DriftRequest},
    state::AppState,
};

pub async fn run_drift(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<DriftRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_drift::DriftReport>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let (older_path, newer_path) = if let (Some(older), Some(newer)) = (
        body.older_snapshot_path.clone(),
        body.newer_snapshot_path.clone(),
    ) {
        (older, newer)
    } else {
        let store = state
            .store
            .lock()
            .map_err(|_| ApiError::internal("store lock"))?;
        let snapshots = store.list_snapshots_scoped(&scope, &body.target)?;
        if snapshots.len() < 2 {
            return Err(ApiError::bad_request(
                "se requieren al menos 2 snapshots persistidos o paths explícitos",
            ));
        }
        (snapshots[1].path.clone(), snapshots[0].path.clone())
    };

    let older_snapshot = atlas_snapshot::load_snapshot(Path::new(&older_path))?;
    let newer_snapshot = atlas_snapshot::load_snapshot(Path::new(&newer_path))?;
    let diff = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

    let policy = match body.policy_path.as_deref() {
        Some(path) => {
            let loaded = atlas_drift::DriftPolicy::load_from_path(Path::new(path))?;
            loaded.validate()?;
            Some(loaded)
        }
        None => None,
    };

    let report = atlas_drift::analyze_diff_with_policy(&diff, policy.as_ref());

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    if body.persist.unwrap_or(true) {
        store.register_drift_report_scoped(
            &scope,
            &diff.target,
            Path::new(&older_path),
            Path::new(&newer_path),
            body.policy_path.as_deref().map(Path::new),
            &report,
        )?;
    }

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "drift.run",
        "target",
        &body.target,
        &json!({
            "older_snapshot_path": older_path,
            "newer_snapshot_path": newer_path,
            "findings": report.findings.len(),
            "suppressed": report.suppressed_findings.len(),
            "score": report.summary.total_score
        }),
    )?;

    Ok(Json(ApiEnvelope { data: report }))
}
