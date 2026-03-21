use std::{path::Path, sync::Arc};

use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::ApiEnvelope,
    state::AppState,
};

pub async fn get_report(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    AxumPath(target): AxumPath<String>,
) -> ApiResult<Json<ApiEnvelope<atlas_report::ExecutiveReport>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let snapshots_meta = {
        let store = state
            .store
            .lock()
            .map_err(|_| ApiError::internal("store lock"))?;
        store.list_snapshots_scoped(&scope, &target)?
    };

    if snapshots_meta.is_empty() {
        return Err(ApiError::not_found(format!(
            "no hay snapshots persistidos para {target}"
        )));
    }

    let mut snapshots = Vec::new();
    for item in &snapshots_meta {
        snapshots.push(atlas_snapshot::load_snapshot(Path::new(&item.path))?);
    }
    snapshots.sort_by_key(|s| s.timestamp);

    let timeline = if snapshots.len() >= 2 {
        Some(atlas_drift::build_timeline_report(
            &target, &snapshots, None,
        )?)
    } else {
        None
    };

    let episodes = if let Some(timeline) = &timeline {
        let mut clusters_by_transition = Vec::new();
        for transition in &timeline.transitions {
            clusters_by_transition.push(atlas_correlation::correlate_report(&transition.report)?);
        }

        Some(atlas_episodes::build_episodes_for_timeline(
            &target,
            timeline,
            &clusters_by_transition,
        )?)
    } else {
        None
    };

    let graph = atlas_graph::build_full_graph(
        &target,
        snapshots.last(),
        timeline.as_ref(),
        episodes.as_ref(),
    );

    let report = atlas_report::build_executive_report(
        &target,
        &snapshots,
        timeline.as_ref(),
        episodes.as_ref(),
        &graph,
        false,
    );

    Ok(Json(ApiEnvelope { data: report }))
}
