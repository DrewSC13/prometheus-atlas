use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{PaginationMeta, SnapshotsResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct SnapshotParams {
    pub limit: Option<usize>,
}

pub async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
    Query(params): Query<SnapshotParams>,
) -> ApiResult<Json<SnapshotsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_snapshots_scoped(&scope, &target)?;
    items.truncate(limit);

    Ok(Json(SnapshotsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
