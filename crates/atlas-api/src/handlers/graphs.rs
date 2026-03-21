use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::ApiEnvelope,
    state::AppState,
};

pub async fn get_graph(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(target): Path<String>,
) -> ApiResult<Json<ApiEnvelope<atlas_graph::ExposureGraph>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let graph = store
        .load_latest_graph_scoped(&scope, &target)?
        .ok_or_else(|| ApiError::not_found(format!("graph no encontrado para {target}")))?;

    Ok(Json(ApiEnvelope { data: graph }))
}
