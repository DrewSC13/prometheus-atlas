use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{AlertDeliveriesResponse, PaginationMeta},
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct AlertParams {
    pub limit: Option<usize>,
}

pub async fn list_alert_deliveries(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<AlertParams>,
) -> ApiResult<Json<AlertDeliveriesResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let items = store.list_alert_deliveries_scoped(&scope, limit)?;

    Ok(Json(AlertDeliveriesResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
