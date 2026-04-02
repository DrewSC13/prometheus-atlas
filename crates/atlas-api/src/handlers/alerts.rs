use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};

use atlas_core::{AlertChannelKind, AlertDeliveryStatus};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{AlertDeliveriesResponse, PaginationMeta},
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct AlertParams {
    pub channel: Option<AlertChannelKind>,
    pub status: Option<AlertDeliveryStatus>,
    pub event_type: Option<String>,
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
    let mut items = store.list_alert_deliveries_scoped(&scope, limit)?;

    if let Some(channel) = params.channel {
        items.retain(|item| item.channel.eq_ignore_ascii_case(channel.as_str()));
    }

    if let Some(status) = params.status {
        items.retain(|item| item.status.eq_ignore_ascii_case(status.as_str()));
    }

    if let Some(event_type) = params.event_type.as_deref() {
        items.retain(|item| item.event_type.eq_ignore_ascii_case(event_type));
    }

    items.truncate(limit);

    Ok(Json(AlertDeliveriesResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
