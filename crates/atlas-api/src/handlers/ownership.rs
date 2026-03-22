use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, AssetOwnerUpsertRequest, AssetOwnersResponse, PaginationMeta},
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct OwnershipParams {
    pub resource: Option<String>,
    pub limit: Option<usize>,
}

pub async fn upsert_asset_owner(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<AssetOwnerUpsertRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_store::StoredAssetOwner>>> {
    auth.require_write()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let item = store.upsert_asset_owner_scoped(
        &scope,
        &body.resource,
        &body.owner,
        body.team.as_deref(),
        body.business_service.as_deref(),
        body.criticality.as_deref(),
    )?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "ownership.asset.upsert",
        "asset_owner",
        &item.resource,
        &serde_json::json!({
            "owner": item.owner,
            "team": item.team,
            "business_service": item.business_service,
            "criticality": item.criticality
        }),
    )?;

    Ok(Json(ApiEnvelope { data: item }))
}

pub async fn list_asset_owners(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(params): Query<OwnershipParams>,
) -> ApiResult<Json<AssetOwnersResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let mut items = store.list_asset_owners_scoped(&scope, params.resource.as_deref())?;
    items.truncate(limit);

    Ok(Json(AssetOwnersResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
