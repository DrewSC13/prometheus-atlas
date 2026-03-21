use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::json;

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, ScanRequest},
    state::AppState,
};

pub async fn scan(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<ScanRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_core::ScanResult>>> {
    auth.require_write()?;
    let result = atlas_discovery::scan_target(&body.target).await?;

    let scope = scope_from_auth(&auth);
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "scan.execute",
        "target",
        &body.target,
        &json!({
            "resolved_ips": result.resolved_ips.len(),
            "subdomains": result.subdomains.len(),
            "services": result.services.len()
        }),
    )?;

    Ok(Json(ApiEnvelope { data: result }))
}
