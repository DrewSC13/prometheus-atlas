use crate::error::ApiError;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: String,
}

pub async fn scan_target(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.target.trim().is_empty() {
        return Err(ApiError::bad_request("target no puede estar vacío"));
    }

    let started = Instant::now();
    let result = atlas_discovery::scan_target(&request.target).await?;

    state.record_telemetry(
        "api-scan",
        Some(&result.target),
        started.elapsed().as_millis(),
        &json!({
            "resolved_ips": result.resolved_ips.len(),
            "subdomains": result.subdomains.len(),
            "services": result.services.len()
        }),
    )?;

    Ok(Json(json!({
        "target": result.target,
        "result": result
    })))
}
