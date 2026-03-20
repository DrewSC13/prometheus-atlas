use axum::Json;

use crate::models::{ApiEnvelope, HealthResponse, ReadyResponse, VersionResponse};

pub async fn health() -> Json<ApiEnvelope<HealthResponse>> {
    Json(ApiEnvelope {
        data: HealthResponse {
            status: "ok".to_string(),
        },
    })
}

pub async fn ready() -> Json<ApiEnvelope<ReadyResponse>> {
    Json(ApiEnvelope {
        data: ReadyResponse {
            status: "ready".to_string(),
        },
    })
}

pub async fn version() -> Json<ApiEnvelope<VersionResponse>> {
    Json(ApiEnvelope {
        data: VersionResponse {
            name: "prometheus-atlas".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "v1".to_string(),
        },
    })
}
