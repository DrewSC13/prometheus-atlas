use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::{default_limit, issue_token, scope_from_auth, validate_bootstrap_token, AuthContext},
    error::{ApiError, ApiResult},
    models::{ApiEnvelope, AuditResponse, BootstrapTokenRequest, PaginationMeta, TokenResponse},
    state::AppState,
};

pub async fn issue_bootstrap_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BootstrapTokenRequest>,
) -> ApiResult<Json<ApiEnvelope<TokenResponse>>> {
    let bootstrap = headers
        .get("x-atlas-bootstrap-token")
        .ok_or_else(|| ApiError::forbidden("x-atlas-bootstrap-token requerido"))?
        .to_str()
        .map_err(|_| ApiError::forbidden("bootstrap token inválido"))?;

    validate_bootstrap_token(&state, bootstrap)?;
    let token = issue_token(
        &state,
        &body.subject,
        &body.tenant_id,
        &body.project_id,
        &body.role,
    )?;

    Ok(Json(ApiEnvelope {
        data: TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.auth.jwt_expiration_seconds,
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResponse>> {
    auth.require_admin()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, query.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let items = store.list_audit_events_scoped(&scope, limit)?;

    Ok(Json(AuditResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

#[allow(dead_code)]
fn _audit_metadata(auth: &AuthContext) -> serde_json::Value {
    json!({
        "actor": auth.subject,
        "roles": auth.roles,
        "tenant_id": auth.tenant_id,
        "project_id": auth.project_id
    })
}
