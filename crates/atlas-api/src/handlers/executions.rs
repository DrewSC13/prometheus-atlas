use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{JobExecutionsResponse, PaginationMeta},
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct ExecutionParams {
    pub limit: Option<usize>,
}

pub async fn list_job_executions(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(job_id): Path<String>,
    Query(params): Query<ExecutionParams>,
) -> ApiResult<Json<JobExecutionsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, params.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let items = store.list_job_executions_scoped(&scope, Some(&job_id), limit)?;

    Ok(Json(JobExecutionsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
