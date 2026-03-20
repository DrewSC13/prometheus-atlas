use crate::handlers::{drift, findings, jobs, query, scan, snapshot};
use crate::state::AppState;
use axum::{
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan::scan_target))
        .route(
            "/snapshot",
            get(snapshot::list_snapshots).post(snapshot::create_snapshot),
        )
        .route(
            "/drift",
            get(drift::list_drift_history).post(drift::run_drift),
        )
        .route("/findings", get(findings::list_findings))
        .route("/findings/:finding_id/ack", post(findings::ack_finding))
        .route(
            "/findings/:finding_id/resolve",
            post(findings::resolve_finding),
        )
        .route(
            "/findings/:finding_id/accept",
            post(findings::accept_finding),
        )
        .route(
            "/findings/:finding_id/assign",
            post(findings::assign_finding),
        )
        .route("/findings/:finding_id/note", post(findings::note_finding))
        .route("/query", post(query::execute_graph_query))
        .route("/jobs", get(jobs::list_jobs).post(jobs::create_job))
        .route("/jobs/history", get(jobs::job_history))
        .route("/jobs/:job_id/run", post(jobs::run_job))
        .route("/jobs/:job_id/enable", post(jobs::enable_job))
        .route("/jobs/:job_id/disable", post(jobs::disable_job))
        .route("/jobs/:job_id", delete(jobs::delete_job))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "atlas-api"
    }))
}
