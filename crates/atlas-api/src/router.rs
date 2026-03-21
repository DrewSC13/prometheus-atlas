use crate::{
    handlers::{
        admin, drift, findings, graphs, health, jobs, queries, query, reports, scan, snapshots,
        telemetry,
    },
    state::AppState,
};
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready))
        .route("/version", get(health::version))
        .route(
            "/v1/admin/bootstrap-token",
            post(admin::issue_bootstrap_token),
        )
        .route("/v1/admin/audit", get(admin::list_audit))
        .route("/v1/scan", post(scan::scan))
        .route("/v1/drift", post(drift::run_drift))
        .route("/v1/query", post(query::run_query))
        .route("/v1/snapshots/:target", get(snapshots::list_snapshots))
        .route("/v1/graphs/:target", get(graphs::get_graph))
        .route("/v1/reports/:target", get(reports::get_report))
        .route("/v1/findings/:target", get(findings::list_findings))
        .route(
            "/v1/findings/:target/current",
            get(findings::list_current_findings),
        )
        .route("/v1/findings/:finding_id/ack", post(findings::ack_finding))
        .route(
            "/v1/findings/:finding_id/resolve",
            post(findings::resolve_finding),
        )
        .route(
            "/v1/findings/:finding_id/accept",
            post(findings::accept_finding),
        )
        .route(
            "/v1/findings/:finding_id/assign",
            post(findings::assign_finding),
        )
        .route(
            "/v1/findings/:finding_id/note",
            post(findings::note_finding),
        )
        .route("/v1/jobs", get(jobs::list_jobs).post(jobs::create_job))
        .route("/v1/jobs/:job_id", get(jobs::get_job))
        .route("/v1/jobs/:job_id/enable", post(jobs::enable_job))
        .route("/v1/jobs/:job_id/disable", post(jobs::disable_job))
        .route("/v1/jobs/:job_id/run", post(jobs::run_job))
        .route("/v1/jobs/:job_id/delete", post(jobs::delete_job))
        .route(
            "/v1/queries",
            get(queries::list_queries).post(queries::save_query),
        )
        .route("/v1/queries/:name", get(queries::get_query))
        .route("/v1/queries/:name/run/:target", get(queries::run_query))
        .route("/v1/telemetry", get(telemetry::list_telemetry))
        .route("/v1/audit", get(telemetry::list_audit_events))
        .with_state(state)
}
