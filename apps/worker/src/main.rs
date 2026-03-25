use anyhow::{bail, Result};
use atlas_config::AppConfig;
use atlas_plugins::default_registry_for;
use atlas_risk::{
    build_incident_operations_intelligence, build_ownership_intelligence, IncidentCandidate,
};
use atlas_snapshot::Snapshot;
use atlas_store::{
    AlertDeliveryRequest, AtlasStore, StorageScope, StoredAlertDelivery, StoredIncident,
};
use clap::Parser;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "atlas-worker")]
#[command(about = "Prometheus Atlas - Local queue worker")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value_t = 2)]
    poll_seconds: u64,

    #[arg(long, default_value_t = 60)]
    lease_seconds: u64,

    #[arg(long)]
    once: bool,

    #[arg(long)]
    worker_id: Option<String>,
}

#[derive(Debug, Clone)]
struct LoadedSnapshotInput {
    path: PathBuf,
    snapshot: Snapshot,
}

struct AnalysisBundle {
    snapshot_inputs: Vec<LoadedSnapshotInput>,
    timeline: Option<atlas_drift::TimelineReport>,
    episodes: Option<atlas_episodes::EpisodeCollection>,
    graph: atlas_graph::ExposureGraph,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = if let Some(path) = cli.config.as_deref() {
        AppConfig::load_from_path(path)?
    } else {
        AppConfig::load_from_default_locations()?
    };

    config.validate()?;
    init_tracing(&config)?;

    let worker_id = cli
        .worker_id
        .unwrap_or_else(|| format!("worker-{}", Uuid::new_v4()));

    let store = AtlasStore::open(Path::new(&config.storage.path))?;
    store.initialize()?;

    info!("atlas-worker iniciado id={}", worker_id);

    loop {
        let processed =
            process_next_queue_item(&config, &store, &worker_id, cli.lease_seconds).await?;

        if cli.once {
            break;
        }

        if !processed {
            sleep(Duration::from_secs(cli.poll_seconds)).await;
        }
    }

    Ok(())
}

async fn process_next_queue_item(
    config: &AppConfig,
    store: &AtlasStore,
    worker_id: &str,
    lease_seconds: u64,
) -> Result<bool> {
    let Some(item) = store.claim_next_job_queue_item(worker_id, lease_seconds)? else {
        return Ok(false);
    };

    let scope = StorageScope::new(item.tenant_id.clone(), item.project_id.clone());

    store.mark_job_queue_running(&item.queue_id)?;
    store.record_audit_event_scoped(
        &scope,
        worker_id,
        "job.worker.start",
        "job_queue",
        &item.queue_id,
        &json!({
            "job_id": item.job_id,
            "target": item.target,
            "trigger": item.trigger
        }),
    )?;

    match execute_queue_item(config, store, &scope, &item).await {
        Ok(result) => {
            store.touch_job_run_scoped(&scope, &item.job_id)?;
            store.mark_job_queue_succeeded(&item.queue_id, &result)?;
            store.record_audit_event_scoped(
                &scope,
                worker_id,
                "job.worker.succeeded",
                "job_queue",
                &item.queue_id,
                &result,
            )?;
            info!(
                "queue item ejecutado con éxito queue_id={} job_id={} target={}",
                item.queue_id, item.job_id, item.target
            );
        }
        Err(err) => {
            warn!(
                "queue item falló queue_id={} job_id={} error={}",
                item.queue_id, item.job_id, err
            );
            store.mark_job_queue_failed(&item.queue_id, &err.to_string(), Some(30))?;
            store.record_audit_event_scoped(
                &scope,
                worker_id,
                "job.worker.failed",
                "job_queue",
                &item.queue_id,
                &json!({
                    "job_id": item.job_id,
                    "target": item.target,
                    "error": err.to_string()
                }),
            )?;
        }
    }

    Ok(true)
}

async fn execute_queue_item(
    config: &AppConfig,
    store: &AtlasStore,
    scope: &StorageScope,
    item: &atlas_queue::JobQueueItem,
) -> Result<serde_json::Value> {
    config.profile(&item.profile)?;

    let started = std::time::Instant::now();
    let result = atlas_discovery::scan_target(&item.target).await?;
    let snapshot = atlas_snapshot::Snapshot::new(result);
    let snapshot_dir = PathBuf::from(".snapshots");
    let snapshot_path = atlas_snapshot::save_snapshot(&snapshot, &snapshot_dir)?;

    let should_persist = item.persist_artifacts || config.drift.persist_by_default;
    let mut transitions = 0usize;
    let mut episodes = 0usize;
    let mut graph_nodes = 0usize;
    let mut graph_edges = 0usize;
    let mut incidents_created = 0usize;
    let mut incidents_updated = 0usize;
    let mut incidents_resolved = 0usize;
    let mut alerts_recorded = 0usize;
    let mut ownership_gaps = 0usize;

    if should_persist {
        store.register_snapshot_scoped(scope, &snapshot_path, &snapshot)?;

        let bundle = build_analysis_bundle(
            config,
            &item.target,
            &snapshot_dir,
            item.policy_path.as_deref().map(Path::new),
        )?;

        if let Some(timeline) = &bundle.timeline {
            transitions = timeline.transition_count;

            for (pair, transition) in bundle
                .snapshot_inputs
                .windows(2)
                .zip(timeline.transitions.iter())
            {
                let older = &pair[0];
                let newer = &pair[1];

                store.register_drift_report_scoped(
                    scope,
                    &item.target,
                    &older.path,
                    &newer.path,
                    item.policy_path.as_deref().map(Path::new),
                    &transition.report,
                )?;
            }
        }

        if let Some(collection) = &bundle.episodes {
            episodes = collection.episode_count;
            store.store_episodes_scoped(scope, &item.target, &collection.episodes)?;
        }

        graph_nodes = bundle.graph.node_count;
        graph_edges = bundle.graph.edge_count;
        store.store_graph_scoped(scope, &item.target, &bundle.graph)?;

        let reconciliation = reconcile_incidents_from_current_state(
            config,
            store,
            scope,
            &item.target,
            Some(&bundle.graph),
        )
        .await?;

        incidents_created = reconciliation.created;
        incidents_updated = reconciliation.updated;
        incidents_resolved = reconciliation.resolved;
        alerts_recorded = reconciliation.alerts_recorded;
        ownership_gaps = reconciliation.ownership_gaps;
    }

    let duration_ms = started.elapsed().as_millis();
    store.record_telemetry_scoped(
        scope,
        "worker-job-run",
        Some(&item.target),
        duration_ms,
        &json!({
            "job_id": item.job_id,
            "queue_id": item.queue_id,
            "persisted": should_persist,
            "snapshot_path": snapshot_path.display().to_string(),
            "transitions": transitions,
            "episodes": episodes,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "incidents_created": incidents_created,
            "incidents_updated": incidents_updated,
            "incidents_resolved": incidents_resolved,
            "alerts_recorded": alerts_recorded,
            "ownership_gaps": ownership_gaps
        }),
    )?;

    Ok(json!({
        "job_id": item.job_id,
        "queue_id": item.queue_id,
        "target": item.target,
        "snapshot_path": snapshot_path.display().to_string(),
        "persisted": should_persist,
        "transitions": transitions,
        "episodes": episodes,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
        "incidents_resolved": incidents_resolved,
        "alerts_recorded": alerts_recorded,
        "ownership_gaps": ownership_gaps,
        "duration_ms": duration_ms
    }))
}

#[derive(Debug, Default)]
struct IncidentReconciliationSummary {
    created: usize,
    updated: usize,
    resolved: usize,
    alerts_recorded: usize,
    ownership_gaps: usize,
}

async fn reconcile_incidents_from_current_state(
    config: &AppConfig,
    store: &AtlasStore,
    scope: &StorageScope,
    target: &str,
    graph: Option<&atlas_graph::ExposureGraph>,
) -> Result<IncidentReconciliationSummary> {
    let started = std::time::Instant::now();

    let current_findings =
        store.list_current_findings_operational_scoped(scope, target, None, None, None, None)?;
    let episodes = store.list_episodes_scoped(scope, target)?;
    let owners = store.list_asset_owners_scoped(scope, None)?;
    let existing_incidents = store
        .list_incidents_scoped(scope, None, None, 500)?
        .into_iter()
        .filter(|item| item.target.eq_ignore_ascii_case(target))
        .collect::<Vec<_>>();

    let ownership_report = build_ownership_intelligence(
        target,
        &current_findings,
        existing_incidents
            .iter()
            .filter(|i| !i.state.eq_ignore_ascii_case("resolved"))
            .count(),
        &owners,
    );

    let operations_report = build_incident_operations_intelligence(
        target,
        &current_findings,
        &episodes,
        &owners,
        graph,
    );

    let active_candidate_ids = operations_report
        .candidates
        .iter()
        .map(|c| c.incident_id.clone())
        .collect::<BTreeSet<_>>();

    let mut summary = IncidentReconciliationSummary {
        ownership_gaps: ownership_report.gaps.len(),
        ..Default::default()
    };

    for candidate in &operations_report.candidates {
        let existing = store.get_incident_scoped(scope, &candidate.incident_id)?;
        let incident = candidate_to_incident(candidate);

        match existing {
            None => {
                store.upsert_incident_scoped(scope, &incident)?;
                summary.created += 1;

                let deliveries =
                    deliver_incident_alerts(config, store, scope, &incident, "incident.opened")
                        .await?;
                summary.alerts_recorded += deliveries.len();
            }
            Some(prev) => {
                let mut next = incident.clone();
                next.created_at = prev.created_at.clone();

                if prev.state.eq_ignore_ascii_case("resolved") {
                    next.state = "reopened".to_string();
                } else {
                    next.state = prev.state.clone();
                }

                if prev.owner.is_some() && next.owner.is_none() {
                    next.owner = prev.owner.clone();
                }

                if prev.notes.is_some() && next.notes.is_none() {
                    next.notes = prev.notes.clone();
                }

                if incident_changed(&prev, &next) {
                    store.upsert_incident_scoped(scope, &next)?;
                    summary.updated += 1;

                    if prev.state.eq_ignore_ascii_case("resolved")
                        && (next.state.eq_ignore_ascii_case("reopened")
                            || next.state.eq_ignore_ascii_case("open"))
                    {
                        let deliveries = deliver_incident_alerts(
                            config,
                            store,
                            scope,
                            &next,
                            "incident.reopened",
                        )
                        .await?;
                        summary.alerts_recorded += deliveries.len();
                    }
                }
            }
        }
    }

    for existing in existing_incidents {
        if existing.state.eq_ignore_ascii_case("resolved") {
            continue;
        }

        if active_candidate_ids.contains(&existing.incident_id) {
            continue;
        }

        store.set_incident_state_scoped(scope, &existing.incident_id, "resolved")?;
        summary.resolved += 1;
    }

    store.record_telemetry_scoped(
        scope,
        "incident-reconciliation",
        Some(target),
        started.elapsed().as_millis(),
        &json!({
            "target": target,
            "created": summary.created,
            "updated": summary.updated,
            "resolved": summary.resolved,
            "ownership_gaps": summary.ownership_gaps,
            "candidate_count": operations_report.total_candidates
        }),
    )?;

    Ok(summary)
}

fn candidate_to_incident(candidate: &IncidentCandidate) -> StoredIncident {
    let now = chrono::Utc::now().to_rfc3339();

    StoredIncident {
        incident_id: candidate.incident_id.clone(),
        target: candidate.target.clone(),
        source_kind: candidate.source_kind.clone(),
        source_id: candidate.source_id.clone(),
        title: candidate.title.clone(),
        severity: candidate.severity.to_string(),
        score: candidate.score,
        state: candidate.state_hint.clone(),
        owner: candidate.ownership.owner.clone(),
        notes: None,
        resource: candidate.resource.clone(),
        context_json: serde_json::to_string(&json!({
            "blast_radius": candidate.blast_radius,
            "related_entities": candidate.related_entities,
            "evidence": candidate.evidence,
            "recommendation": candidate.recommendation,
            "ownership": {
                "owner": candidate.ownership.owner.clone(),
                "team": candidate.ownership.team.clone(),
                "business_service": candidate.ownership.business_service.clone(),
                "criticality": candidate.ownership.criticality.clone(),
                "confidence": candidate.ownership.confidence
            }
        }))
        .unwrap_or_else(|_| "{}".to_string()),
        created_at: now.clone(),
        updated_at: now,
    }
}

fn incident_changed(prev: &StoredIncident, next: &StoredIncident) -> bool {
    prev.title != next.title
        || prev.severity != next.severity
        || prev.score != next.score
        || prev.state != next.state
        || prev.owner != next.owner
        || prev.resource != next.resource
        || prev.context_json != next.context_json
}

async fn deliver_incident_alerts(
    config: &AppConfig,
    store: &AtlasStore,
    scope: &StorageScope,
    incident: &StoredIncident,
    event_type: &str,
) -> Result<Vec<StoredAlertDelivery>> {
    if !config.alerts.enabled {
        return Ok(Vec::new());
    }

    let payload = json!({
        "event_type": event_type,
        "incident_id": incident.incident_id,
        "target": incident.target,
        "title": incident.title,
        "severity": incident.severity,
        "score": incident.score,
        "resource": incident.resource,
        "source_kind": incident.source_kind,
        "source_id": incident.source_id,
        "owner": incident.owner
    });

    let client = reqwest::Client::new();
    let mut deliveries = Vec::new();

    for url in &config.alerts.webhook_urls {
        let response = client.post(url).json(&payload).send().await;
        let (status, response_body) = match response {
            Ok(resp) => {
                let code = resp.status();
                let body = resp.text().await.ok();
                if code.is_success() {
                    ("delivered".to_string(), body)
                } else {
                    ("failed".to_string(), body)
                }
            }
            Err(err) => ("failed".to_string(), Some(err.to_string())),
        };

        deliveries.push(store.record_alert_delivery_scoped(
            scope,
            &AlertDeliveryRequest {
                channel: "webhook".to_string(),
                destination: url.clone(),
                event_type: event_type.to_string(),
                status,
                payload: payload.clone(),
                response_body,
            },
        )?);
    }

    for url in &config.alerts.slack_webhooks {
        let slack_payload = json!({
            "text": format!(
                "[{}] {} | target={} | score={} | event={}",
                incident.severity, incident.title, incident.target, incident.score, event_type
            )
        });

        let response = client.post(url).json(&slack_payload).send().await;
        let (status, response_body) = match response {
            Ok(resp) => {
                let code = resp.status();
                let body = resp.text().await.ok();
                if code.is_success() {
                    ("delivered".to_string(), body)
                } else {
                    ("failed".to_string(), body)
                }
            }
            Err(err) => ("failed".to_string(), Some(err.to_string())),
        };

        deliveries.push(store.record_alert_delivery_scoped(
            scope,
            &AlertDeliveryRequest {
                channel: "slack".to_string(),
                destination: url.clone(),
                event_type: event_type.to_string(),
                status,
                payload: slack_payload.clone(),
                response_body,
            },
        )?);
    }

    for recipient in &config.alerts.email_recipients {
        deliveries.push(store.record_alert_delivery_scoped(
            scope,
            &AlertDeliveryRequest {
                channel: "email".to_string(),
                destination: recipient.clone(),
                event_type: event_type.to_string(),
                status: "pending_external".to_string(),
                payload: payload.clone(),
                response_body: Some(
                    "email transport no implementado; delivery registrada".to_string(),
                ),
            },
        )?);
    }

    Ok(deliveries)
}

fn build_analysis_bundle(
    config: &AppConfig,
    target: &str,
    dir: &Path,
    policy_path: Option<&Path>,
) -> Result<AnalysisBundle> {
    let snapshot_inputs = load_snapshot_inputs_for_target(dir, target)?;
    if snapshot_inputs.is_empty() {
        bail!("no hay snapshots para construir análisis de {target}");
    }

    let latest_snapshot = snapshot_inputs.last().map(|item| item.snapshot.clone());
    let policy_loaded = load_policy(policy_path)?;

    let mut timeline = None;
    let mut episodes = None;

    if snapshot_inputs.len() >= 2 {
        let snapshots = snapshot_inputs
            .iter()
            .map(|item| item.snapshot.clone())
            .collect::<Vec<_>>();

        let mut built_timeline =
            atlas_drift::build_timeline_report(target, &snapshots, policy_loaded.as_ref())?;

        let registry = default_registry_for(&config.plugins.enabled);
        registry.apply_timeline_report(&mut built_timeline);

        let mut clusters_by_transition = Vec::new();
        for transition in &built_timeline.transitions {
            let clusters = atlas_correlation::correlate_report(&transition.report)?;
            clusters_by_transition.push(clusters);
        }

        let built_episodes = atlas_episodes::build_episodes_for_timeline(
            target,
            &built_timeline,
            &clusters_by_transition,
        )?;

        timeline = Some(built_timeline);
        episodes = Some(built_episodes);
    }

    let graph = atlas_graph::build_full_graph(
        target,
        latest_snapshot.as_ref(),
        timeline.as_ref(),
        episodes.as_ref(),
    );

    Ok(AnalysisBundle {
        snapshot_inputs,
        timeline,
        episodes,
        graph,
    })
}

fn load_snapshot_inputs_for_target(dir: &Path, target: &str) -> Result<Vec<LoadedSnapshotInput>> {
    let paths = atlas_snapshot::list_snapshots_for_target(dir, target)?;
    let mut loaded = Vec::new();

    for path in paths {
        let snapshot = atlas_snapshot::load_snapshot(&path)?;
        loaded.push(LoadedSnapshotInput { path, snapshot });
    }

    loaded.sort_by_key(|a| a.snapshot.timestamp);
    Ok(loaded)
}

fn load_policy(path: Option<&Path>) -> Result<Option<atlas_drift::DriftPolicy>> {
    match path {
        Some(path) => {
            let loaded = atlas_drift::DriftPolicy::load_from_path(path)?;
            loaded.validate()?;
            Ok(Some(loaded))
        }
        None => Ok(None),
    }
}

fn init_tracing(config: &AppConfig) -> Result<()> {
    let filter =
        EnvFilter::try_new(config.logging.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.logging.json {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    Ok(())
}
