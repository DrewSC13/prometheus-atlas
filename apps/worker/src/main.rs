use anyhow::{bail, Result};
use atlas_config::AppConfig;
use atlas_plugins::default_registry_for;
use atlas_snapshot::Snapshot;
use atlas_store::{AtlasStore, StorageScope};
use clap::Parser;
use serde_json::json;
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

    let scan_started = std::time::Instant::now();
    let result = atlas_discovery::scan_target(&item.target).await?;
    let snapshot = atlas_snapshot::Snapshot::new(result);
    let snapshot_dir = PathBuf::from(".snapshots");
    let snapshot_path = atlas_snapshot::save_snapshot(&snapshot, &snapshot_dir)?;

    let should_persist = item.persist_artifacts || config.drift.persist_by_default;
    if should_persist {
        store.register_snapshot_scoped(scope, &snapshot_path, &snapshot)?;
    }

    let mut transitions = 0usize;
    let mut episodes = 0usize;
    let mut graph_nodes = 0usize;
    let mut graph_edges = 0usize;

    if should_persist {
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
    }

    let duration_ms = scan_started.elapsed().as_millis();
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
            "graph_edges": graph_edges
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
        "duration_ms": duration_ms
    }))
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
