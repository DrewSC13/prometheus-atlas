use anyhow::Result;
use atlas_config::AppConfig;
use atlas_jobs::{JobDispatchRequest, JobTrigger};
use atlas_store::AtlasStore;
use clap::Parser;
use serde_json::json;
use std::path::Path;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "atlas-scheduler")]
#[command(about = "Prometheus Atlas - Distributed scheduler control plane")]
struct Cli {
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    #[arg(long)]
    once: bool,
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

    if !config.scheduler.enabled {
        warn!("scheduler.disabled=true; no se ejecutará el control plane");
        return Ok(());
    }

    let store = AtlasStore::open(Path::new(&config.storage.path))?;
    store.initialize()?;

    info!(
        "atlas-scheduler iniciado poll_seconds={}",
        config.scheduler.poll_seconds
    );

    loop {
        run_scheduler_tick(&config, &store)?;

        if cli.once {
            break;
        }

        sleep(Duration::from_secs(config.scheduler.poll_seconds)).await;
    }

    Ok(())
}

fn run_scheduler_tick(config: &AppConfig, store: &AtlasStore) -> Result<()> {
    let now = chrono::Utc::now();
    let jobs = store.list_all_jobs_with_scope()?;

    let mut enqueued = 0usize;
    let mut skipped = 0usize;

    for scoped in &jobs {
        if !scoped.job.enabled || !scoped.job.is_due_at(now) {
            continue;
        }

        if store.job_has_active_queue_item_scoped(&scoped.scope, &scoped.job.job_id)? {
            skipped += 1;
            continue;
        }

        let dispatch = JobDispatchRequest::new(
            scoped.scope.tenant_id.clone(),
            scoped.scope.project_id.clone(),
            scoped.job.job_id.clone(),
            scoped.job.target.clone(),
            scoped.job.profile.clone(),
            JobTrigger::Scheduled,
        )
        .requested_by("scheduler")
        .persist_artifacts(config.drift.persist_by_default)
        .with_policy_path(scoped.job.policy_path.clone());

        let item = store.enqueue_job_dispatch_scoped(&scoped.scope, &dispatch)?;
        store.record_audit_event_scoped(
            &scoped.scope,
            "scheduler",
            "job.schedule.enqueue",
            "job_queue",
            &item.queue_id,
            &json!({
                "job_id": scoped.job.job_id,
                "target": scoped.job.target,
                "trigger": "scheduled"
            }),
        )?;

        enqueued += 1;
    }

    info!(
        "scheduler tick completado total_jobs={} enqueued={} skipped_active={}",
        jobs.len(),
        enqueued,
        skipped
    );

    Ok(())
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
