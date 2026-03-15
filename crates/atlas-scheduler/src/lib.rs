use anyhow::Result;
use atlas_discovery::scan_target;
use atlas_jobs::scheduler_plan;
use atlas_snapshot::{save_snapshot, Snapshot};
use atlas_store::AtlasStore;
use chrono::Utc;
use std::path::Path;

pub async fn run_scheduler_once(store: &AtlasStore) -> Result<()> {
    store.initialize()?;

    let jobs = store.list_jobs()?;
    let plans = scheduler_plan(&jobs, Utc::now());

    if plans.is_empty() {
        println!("No hay jobs para ejecutar.");
        return Ok(());
    }

    for plan in plans {
        println!("Ejecutando job {} para {}", plan.job_id, plan.target);

        let scan = scan_target(&plan.target).await?;
        let snapshot = Snapshot::new(scan);

        let snapshot_dir = Path::new(".snapshots");
        let path = save_snapshot(&snapshot, snapshot_dir)?;

        store.register_snapshot(&path, &snapshot)?;
        store.touch_job_run(&plan.job_id)?;

        println!(
            "Job {} completado. Snapshot guardado en {}",
            plan.job_id,
            path.display()
        );
    }

    Ok(())
}

pub async fn run_scheduler_loop(store: &AtlasStore, interval_seconds: u64) -> Result<()> {
    loop {
        if let Err(error) = run_scheduler_once(store).await {
            eprintln!("Error en scheduler: {error}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_seconds)).await;
    }
}
