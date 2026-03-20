use anyhow::{bail, Result};
use atlas_config::AppConfig;
use atlas_risk::{AlertEvent, RiskReport, SummaryReport};
use atlas_store::AtlasStore;
use serde::Serialize;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Serialize)]
struct WatchCycleReport {
    cycle: usize,
    snapshot_path: String,
    risk: RiskReport,
    summary: SummaryReport,
    alerts: Vec<AlertEvent>,
}

pub fn handle_risk(
    config: &AppConfig,
    target: String,
    dir: PathBuf,
    policy: Option<PathBuf>,
    want_json: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let started = Instant::now();
    let bundle = super::build_analysis_bundle(config, &target, &dir, policy.as_deref())?;

    let report = atlas_risk::build_risk_report(
        &target,
        bundle.timeline.as_ref(),
        bundle.episodes.as_ref(),
        &bundle.graph,
    );

    if want_json {
        atlas_output::write_json_output(&report, output.as_deref())?;
    } else {
        print_human_risk_report(&report);
    }

    let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
    super::record_telemetry_if_enabled(
        config,
        store.as_ref(),
        "risk",
        Some(&target),
        started.elapsed().as_millis(),
        json!({
            "total_risks": report.total_risks,
            "critical": report.critical,
            "high": report.high,
            "score": report.total_score
        }),
    )?;

    Ok(())
}

pub fn handle_summary(
    config: &AppConfig,
    target: String,
    dir: PathBuf,
    policy: Option<PathBuf>,
    want_json: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let started = Instant::now();
    let bundle = super::build_analysis_bundle(config, &target, &dir, policy.as_deref())?;

    let snapshots = bundle
        .snapshot_inputs
        .iter()
        .map(|item| item.snapshot.clone())
        .collect::<Vec<_>>();

    let report = atlas_risk::build_summary_report(
        &target,
        &snapshots,
        bundle.timeline.as_ref(),
        bundle.episodes.as_ref(),
        &bundle.graph,
    );

    if want_json {
        atlas_output::write_json_output(&report, output.as_deref())?;
    } else {
        print_human_summary_report(&report);
    }

    let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
    super::record_telemetry_if_enabled(
        config,
        store.as_ref(),
        "summary",
        Some(&target),
        started.elapsed().as_millis(),
        json!({
            "snapshots": report.snapshot_count,
            "risk_score": report.exposure.total_risk_score,
            "services": report.assets.services,
            "subdomains": report.assets.subdomains
        }),
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_watch(
    config: &AppConfig,
    target: String,
    dir: PathBuf,
    policy: Option<PathBuf>,
    interval: u64,
    persist: bool,
    alerts_enabled: bool,
    alert_output: Option<PathBuf>,
    iterations: Option<usize>,
    want_json: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    if interval == 0 {
        bail!("interval debe ser > 0");
    }

    if want_json && iterations.is_none() {
        bail!("watch con --json requiere --iterations para producir una salida finita");
    }

    let total_iterations = iterations.unwrap_or(usize::MAX);
    let mut reports = Vec::new();

    for cycle in 1..=total_iterations {
        let started = Instant::now();

        let scan = atlas_discovery::scan_target(&target).await?;
        let snapshot = atlas_snapshot::Snapshot::new(scan);
        let snapshot_path = atlas_snapshot::save_snapshot(&snapshot, &dir)?;

        let should_persist = persist || config.drift.persist_by_default;
        if should_persist {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.register_snapshot(&snapshot_path, &snapshot)?;
        }

        let bundle = super::build_analysis_bundle(config, &target, &dir, policy.as_deref())?;

        if should_persist {
            persist_analysis_bundle(
                Path::new(&config.storage.path),
                &target,
                policy.as_deref(),
                &bundle,
            )?;
        }

        let snapshots = bundle
            .snapshot_inputs
            .iter()
            .map(|item| item.snapshot.clone())
            .collect::<Vec<_>>();

        let risk = atlas_risk::build_risk_report(
            &target,
            bundle.timeline.as_ref(),
            bundle.episodes.as_ref(),
            &bundle.graph,
        );

        let summary = atlas_risk::build_summary_report(
            &target,
            &snapshots,
            bundle.timeline.as_ref(),
            bundle.episodes.as_ref(),
            &bundle.graph,
        );

        let cycle_alerts = if alerts_enabled {
            atlas_risk::build_basic_alerts(&risk)
        } else {
            Vec::new()
        };

        if let Some(path) = alert_output.as_deref() {
            append_alerts(path, &cycle_alerts)?;
        }

        if want_json {
            reports.push(WatchCycleReport {
                cycle,
                snapshot_path: snapshot_path.display().to_string(),
                risk: risk.clone(),
                summary: summary.clone(),
                alerts: cycle_alerts.clone(),
            });
        } else {
            print_watch_cycle(
                cycle,
                &snapshot_path,
                &risk,
                &summary,
                &cycle_alerts,
                should_persist,
            );
        }

        let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
        super::record_telemetry_if_enabled(
            config,
            store.as_ref(),
            "watch",
            Some(&target),
            started.elapsed().as_millis(),
            json!({
                "cycle": cycle,
                "snapshot_path": snapshot_path.display().to_string(),
                "persisted": should_persist,
                "alerts": cycle_alerts.len(),
                "risk_score": risk.total_score
            }),
        )?;

        if cycle == total_iterations {
            break;
        }

        sleep(Duration::from_secs(interval)).await;
    }

    if want_json {
        atlas_output::write_json_output(&reports, output.as_deref())?;
    }

    Ok(())
}

fn persist_analysis_bundle(
    db_path: &Path,
    target: &str,
    policy_path: Option<&Path>,
    bundle: &super::AnalysisBundle,
) -> Result<()> {
    let store = AtlasStore::open(db_path)?;
    store.initialize()?;

    if let Some(timeline) = &bundle.timeline {
        for (pair, transition) in bundle
            .snapshot_inputs
            .windows(2)
            .zip(timeline.transitions.iter())
        {
            let older = &pair[0];
            let newer = &pair[1];
            store.register_drift_report(
                target,
                &older.path,
                &newer.path,
                policy_path,
                &transition.report,
            )?;
        }
    }

    if let Some(collection) = &bundle.episodes {
        store.store_episodes(target, &collection.episodes)?;
    }

    store.store_graph(target, &bundle.graph)?;
    Ok(())
}

fn append_alerts(path: &Path, alerts: &[AlertEvent]) -> Result<()> {
    if alerts.is_empty() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for alert in alerts {
        let line = serde_json::to_string(alert)?;
        writeln!(file, "{line}")?;
    }

    Ok(())
}

fn print_watch_cycle(
    cycle: usize,
    snapshot_path: &Path,
    risk: &RiskReport,
    summary: &SummaryReport,
    alerts: &[AlertEvent],
    persisted: bool,
) {
    println!("============================================================");
    println!("Watch cycle: {}", cycle);
    println!("Snapshot: {}", snapshot_path.display());
    println!("Persisted: {}", if persisted { "yes" } else { "no" });

    println!();
    print_human_summary_report(summary);

    println!();
    print_human_risk_report(risk);

    if !alerts.is_empty() {
        println!();
        println!("Alerts:");
        for alert in alerts {
            println!(
                "  - [{}] {} | resource={} | {}",
                alert.severity, alert.title, alert.resource, alert.message
            );
        }
    }

    println!("============================================================");
}

fn print_human_risk_report(report: &RiskReport) {
    println!("Target: {}", report.target);
    println!("Generated at: {}", report.generated_at);
    println!("Total risks: {}", report.total_risks);
    println!("Total score: {}", report.total_score);

    println!();
    println!("By severity:");
    println!("  - Critical: {}", report.critical);
    println!("  - High: {}", report.high);
    println!("  - Medium: {}", report.medium);
    println!("  - Low: {}", report.low);

    if report.risks.is_empty() {
        println!();
        println!("No se detectaron riesgos priorizados.");
        return;
    }

    println!();
    println!("Top risks:");
    for item in &report.top_risks {
        println!(
            "  - [{}] {} | resource={} | score={}",
            item.severity, item.title, item.resource, item.score
        );
        println!("      kind={}", item.kind);
        println!("      description={}", item.description);
        println!("      recommendation={}", item.recommendation);

        if !item.evidence.is_empty() {
            println!("      evidence={}", item.evidence.join(", "));
        }
    }
}

fn print_human_summary_report(report: &SummaryReport) {
    println!("Target: {}", report.target);
    println!("Generated at: {}", report.generated_at);
    println!("Snapshots: {}", report.snapshot_count);

    if let Some(latest) = report.latest_snapshot_at {
        println!("Latest snapshot: {}", latest);
    }

    println!();
    println!("Assets:");
    println!("  - Subdomains: {}", report.assets.subdomains);
    println!("  - IPs: {}", report.assets.ips);
    println!("  - Services: {}", report.assets.services);
    println!("  - Technologies: {}", report.assets.technologies);
    println!("  - Episodes: {}", report.assets.episodes);

    println!();
    println!("Exposure:");
    println!("  - Critical risks: {}", report.exposure.critical_risks);
    println!("  - High risks: {}", report.exposure.high_risks);
    println!("  - Medium risks: {}", report.exposure.medium_risks);
    println!("  - Low risks: {}", report.exposure.low_risks);
    println!("  - Total risk score: {}", report.exposure.total_risk_score);

    if let Some(drift) = &report.drift {
        println!();
        println!("Drift:");
        println!("  - Total findings: {}", drift.total_findings);
        println!("  - Critical findings: {}", drift.critical_findings);
        println!("  - Recurring findings: {}", drift.recurring_findings);
        println!("  - Persistent findings: {}", drift.persistent_findings);

        if !drift.top_resources.is_empty() {
            println!("  - Top resources:");
            for item in &drift.top_resources {
                println!(
                    "      {} | occurrences={} | score={}",
                    item.resource, item.occurrences, item.total_score
                );
            }
        }
    }

    println!();
    println!("Graph:");
    println!("  - Nodes: {}", report.graph.node_count);
    println!("  - Edges: {}", report.graph.edge_count);
    println!("  - Connected nodes: {}", report.graph.connected_nodes);
    println!("  - Isolated nodes: {}", report.graph.isolated_nodes);
    println!("  - Max degree: {}", report.graph.max_degree);

    if !report.graph.hubs.is_empty() {
        println!("  - Hubs:");
        for hub in &report.graph.hubs {
            println!("      {}", hub);
        }
    }

    if !report.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for recommendation in &report.recommendations {
            println!("  - {}", recommendation);
        }
    }
}
