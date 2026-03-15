use anyhow::{Context, Result};
use atlas_config::AppConfig;
use atlas_correlation::{
    build_episodes, build_resource_lineage, build_timeline_episodes, explain_finding,
};
use atlas_jobs::{scheduler_plan, AtlasJob};
use atlas_plugins::default_registry_for;
use atlas_store::{AtlasStore, ExportFormat};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "atlas")]
#[command(about = "Prometheus Atlas - Security Drift Scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init {
        #[arg(long, default_value = "atlas.toml")]
        output: PathBuf,
    },

    Scan {
        target: String,

        #[arg(long, default_value = "standard")]
        profile: String,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Snapshot {
        target: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,

        #[arg(long, default_value = "standard")]
        profile: String,

        #[arg(long)]
        persist: bool,
    },

    Diff {
        older: PathBuf,
        newer: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Drift {
        older: PathBuf,
        newer: PathBuf,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long)]
        persist: bool,

        #[arg(long)]
        profile: Option<String>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Timeline {
        target: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Episodes {
        target: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Explain {
        target: String,

        #[arg(long)]
        resource: String,
    },

    PolicyValidate {
        path: PathBuf,
    },

    PolicyExplain {
        path: PathBuf,
    },

    History {
        target: String,
    },

    Findings {
        target: String,

        #[arg(long)]
        severity: Option<String>,

        #[arg(long)]
        state: Option<String>,
    },

    Snapshots {
        target: String,
    },

    Export {
        target: String,

        #[arg(long)]
        format: String,

        #[arg(long)]
        output: PathBuf,

        #[arg(long)]
        severity: Option<String>,

        #[arg(long)]
        state: Option<String>,
    },

    BaselineApprove {
        resource: String,

        #[arg(long)]
        expires_at: Option<String>,
    },

    BaselineRevoke {
        resource: String,
    },

    BaselineList,

    JobCreate {
        target: String,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long, default_value = "standard")]
        profile: String,

        #[arg(long)]
        interval: Option<u64>,
    },

    JobList,

    JobDisable {
        job_id: String,
    },

    JobRun {
        job_id: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,
    },

    SchedulerPlan,

    Migrate {
        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,
    },

    Telemetry {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
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
    info!("Prometheus Atlas starting");

    match cli.command {
        Commands::Init { output } => {
            let started = Instant::now();

            if output.exists() {
                warn!(
                    "El archivo de configuración ya existe: {}",
                    output.display()
                );
            } else {
                AppConfig::write_default_to_path(&output)?;
                println!("Configuración creada en: {}", output.display());
            }

            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            println!("Storage inicializado en: {}", config.storage.path);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "init",
                None,
                started.elapsed().as_millis(),
                json!({"config_path": output.display().to_string()}),
            )?;
        }

        Commands::Scan {
            target,
            profile,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let _profile = config.profile(&profile)?;
            let result = atlas_discovery::scan_target(&target).await?;

            if want_json {
                atlas_output::write_json_output(&result, output.as_deref())?;
            } else {
                atlas_output::print_human_scan_result(&result);
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "scan",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "resolved_ips": result.resolved_ips.len(),
                    "subdomains": result.subdomains.len(),
                    "services": result.services.len(),
                    "profile": profile
                }),
            )?;
        }

        Commands::Snapshot {
            target,
            dir,
            profile,
            persist,
        } => {
            let started = Instant::now();
            let _profile = config.profile(&profile)?;
            let result = atlas_discovery::scan_target(&target).await?;
            let snapshot = atlas_snapshot::Snapshot::new(result);
            let path = atlas_snapshot::save_snapshot(&snapshot, &dir)?;
            println!("Snapshot guardado en: {}", path.display());

            let should_persist = persist || config.drift.persist_by_default;
            let store = AtlasStore::open(Path::new(&config.storage.path))?;

            if should_persist {
                store.initialize()?;
                store.register_snapshot(&path, &snapshot)?;
                println!("Snapshot registrado en storage.");
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "snapshot",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "path": path.display().to_string(),
                    "persisted": should_persist,
                    "profile": profile
                }),
            )?;
        }

        Commands::Diff {
            older,
            newer,
            json: want_json,
            output,
        } => {
            let older_snapshot = atlas_snapshot::load_snapshot(&older)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer)?;
            let report = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

            if want_json {
                atlas_output::write_json_output(&report, output.as_deref())?;
            } else {
                print_human_diff_report(&report);
            }
        }

        Commands::Drift {
            older,
            newer,
            policy,
            persist,
            profile,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let older_snapshot = atlas_snapshot::load_snapshot(&older)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer)?;
            let diff = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

            let profile_name = profile.unwrap_or_else(|| config.drift.profile.clone());
            let _profile = config.profile(&profile_name)?;

            let policy_loaded = match policy.as_deref() {
                Some(path) => {
                    let loaded = atlas_drift::DriftPolicy::load_from_path(path)?;
                    loaded.validate()?;
                    Some(loaded)
                }
                None => None,
            };

            let mut drift = atlas_drift::analyze_diff_with_policy(&diff, policy_loaded.as_ref());

            let registry = default_registry_for(&config.plugins.enabled);
            registry.apply_drift_report(&mut drift);

            if want_json {
                atlas_output::write_json_output(&drift, output.as_deref())?;
            } else {
                print_human_drift_report(&drift);
            }

            let should_persist = persist || config.drift.persist_by_default;
            let store = AtlasStore::open(Path::new(&config.storage.path))?;

            if should_persist {
                store.initialize()?;
                store.register_drift_report(
                    &diff.target,
                    &older,
                    &newer,
                    policy.as_deref(),
                    &drift,
                )?;
                println!("Drift registrado en storage.");
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "drift",
                Some(&diff.target),
                started.elapsed().as_millis(),
                json!({
                    "findings": drift.findings.len(),
                    "suppressed": drift.suppressed_findings.len(),
                    "score": drift.summary.total_score,
                    "persisted": should_persist,
                    "profile": profile_name
                }),
            )?;
        }

        Commands::Timeline {
            target,
            dir,
            policy,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let snapshots = atlas_snapshot::load_all_snapshots_for_target(&dir, &target)?;

            let policy_loaded = match policy.as_deref() {
                Some(path) => {
                    let loaded = atlas_drift::DriftPolicy::load_from_path(path)?;
                    loaded.validate()?;
                    Some(loaded)
                }
                None => None,
            };

            let mut timeline =
                atlas_drift::build_timeline_report(&target, &snapshots, policy_loaded.as_ref())?;

            let registry = default_registry_for(&config.plugins.enabled);
            registry.apply_timeline_report(&mut timeline);

            if want_json {
                atlas_output::write_json_output(&timeline, output.as_deref())?;
            } else {
                print_human_timeline_report(&timeline);
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "timeline",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "snapshots": timeline.snapshot_count,
                    "transitions": timeline.transition_count,
                    "total_findings": timeline.executive.total_findings,
                    "total_score": timeline.executive.total_score
                }),
            )?;
        }

        Commands::Episodes {
            target,
            dir,
            policy,
            json: want_json,
            output,
        } => {
            let snapshots = atlas_snapshot::load_all_snapshots_for_target(&dir, &target)?;

            let policy_loaded = match policy.as_deref() {
                Some(path) => {
                    let loaded = atlas_drift::DriftPolicy::load_from_path(path)?;
                    loaded.validate()?;
                    Some(loaded)
                }
                None => None,
            };

            let timeline =
                atlas_drift::build_timeline_report(&target, &snapshots, policy_loaded.as_ref())?;

            let episodes = build_timeline_episodes(&timeline);

            if want_json {
                atlas_output::write_json_output(&episodes, output.as_deref())?;
            } else {
                print_human_episodes(&episodes);
            }
        }

        Commands::Explain { target, resource } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let findings = store.list_findings(&target, None, None)?;

            let matched: Vec<_> = findings
                .into_iter()
                .filter(|f| f.resource == resource)
                .collect();

            if matched.is_empty() {
                println!("No se encontraron findings para el recurso {resource}");
            } else {
                println!("Explicación para {resource}:");
                for item in matched {
                    let synthetic = atlas_drift::DriftFinding {
                        finding_id: item.finding_id.clone(),
                        severity: parse_severity(&item.severity),
                        score: item.score,
                        category: item.category.clone(),
                        title: item.category.clone(),
                        resource: item.resource.clone(),
                        asset_type: parse_asset_type(&item.asset_type),
                        environment: parse_environment(&item.environment),
                        criticality: parse_criticality(&item.criticality),
                        state: parse_state(&item.state),
                        tags: item.tags.clone(),
                        description: item.description.clone(),
                    };

                    let explanation = explain_finding(&synthetic);

                    println!(
                        "- finding_id={} | base_score={} | final_score={} | multiplier={}",
                        explanation.finding_id,
                        explanation.base_score,
                        explanation.final_score,
                        explanation.criticality_multiplier
                    );

                    for reason in explanation.reasons {
                        println!("    • {}", reason);
                    }
                }
            }
        }

        Commands::PolicyValidate { path } => {
            let policy = atlas_drift::DriftPolicy::load_from_path(&path)?;
            policy.validate()?;
            println!("Policy válida: {}", path.display());
        }

        Commands::PolicyExplain { path } => {
            let policy = atlas_drift::DriftPolicy::load_from_path(&path)?;
            policy.validate()?;
            println!("Resumen de policy {}:", path.display());
            for line in policy.describe() {
                println!("- {}", line);
            }
        }

        Commands::History { target } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let history = store.list_history(&target)?;

            if history.is_empty() {
                println!("No hay historial persistido para {target}");
            } else {
                println!("Historial de drift para {target}:");
                for item in history {
                    println!(
                        "- run_id={} | {} -> {} | findings={} | score={} | severity={}",
                        item.run_id,
                        item.older_snapshot_path,
                        item.newer_snapshot_path,
                        item.total_findings,
                        item.total_score,
                        item.overall_severity
                    );
                }
            }
        }

        Commands::Findings {
            target,
            severity,
            state,
        } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let findings = store.list_findings(&target, severity.as_deref(), state.as_deref())?;

            if findings.is_empty() {
                println!("No hay findings persistidos para {target}");
            } else {
                println!("Findings persistidos para {target}:");
                for item in findings {
                    println!(
                        "- id={} | severity={} | state={} | category={} | resource={} | score={}",
                        item.finding_id,
                        item.severity,
                        item.state,
                        item.category,
                        item.resource,
                        item.score
                    );
                }
            }
        }

        Commands::Snapshots { target } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let snapshots = store.list_snapshots(&target)?;

            if snapshots.is_empty() {
                println!("No hay snapshots registrados para {target}");
            } else {
                println!("Snapshots registrados para {target}:");
                for snapshot in snapshots {
                    println!(
                        "- id={} | ts={} | version={} | hash={} | path={}",
                        snapshot.snapshot_id,
                        snapshot.timestamp,
                        snapshot.snapshot_version,
                        snapshot.file_hash,
                        snapshot.path
                    );
                }
            }
        }

        Commands::Export {
            target,
            format,
            output,
            severity,
            state,
        } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let export_format = ExportFormat::from_str(&format)
                .with_context(|| format!("formato no soportado: {format}"))?;

            store.export_findings(
                &target,
                severity.as_deref(),
                state.as_deref(),
                export_format,
                &output,
            )?;

            println!("Export completado en: {}", output.display());
        }

        Commands::BaselineApprove {
            resource,
            expires_at,
        } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.approve_baseline(&resource, expires_at.as_deref())?;
            println!("Baseline aprobado para {}", resource);
        }

        Commands::BaselineRevoke { resource } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.revoke_baseline(&resource)?;
            println!("Baseline revocado para {}", resource);
        }

        Commands::BaselineList => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let baseline = store.list_baseline()?;

            if baseline.is_empty() {
                println!("No hay baseline aprobado.");
            } else {
                println!("Baseline entries:");
                for entry in baseline {
                    println!(
                        "- resource={} | approved={} | expires_at={}",
                        entry.resource,
                        entry.approved,
                        entry.expires_at.unwrap_or_else(|| "-".to_string())
                    );
                }
            }
        }

        Commands::JobCreate {
            target,
            policy,
            profile,
            interval,
        } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let _profile = config.profile(&profile)?;

            let job = AtlasJob::new(
                &target,
                policy.as_ref().map(|p| p.display().to_string()),
                &profile,
                interval.unwrap_or(config.jobs.default_interval_seconds),
            )?;

            store.create_job(&job)?;
            println!("Job creado: {} para {}", job.job_id, job.target);
        }

        Commands::JobList => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let jobs = store.list_jobs()?;

            if jobs.is_empty() {
                println!("No hay jobs registrados.");
            } else {
                println!("Jobs:");
                for job in jobs {
                    println!(
                        "- id={} | target={} | profile={} | interval={}s | enabled={}",
                        job.job_id, job.target, job.profile, job.interval_seconds, job.enabled
                    );
                }
            }
        }

        Commands::JobDisable { job_id } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.set_job_enabled(&job_id, false)?;
            println!("Job deshabilitado: {}", job_id);
        }

        Commands::JobRun { job_id, dir } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let jobs = store.list_jobs()?;

            let job = jobs
                .into_iter()
                .find(|j| j.job_id == job_id)
                .with_context(|| format!("job no encontrado: {job_id}"))?;

            let _profile = config.profile(&job.profile)?;
            let result = atlas_discovery::scan_target(&job.target).await?;
            let snapshot = atlas_snapshot::Snapshot::new(result);
            let path = atlas_snapshot::save_snapshot(&snapshot, &dir)?;
            store.register_snapshot(&path, &snapshot)?;
            store.touch_job_run(&job.job_id)?;

            println!(
                "Job ejecutado correctamente. target={} snapshot={}",
                job.target,
                path.display()
            );
        }

        Commands::SchedulerPlan => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let jobs = store.list_jobs()?;
            let plan = scheduler_plan(&jobs, chrono::Utc::now());

            if plan.is_empty() {
                println!("No hay jobs listos para ejecutar.");
            } else {
                println!("Jobs planificados:");
                for item in plan {
                    println!(
                        "- job_id={} | target={} | profile={}",
                        item.job_id, item.target, item.profile
                    );
                }
            }
        }

        Commands::Migrate { dir } => {
            let report = atlas_snapshot::migrate_snapshots_in_dir(&dir)?;
            println!(
                "Migración completada. Archivos revisados: {} | migrados: {}",
                report.scanned_files, report.migrated_files
            );
        }

        Commands::Telemetry { limit } => {
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let events = store.list_telemetry(limit)?;

            if events.is_empty() {
                println!("No hay eventos de telemetría.");
            } else {
                println!("Últimos eventos de telemetría:");
                for event in events {
                    println!(
                        "- {} | command={} | target={} | duration_ms={}",
                        event.created_at,
                        event.name,
                        event.target.unwrap_or_else(|| "-".to_string()),
                        event.duration_ms
                    );
                }
            }
        }
    }

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

fn record_telemetry_if_enabled(
    config: &AppConfig,
    store: Option<&AtlasStore>,
    name: &str,
    target: Option<&str>,
    duration_ms: u128,
    metadata: serde_json::Value,
) -> Result<()> {
    if config.telemetry.enabled {
        if let Some(store) = store {
            store.record_telemetry(name, target, duration_ms, &metadata)?;
        }
    }

    Ok(())
}

fn parse_severity(value: &str) -> atlas_drift::Severity {
    match value {
        "HIGH" | "High" => atlas_drift::Severity::High,
        "MEDIUM" | "Medium" => atlas_drift::Severity::Medium,
        "LOW" | "Low" => atlas_drift::Severity::Low,
        _ => atlas_drift::Severity::Info,
    }
}

fn parse_criticality(value: &str) -> atlas_drift::Criticality {
    match value {
        "CRITICAL" | "Critical" => atlas_drift::Criticality::Critical,
        "HIGH" | "High" => atlas_drift::Criticality::High,
        "MEDIUM" | "Medium" => atlas_drift::Criticality::Medium,
        _ => atlas_drift::Criticality::Low,
    }
}

fn parse_state(value: &str) -> atlas_drift::FindingState {
    match value {
        "Recurring" => atlas_drift::FindingState::Recurring,
        "Persistent" => atlas_drift::FindingState::Persistent,
        "Suppressed" => atlas_drift::FindingState::Suppressed,
        "Resolved" => atlas_drift::FindingState::Resolved,
        _ => atlas_drift::FindingState::New,
    }
}

fn parse_asset_type(value: &str) -> atlas_drift::AssetType {
    match value {
        "Ip" => atlas_drift::AssetType::Ip,
        "Subdomain" => atlas_drift::AssetType::Subdomain,
        "Service" => atlas_drift::AssetType::Service,
        _ => atlas_drift::AssetType::Unknown,
    }
}

fn parse_environment(value: &str) -> atlas_drift::Environment {
    match value {
        "Production" => atlas_drift::Environment::Production,
        "Admin" => atlas_drift::Environment::Admin,
        "Development" => atlas_drift::Environment::Development,
        "Staging" => atlas_drift::Environment::Staging,
        "Test" => atlas_drift::Environment::Test,
        _ => atlas_drift::Environment::Unknown,
    }
}

fn print_human_diff_report(report: &atlas_diff::DiffReport) {
    println!("Target: {}", report.target);
    println!("Snapshot anterior: {}", report.older_timestamp);
    println!("Snapshot actual:   {}", report.newer_timestamp);

    println!();
    println!("Resumen:");
    println!("  - IPs nuevas: {}", report.new_ips.len());
    println!("  - IPs removidas: {}", report.removed_ips.len());
    println!("  - Subdominios nuevos: {}", report.new_subdomains.len());
    println!(
        "  - Subdominios removidos: {}",
        report.removed_subdomains.len()
    );
    println!("  - Servicios nuevos: {}", report.new_services.len());
    println!("  - Servicios removidos: {}", report.removed_services.len());
    println!(
        "  - Servicios modificados: {}",
        report.changed_services.len()
    );

    if !report.has_changes() {
        println!();
        println!("No se detectaron cambios entre snapshots.");
    }
}

fn print_human_drift_report(report: &atlas_drift::DriftReport) {
    println!("Target: {}", report.target);
    println!("Snapshot anterior: {}", report.older_timestamp);
    println!("Snapshot actual:   {}", report.newer_timestamp);
    println!("Hallazgos: {}", report.findings.len());

    println!();
    println!("Resumen por severidad:");
    println!("  - High: {}", report.summary.high);
    println!("  - Medium: {}", report.summary.medium);
    println!("  - Low: {}", report.summary.low);
    println!("  - Info: {}", report.summary.info);

    println!();
    println!("Score total: {}", report.summary.total_score);
    println!("Severidad global: {}", report.summary.overall_severity);
    println!(
        "Hallazgos sobre activos críticos: {}",
        report.summary.critical_findings
    );

    println!();
    println!("Estados de hallazgo:");
    println!("  - New: {}", report.summary.states.new);
    println!("  - Recurring: {}", report.summary.states.recurring);
    println!("  - Persistent: {}", report.summary.states.persistent);
    println!("  - Suppressed: {}", report.summary.states.suppressed);
    println!("  - Resolved: {}", report.summary.states.resolved);

    if !report.suppressed_findings.is_empty() {
        println!();
        println!(
            "Hallazgos suprimidos por baseline/policy: {}",
            report.suppressed_findings.len()
        );
    }

    if report.findings.is_empty() {
        println!();
        println!("No se detectaron hallazgos de Security Drift.");
        return;
    }

    println!();
    println!("Hallazgos agrupados por recurso:");
    for group in &report.groups {
        println!(
            "  - recurso={} | severidad={} | criticidad={} | score={}",
            group.resource, group.highest_severity, group.highest_criticality, group.total_score
        );

        for finding in &group.findings {
            println!(
                "      [{}] id={} | categoría={} | tipo={} | entorno={} | criticidad={} | estado={} | score={}",
                finding.title,
                finding.finding_id,
                finding.category,
                finding.asset_type,
                finding.environment,
                finding.criticality,
                finding.state,
                finding.score
            );

            if !finding.tags.is_empty() {
                println!("          tags: {}", finding.tags.join(", "));
            }

            println!("          {}", finding.description);
        }
    }

    let episodes = build_episodes(report);
    if !episodes.is_empty() {
        println!();
        println!("Episodes:");
        for episode in episodes {
            println!(
                "  - id={} | category={:?} | severity={} | resource={} | score={}",
                episode.episode_id,
                episode.category,
                episode.severity,
                episode.resource,
                episode.score
            );
        }
    }

    let lineage = build_resource_lineage(report);
    if !lineage.is_empty() {
        println!();
        println!("Lineage detectado:");
        for link in lineage {
            println!("  - {} -> {} ({})", link.parent, link.child, link.relation);
        }
    }
}

fn print_human_timeline_report(report: &atlas_drift::TimelineReport) {
    println!("Target: {}", report.target);
    println!("Snapshots procesados: {}", report.snapshot_count);
    println!("Transiciones analizadas: {}", report.transition_count);

    println!();
    println!("Resumen ejecutivo:");
    println!("  - Score acumulado: {}", report.executive.total_score);
    println!(
        "  - Severidad global: {}",
        report.executive.overall_severity
    );
    println!(
        "  - Hallazgos acumulados: {}",
        report.executive.total_findings
    );
    println!(
        "  - Recursos únicos afectados: {}",
        report.executive.unique_resources
    );
    println!(
        "  - Hallazgos sobre activos críticos: {}",
        report.executive.critical_findings
    );
    println!(
        "  - Hallazgos recurrentes: {}",
        report.executive.recurring_findings
    );
    println!(
        "  - Hallazgos persistentes: {}",
        report.executive.persistent_findings
    );

    if !report.executive.top_resources.is_empty() {
        println!();
        println!("Recursos más problemáticos:");
        for item in &report.executive.top_resources {
            println!(
                "  - {} | score={} | ocurrencias={}",
                item.resource, item.total_score, item.occurrences
            );
        }
    }

    if !report.executive.top_categories.is_empty() {
        println!();
        println!("Categorías más frecuentes:");
        for item in &report.executive.top_categories {
            println!(
                "  - {} | ocurrencias={} | score={}",
                item.category, item.occurrences, item.total_score
            );
        }
    }

    if !report.transitions.is_empty() {
        println!();
        println!("Transiciones:");
        for transition in &report.transitions {
            println!(
                "  - {} -> {} | hallazgos={} | score={}",
                transition.older_timestamp,
                transition.newer_timestamp,
                transition.report.findings.len(),
                transition.report.summary.total_score
            );
        }
    }

    let episodes = build_timeline_episodes(report);
    if !episodes.is_empty() {
        println!();
        println!("Episodes históricos:");
        for episode in episodes {
            println!(
                "  - id={} | category={:?} | severity={} | resource={} | score={}",
                episode.episode_id,
                episode.category,
                episode.severity,
                episode.resource,
                episode.score
            );
        }
    }
}

fn print_human_episodes(episodes: &[atlas_correlation::RiskEpisode]) {
    if episodes.is_empty() {
        println!("No se detectaron episodes.");
        return;
    }

    println!("Episodes:");
    for episode in episodes {
        println!(
            "- id={} | category={:?} | severity={} | resource={} | score={}",
            episode.episode_id, episode.category, episode.severity, episode.resource, episode.score
        );
        for finding in &episode.findings {
            println!(
                "    • {} | {} | {} | score={}",
                finding.finding_id, finding.category, finding.resource, finding.score
            );
        }
    }
}
