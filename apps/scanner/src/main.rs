use anyhow::{bail, Context, Result};
use atlas_config::AppConfig;
use atlas_plugins::default_registry_for;
use atlas_query::{
    build_graph_stats_report, execute_query, graph_search, parse_query, GraphSearchRequest,
};
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

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Snapshot {
        target: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,

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
        persist: bool,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Graph {
        target: String,

        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,

        #[arg(long)]
        policy: Option<PathBuf>,

        #[arg(long)]
        persist: bool,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    GraphStats {
        target: String,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    GraphSearch {
        target: String,

        #[arg(long)]
        kind: Option<String>,

        #[arg(long)]
        label_contains: Option<String>,

        #[arg(long)]
        min_degree: Option<usize>,

        #[arg(long, default_value_t = 25)]
        limit: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Query {
        target: String,

        expression: String,

        #[arg(long, default_value_t = 25)]
        limit: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
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
            json: want_json,
            output,
        } => {
            let started = Instant::now();
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
                    "services": result.services.len()
                }),
            )?;
        }

        Commands::Snapshot {
            target,
            dir,
            persist,
        } => {
            let started = Instant::now();
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
                    "persisted": should_persist
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
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let older_snapshot = atlas_snapshot::load_snapshot(&older)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer)?;
            let diff = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

            let policy_loaded = load_policy(policy.as_deref())?;
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
                    "persisted": should_persist
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
            let policy_loaded = load_policy(policy.as_deref())?;

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
            persist,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let snapshots = atlas_snapshot::load_all_snapshots_for_target(&dir, &target)?;
            let policy_loaded = load_policy(policy.as_deref())?;

            let mut timeline =
                atlas_drift::build_timeline_report(&target, &snapshots, policy_loaded.as_ref())?;

            let registry = default_registry_for(&config.plugins.enabled);
            registry.apply_timeline_report(&mut timeline);

            let mut clusters_by_transition = Vec::new();
            for transition in &timeline.transitions {
                let clusters = atlas_correlation::correlate_report(&transition.report)?;
                clusters_by_transition.push(clusters);
            }

            let collection = atlas_episodes::build_episodes_for_timeline(
                &target,
                &timeline,
                &clusters_by_transition,
            )?;

            if want_json {
                atlas_output::write_json_output(&collection, output.as_deref())?;
            } else {
                print_human_episode_collection(&collection);
            }

            let should_persist = persist || config.drift.persist_by_default;
            let store = AtlasStore::open(Path::new(&config.storage.path))?;

            if should_persist {
                store.initialize()?;
                store.store_episodes(&target, &collection.episodes)?;
                println!("Episodes registrados en storage.");
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "episodes",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "episodes": collection.episode_count,
                    "persisted": should_persist
                }),
            )?;
        }

        Commands::Graph {
            target,
            dir,
            policy,
            persist,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let graph =
                build_graph_from_snapshots_and_context(&config, &target, &dir, policy.as_deref())?;

            if want_json {
                atlas_output::write_json_output(&graph, output.as_deref())?;
            } else {
                atlas_output::print_human_exposure_graph(&graph);
            }

            let should_persist = persist || config.drift.persist_by_default;
            let store = AtlasStore::open(Path::new(&config.storage.path))?;

            if should_persist {
                store.initialize()?;
                store.store_graph(&target, &graph)?;
                println!("Graph registrado en storage.");
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "graph",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "nodes": graph.node_count,
                    "edges": graph.edge_count,
                    "persisted": should_persist
                }),
            )?;
        }

        Commands::GraphStats {
            target,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let graph = require_latest_graph(&store, &target)?;

            let report = build_graph_stats_report(&graph);

            if want_json {
                atlas_output::write_json_output(&report, output.as_deref())?;
            } else {
                atlas_output::print_human_graph_stats(&report);
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "graph-stats",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "nodes": report.node_count,
                    "edges": report.edge_count
                }),
            )?;
        }

        Commands::GraphSearch {
            target,
            kind,
            label_contains,
            min_degree,
            limit,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let graph = require_latest_graph(&store, &target)?;

            let search_kind = match kind {
                Some(value) => Some(parse_node_kind_loose(&value)?),
                None => None,
            };

            let result = graph_search(
                &graph,
                &GraphSearchRequest {
                    kind: search_kind,
                    label_contains,
                    min_degree,
                    limit,
                },
            );

            if want_json {
                atlas_output::write_json_output(&result, output.as_deref())?;
            } else {
                atlas_output::print_human_query_result(&result);
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "graph-search",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "matches": result.summary.total_matches,
                    "limit": limit
                }),
            )?;
        }

        Commands::Query {
            target,
            expression,
            limit,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let graph = require_latest_graph(&store, &target)?;

            let query = parse_query(&expression, limit)?;
            let result = execute_query(&graph, &query)?;

            if want_json {
                atlas_output::write_json_output(&result, output.as_deref())?;
            } else {
                atlas_output::print_human_query_result(&result);
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "query",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "expression": expression,
                    "matches": result.summary.total_matches
                }),
            )?;
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

fn build_graph_from_snapshots_and_context(
    config: &AppConfig,
    target: &str,
    dir: &Path,
    policy_path: Option<&Path>,
) -> Result<atlas_graph::ExposureGraph> {
    let snapshots = atlas_snapshot::load_all_snapshots_for_target(dir, target)?;
    if snapshots.is_empty() {
        bail!("no hay snapshots para construir el grafo de {target}");
    }

    let latest_snapshot = snapshots.last().cloned();
    let policy_loaded = load_policy(policy_path)?;

    let mut maybe_timeline = None;
    let mut maybe_collection = None;

    if snapshots.len() >= 2 {
        let mut timeline =
            atlas_drift::build_timeline_report(target, &snapshots, policy_loaded.as_ref())?;

        let registry = default_registry_for(&config.plugins.enabled);
        registry.apply_timeline_report(&mut timeline);

        let mut clusters_by_transition = Vec::new();
        for transition in &timeline.transitions {
            let clusters = atlas_correlation::correlate_report(&transition.report)?;
            clusters_by_transition.push(clusters);
        }

        let collection = atlas_episodes::build_episodes_for_timeline(
            target,
            &timeline,
            &clusters_by_transition,
        )?;

        maybe_timeline = Some(timeline);
        maybe_collection = Some(collection);
    }

    Ok(atlas_graph::build_full_graph(
        target,
        latest_snapshot.as_ref(),
        maybe_timeline.as_ref(),
        maybe_collection.as_ref(),
    ))
}

fn require_latest_graph(store: &AtlasStore, target: &str) -> Result<atlas_graph::ExposureGraph> {
    store
        .load_latest_graph(target)?
        .ok_or_else(|| anyhow::anyhow!("no existe un grafo persistido para {target}; ejecuta primero `atlas graph {target} --persist`"))
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

fn parse_node_kind_loose(input: &str) -> Result<atlas_graph::NodeKind> {
    match input.to_ascii_lowercase().as_str() {
        "target" | "targets" => Ok(atlas_graph::NodeKind::Target),
        "subdomain" | "subdomains" => Ok(atlas_graph::NodeKind::Subdomain),
        "ip" | "ips" => Ok(atlas_graph::NodeKind::Ip),
        "service" | "services" => Ok(atlas_graph::NodeKind::Service),
        "technology" | "technologies" | "tech" => Ok(atlas_graph::NodeKind::Technology),
        "episode" | "episodes" => Ok(atlas_graph::NodeKind::Episode),
        other => bail!("node kind no soportado: {other}"),
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
}

fn print_human_episode_collection(collection: &atlas_episodes::EpisodeCollection) {
    println!("Target: {}", collection.target);
    println!("Episodes: {}", collection.episode_count);

    if collection.episodes.is_empty() {
        println!();
        println!("No se detectaron episodios compuestos.");
        return;
    }

    println!();
    println!("Episodios:");
    for episode in &collection.episodes {
        println!(
            "  - [{}] {} | score={} | criticidad={} | estado={} | recursos={}",
            episode.severity,
            episode.title,
            episode.score,
            episode.criticality,
            episode.state,
            episode.resource_count
        );
        println!("      kind={}", episode.kind);
        println!("      summary={}", episode.summary);

        if !episode.resources.is_empty() {
            println!("      resources={}", episode.resources.join(", "));
        }

        for line in &episode.explanation {
            println!("      explicación: {}", line);
        }
    }
}
