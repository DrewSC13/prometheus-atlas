use anyhow::{anyhow, bail, Context, Result};
use atlas_config::AppConfig;
use atlas_jobs::AtlasJob;
use atlas_plugins::default_registry_for;
use atlas_query::{
    build_graph_stats_report, execute_query, graph_search, parse_query, GraphSearchRequest,
};
use atlas_report::build_executive_report;
use atlas_scheduler::select_due_jobs;
use atlas_store::{AtlasStore, ExportFormat};
use chrono::Utc;
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::{json, Value};
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

    Profiles {
        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
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

    QuerySave {
        name: String,
        expression: String,
    },

    QueryList {
        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    QueryRun {
        name: String,
        target: String,

        #[arg(long, default_value_t = 25)]
        limit: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    QueryRunAll {
        target: String,

        #[arg(long, default_value_t = 25)]
        limit: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    QueryDelete {
        name: String,
    },

    BaselineApprove {
        resource: String,
    },

    BaselineRevoke {
        resource: String,
    },

    BaselineList {
        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    PolicyCheck {
        #[arg(long)]
        policy: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    JobCreate {
        target: String,

        #[arg(long)]
        profile: String,

        #[arg(long)]
        interval: u64,

        #[arg(long)]
        policy: Option<PathBuf>,
    },

    JobList {
        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    JobEnable {
        job_id: String,
    },

    JobDisable {
        job_id: String,
    },

    JobRun {
        job_id: String,

        #[arg(long)]
        persist: bool,
    },

    JobDelete {
        job_id: String,
    },

    JobHistory {
        #[arg(long)]
        target: Option<String>,

        #[arg(long)]
        job_id: Option<String>,

        #[arg(long, default_value_t = 100)]
        limit: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    SchedulerRun {
        #[arg(long)]
        persist: bool,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    SchedulerStatus {
        #[arg(long)]
        json: bool,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Report {
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

    Rebuild {
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

    FindingList {
        target: String,

        #[arg(long)]
        op_state: Option<String>,
    },

    FindingAck {
        finding_id: String,
    },

    FindingResolve {
        finding_id: String,
    },

    FindingAccept {
        finding_id: String,
    },

    FindingAssign {
        finding_id: String,
        owner: String,
    },

    FindingNote {
        finding_id: String,
        note: String,
    },

    ReportFindings {
        target: String,
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

#[derive(Debug, Clone)]
struct LoadedSnapshotInput {
    path: PathBuf,
    snapshot: atlas_snapshot::Snapshot,
}

struct AnalysisBundle {
    snapshot_inputs: Vec<LoadedSnapshotInput>,
    timeline: Option<atlas_drift::TimelineReport>,
    episodes: Option<atlas_episodes::EpisodeCollection>,
    graph: atlas_graph::ExposureGraph,
}

#[derive(Debug, Clone, Serialize)]
struct SavedQueryExecutionSummary {
    name: String,
    expression: String,
    total_matches: usize,
    returned_matches: usize,
    top_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SavedQueryBatchSummary {
    target: String,
    total_queries: usize,
    matched_queries: usize,
    results: Vec<SavedQueryExecutionSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyCheckSummary {
    path: String,
    valid: bool,
    details: Vec<String>,
    allowlisted_resources: usize,
    allowlisted_categories: usize,
    critical_resources: usize,
    critical_patterns: usize,
    environment_overrides: usize,
    temporary_exceptions: usize,
    baseline_resources: usize,
    baseline_categories: usize,
}

#[derive(Debug, Clone, Serialize)]
struct BaselineListSummary {
    total: usize,
    resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct JobHistoryEntry {
    created_at: String,
    command: String,
    target: Option<String>,
    job_id: Option<String>,
    metadata: Value,
}

#[derive(Debug, Clone, Serialize)]
struct SchedulerStatusSummary {
    total_jobs: usize,
    enabled_jobs: usize,
    disabled_jobs: usize,
    due_jobs: usize,
    jobs: Vec<JobStatusItem>,
}

#[derive(Debug, Clone, Serialize)]
struct JobStatusItem {
    job_id: String,
    target: String,
    profile: String,
    interval_seconds: u64,
    enabled: bool,
    policy_path: Option<String>,
    last_run_at: Option<String>,
    due_now: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SchedulerRunSummary {
    evaluated_jobs: usize,
    due_jobs: usize,
    executed_jobs: usize,
    results: Vec<SchedulerRunItem>,
}

#[derive(Debug, Clone, Serialize)]
struct SchedulerRunItem {
    job_id: String,
    target: String,
    snapshot_path: String,
    persisted: bool,
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

        Commands::Profiles {
            json: want_json,
            output,
        } => {
            let started = Instant::now();

            if want_json {
                atlas_output::write_json_output(&config.profiles, output.as_deref())?;
            } else {
                println!("Profiles disponibles:");
                for profile in &config.profiles {
                    let ports = profile
                        .ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "- {} | ports=[{}] | timeout_ms={}",
                        profile.name, ports, profile.timeout_ms
                    );
                }
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "profiles",
                None,
                started.elapsed().as_millis(),
                json!({"profiles": config.profiles.len()}),
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

        Commands::QuerySave { name, expression } => {
            let started = Instant::now();

            parse_query(&expression, 25)
                .with_context(|| format!("query inválida para guardar: {}", expression))?;

            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.save_saved_query(&name, &expression)?;

            println!("Query guardada: {}", name);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "query-save",
                None,
                started.elapsed().as_millis(),
                json!({
                    "name": name,
                    "expression": expression
                }),
            )?;
        }

        Commands::QueryList {
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let queries = store.list_saved_queries()?;

            if want_json {
                atlas_output::write_json_output(&queries, output.as_deref())?;
            } else if queries.is_empty() {
                println!("No hay queries guardadas.");
            } else {
                println!("Queries guardadas:");
                for item in queries {
                    println!("- {} | {}", item.name, item.expression);
                }
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "query-list",
                None,
                started.elapsed().as_millis(),
                json!({}),
            )?;
        }

        Commands::QueryRun {
            name,
            target,
            limit,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let saved = store
                .load_saved_query(&name)?
                .ok_or_else(|| anyhow!("query guardada no encontrada: {name}"))?;

            let graph = require_latest_graph(&store, &target)?;
            let query = parse_query(&saved.expression, limit)?;
            let result = execute_query(&graph, &query)?;

            if want_json {
                atlas_output::write_json_output(&result, output.as_deref())?;
            } else {
                println!("Saved query: {}", saved.name);
                atlas_output::print_human_query_result(&result);
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "query-run",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "name": saved.name,
                    "matches": result.summary.total_matches
                }),
            )?;
        }

        Commands::QueryRunAll {
            target,
            limit,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let saved_queries = store.list_saved_queries()?;
            if saved_queries.is_empty() {
                if want_json {
                    let empty = SavedQueryBatchSummary {
                        target: target.clone(),
                        total_queries: 0,
                        matched_queries: 0,
                        results: Vec::new(),
                    };
                    atlas_output::write_json_output(&empty, output.as_deref())?;
                } else {
                    println!("No hay queries guardadas.");
                }

                record_telemetry_if_enabled(
                    &config,
                    Some(&store),
                    "query-run-all",
                    Some(&target),
                    started.elapsed().as_millis(),
                    json!({
                        "total_queries": 0,
                        "matched_queries": 0
                    }),
                )?;
            } else {
                let graph = require_latest_graph(&store, &target)?;
                let mut results = Vec::new();

                for saved in saved_queries {
                    let query = parse_query(&saved.expression, limit)?;
                    let result = execute_query(&graph, &query)?;

                    results.push(SavedQueryExecutionSummary {
                        name: saved.name,
                        expression: saved.expression,
                        total_matches: result.summary.total_matches,
                        returned_matches: result.summary.returned_matches,
                        top_labels: result
                            .matched_nodes
                            .iter()
                            .take(5)
                            .map(|node| node.label.clone())
                            .collect(),
                    });
                }

                let matched_queries = results.iter().filter(|item| item.total_matches > 0).count();

                let summary = SavedQueryBatchSummary {
                    target: target.clone(),
                    total_queries: results.len(),
                    matched_queries,
                    results,
                };

                if want_json {
                    atlas_output::write_json_output(&summary, output.as_deref())?;
                } else {
                    print_human_saved_query_batch(&summary);
                }

                record_telemetry_if_enabled(
                    &config,
                    Some(&store),
                    "query-run-all",
                    Some(&target),
                    started.elapsed().as_millis(),
                    json!({
                        "total_queries": summary.total_queries,
                        "matched_queries": summary.matched_queries
                    }),
                )?;
            }
        }

        Commands::QueryDelete { name } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let existing = store.load_saved_query(&name)?;
            if existing.is_none() {
                bail!("query guardada no encontrada: {name}");
            }

            store.delete_saved_query(&name)?;
            println!("Query eliminada: {}", name);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "query-delete",
                None,
                started.elapsed().as_millis(),
                json!({
                    "name": name
                }),
            )?;
        }

        Commands::BaselineApprove { resource } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.baseline_approve(&resource)?;
            println!("Resource aprobado para baseline: {}", resource);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "baseline-approve",
                Some(&resource),
                started.elapsed().as_millis(),
                json!({"resource": resource}),
            )?;
        }

        Commands::BaselineRevoke { resource } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            store.baseline_revoke(&resource)?;
            println!("Resource removido de baseline: {}", resource);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "baseline-revoke",
                Some(&resource),
                started.elapsed().as_millis(),
                json!({"resource": resource}),
            )?;
        }

        Commands::BaselineList {
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let resources = store.baseline_list()?;

            let summary = BaselineListSummary {
                total: resources.len(),
                resources,
            };

            if want_json {
                atlas_output::write_json_output(&summary, output.as_deref())?;
            } else if summary.resources.is_empty() {
                println!("No hay recursos aprobados en baseline.");
            } else {
                println!("Baseline aprobado:");
                for resource in &summary.resources {
                    println!("- {}", resource);
                }
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "baseline-list",
                None,
                started.elapsed().as_millis(),
                json!({"total": summary.total}),
            )?;
        }

        Commands::PolicyCheck {
            policy,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let loaded = atlas_drift::DriftPolicy::load_from_path(&policy)?;
            loaded.validate()?;

            let summary = PolicyCheckSummary {
                path: policy.display().to_string(),
                valid: true,
                details: loaded.describe(),
                allowlisted_resources: loaded.allowlisted_resources.len(),
                allowlisted_categories: loaded.allowlisted_categories.len(),
                critical_resources: loaded.critical_resources.len(),
                critical_patterns: loaded.critical_patterns.len(),
                environment_overrides: loaded.environment_overrides.len(),
                temporary_exceptions: loaded.temporary_exceptions.len(),
                baseline_resources: loaded.baseline_resources.len(),
                baseline_categories: loaded.baseline_categories.len(),
            };

            if want_json {
                atlas_output::write_json_output(&summary, output.as_deref())?;
            } else {
                print_human_policy_check(&summary);
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "policy-check",
                None,
                started.elapsed().as_millis(),
                json!({
                    "path": summary.path,
                    "valid": summary.valid
                }),
            )?;
        }

        Commands::JobCreate {
            target,
            profile,
            interval,
            policy,
        } => {
            let started = Instant::now();
            config.profile(&profile)?;

            if interval == 0 {
                bail!("interval debe ser > 0");
            }

            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let job_id = format!(
                "job:{}:{}",
                target,
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            );

            let job = AtlasJob {
                job_id: job_id.clone(),
                target: target.clone(),
                profile: profile.clone(),
                interval_seconds: interval,
                enabled: true,
                policy_path: policy.as_ref().map(|p| p.display().to_string()),
                last_run_at: None,
                created_at: Utc::now(),
            };

            store.insert_job(&job)?;

            println!("Job creado: {}", job_id);
            println!("  - target: {}", target);
            println!("  - profile: {}", profile);
            println!("  - interval_seconds: {}", interval);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-create",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "job_id": job_id,
                    "profile": profile,
                    "interval_seconds": interval
                }),
            )?;
        }

        Commands::JobList {
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;
            let jobs = store.list_jobs()?;

            if want_json {
                atlas_output::write_json_output(&jobs, output.as_deref())?;
            } else if jobs.is_empty() {
                println!("No hay jobs configurados.");
            } else {
                println!("Jobs configurados:");
                for job in jobs {
                    println!(
                        "- {} | target={} | profile={} | interval={}s | enabled={} | last_run_at={}",
                        job.job_id,
                        job.target,
                        job.profile,
                        job.interval_seconds,
                        if job.enabled { "yes" } else { "no" },
                        job.last_run_at
                            .map(|d| d.to_rfc3339())
                            .unwrap_or_else(|| "-".to_string())
                    );
                }
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-list",
                None,
                started.elapsed().as_millis(),
                json!({}),
            )?;
        }

        Commands::JobEnable { job_id } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let mut job = load_job_by_id(&store, &job_id)?;
            job.enabled = true;
            store.insert_job(&job)?;

            println!("Job habilitado: {}", job_id);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-enable",
                Some(&job.target),
                started.elapsed().as_millis(),
                json!({ "job_id": job_id }),
            )?;
        }

        Commands::JobDisable { job_id } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let mut job = load_job_by_id(&store, &job_id)?;
            job.enabled = false;
            store.insert_job(&job)?;

            println!("Job deshabilitado: {}", job_id);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-disable",
                Some(&job.target),
                started.elapsed().as_millis(),
                json!({ "job_id": job_id }),
            )?;
        }

        Commands::JobRun { job_id, persist } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let job = load_job_by_id(&store, &job_id)?;
            let snapshot_path = run_job_once(&config, &store, &job, persist).await?;
            store.touch_job_run(&job.job_id)?;

            println!("Job ejecutado: {}", job.job_id);
            println!("  - target: {}", job.target);
            println!("  - snapshot: {}", snapshot_path.display());

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-run",
                Some(&job.target),
                started.elapsed().as_millis(),
                json!({
                    "job_id": job.job_id,
                    "snapshot_path": snapshot_path.display().to_string(),
                    "persist": persist || config.drift.persist_by_default
                }),
            )?;
        }

        Commands::JobDelete { job_id } => {
            let started = Instant::now();
            let db_path = PathBuf::from(&config.storage.path);
            let store = AtlasStore::open(&db_path)?;
            store.initialize()?;

            let job = load_job_by_id(&store, &job_id)?;
            delete_job_record(&db_path, &job_id)?;

            println!("Job eliminado: {}", job_id);

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-delete",
                Some(&job.target),
                started.elapsed().as_millis(),
                json!({ "job_id": job_id }),
            )?;
        }

        Commands::JobHistory {
            target,
            job_id,
            limit,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let history = build_job_history(&store, limit, target.as_deref(), job_id.as_deref())?;

            if want_json {
                atlas_output::write_json_output(&history, output.as_deref())?;
            } else if history.is_empty() {
                println!("No hay historial de jobs.");
            } else {
                println!("Historial de jobs:");
                for item in &history {
                    println!(
                        "- {} | command={} | target={} | job_id={}",
                        item.created_at,
                        item.command,
                        item.target.clone().unwrap_or_else(|| "-".to_string()),
                        item.job_id.clone().unwrap_or_else(|| "-".to_string())
                    );
                }
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "job-history",
                target.as_deref(),
                started.elapsed().as_millis(),
                json!({
                    "limit": limit
                }),
            )?;
        }

        Commands::SchedulerRun {
            persist,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let jobs = store.list_jobs()?;
            let due_jobs = select_due_jobs(&jobs, Utc::now());

            let mut results = Vec::new();
            for job in &due_jobs {
                let snapshot_path = run_job_once(&config, &store, job, persist).await?;
                store.touch_job_run(&job.job_id)?;

                results.push(SchedulerRunItem {
                    job_id: job.job_id.clone(),
                    target: job.target.clone(),
                    snapshot_path: snapshot_path.display().to_string(),
                    persisted: persist || config.drift.persist_by_default,
                });

                record_telemetry_if_enabled(
                    &config,
                    Some(&store),
                    "job-run",
                    Some(&job.target),
                    0,
                    json!({
                        "job_id": job.job_id,
                        "snapshot_path": snapshot_path.display().to_string(),
                        "trigger": "scheduler"
                    }),
                )?;
            }

            let summary = SchedulerRunSummary {
                evaluated_jobs: jobs.len(),
                due_jobs: due_jobs.len(),
                executed_jobs: results.len(),
                results,
            };

            if want_json {
                atlas_output::write_json_output(&summary, output.as_deref())?;
            } else {
                println!("Scheduler run:");
                println!("  - evaluated_jobs: {}", summary.evaluated_jobs);
                println!("  - due_jobs: {}", summary.due_jobs);
                println!("  - executed_jobs: {}", summary.executed_jobs);

                if !summary.results.is_empty() {
                    println!();
                    println!("Resultados:");
                    for item in &summary.results {
                        println!(
                            "- {} | target={} | snapshot={}",
                            item.job_id, item.target, item.snapshot_path
                        );
                    }
                }
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "scheduler-run",
                None,
                started.elapsed().as_millis(),
                json!({
                    "evaluated_jobs": summary.evaluated_jobs,
                    "due_jobs": summary.due_jobs,
                    "executed_jobs": summary.executed_jobs
                }),
            )?;
        }

        Commands::SchedulerStatus {
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let store = AtlasStore::open(Path::new(&config.storage.path))?;
            store.initialize()?;

            let jobs = store.list_jobs()?;
            let now = Utc::now();
            let due_jobs = select_due_jobs(&jobs, now);

            let summary = SchedulerStatusSummary {
                total_jobs: jobs.len(),
                enabled_jobs: jobs.iter().filter(|j| j.enabled).count(),
                disabled_jobs: jobs.iter().filter(|j| !j.enabled).count(),
                due_jobs: due_jobs.len(),
                jobs: jobs
                    .iter()
                    .map(|job| JobStatusItem {
                        job_id: job.job_id.clone(),
                        target: job.target.clone(),
                        profile: job.profile.clone(),
                        interval_seconds: job.interval_seconds,
                        enabled: job.enabled,
                        policy_path: job.policy_path.clone(),
                        last_run_at: job.last_run_at.map(|d| d.to_rfc3339()),
                        due_now: due_jobs.iter().any(|item| item.job_id == job.job_id),
                    })
                    .collect(),
            };

            if want_json {
                atlas_output::write_json_output(&summary, output.as_deref())?;
            } else {
                print_human_scheduler_status(&summary);
            }

            record_telemetry_if_enabled(
                &config,
                Some(&store),
                "scheduler-status",
                None,
                started.elapsed().as_millis(),
                json!({
                    "total_jobs": summary.total_jobs,
                    "due_jobs": summary.due_jobs
                }),
            )?;
        }

        Commands::Report {
            target,
            dir,
            policy,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let bundle = build_analysis_bundle(&config, &target, &dir, policy.as_deref())?;

            let snapshots = bundle
                .snapshot_inputs
                .iter()
                .map(|item| item.snapshot.clone())
                .collect::<Vec<_>>();

            let report = build_executive_report(
                &target,
                &snapshots,
                bundle.timeline.as_ref(),
                bundle.episodes.as_ref(),
                &bundle.graph,
                policy.is_some(),
            );

            if want_json {
                atlas_output::write_json_output(&report, output.as_deref())?;
            } else {
                atlas_output::print_human_executive_report(&report);
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "report",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "snapshots": report.snapshot_count,
                    "findings": report.overview.total_findings,
                    "score": report.overview.total_score
                }),
            )?;
        }

        Commands::Rebuild {
            target,
            dir,
            policy,
            persist,
            json: want_json,
            output,
        } => {
            let started = Instant::now();
            let bundle = build_analysis_bundle(&config, &target, &dir, policy.as_deref())?;
            let should_persist = persist || config.drift.persist_by_default;

            let transitions = bundle
                .timeline
                .as_ref()
                .map(|timeline| timeline.transition_count)
                .unwrap_or(0);

            let episodes = bundle
                .episodes
                .as_ref()
                .map(|collection| collection.episode_count)
                .unwrap_or(0);

            if should_persist {
                let store = AtlasStore::open(Path::new(&config.storage.path))?;
                store.initialize()?;

                for item in &bundle.snapshot_inputs {
                    store.register_snapshot(&item.path, &item.snapshot)?;
                }

                if let Some(timeline) = &bundle.timeline {
                    for (pair, transition) in bundle
                        .snapshot_inputs
                        .windows(2)
                        .zip(timeline.transitions.iter())
                    {
                        let older = &pair[0];
                        let newer = &pair[1];
                        store.register_drift_report(
                            &target,
                            &older.path,
                            &newer.path,
                            policy.as_deref(),
                            &transition.report,
                        )?;
                    }
                }

                if let Some(collection) = &bundle.episodes {
                    store.store_episodes(&target, &collection.episodes)?;
                }

                store.store_graph(&target, &bundle.graph)?;
            }

            let summary = json!({
                "target": target,
                "snapshots": bundle.snapshot_inputs.len(),
                "transitions": transitions,
                "episodes": episodes,
                "graph_nodes": bundle.graph.node_count,
                "graph_edges": bundle.graph.edge_count,
                "persisted": should_persist
            });

            if want_json {
                atlas_output::write_json_output(&summary, output.as_deref())?;
            } else {
                println!("Rebuild completado para {}", target);
                println!("  - Snapshots: {}", bundle.snapshot_inputs.len());
                println!("  - Transitions: {}", transitions);
                println!("  - Episodes: {}", episodes);
                println!("  - Graph nodes: {}", bundle.graph.node_count);
                println!("  - Graph edges: {}", bundle.graph.edge_count);
                println!(
                    "  - Persisted: {}",
                    if should_persist { "yes" } else { "no" }
                );
            }

            let store = AtlasStore::open(Path::new(&config.storage.path)).ok();
            record_telemetry_if_enabled(
                &config,
                store.as_ref(),
                "rebuild",
                Some(&target),
                started.elapsed().as_millis(),
                json!({
                    "snapshots": bundle.snapshot_inputs.len(),
                    "transitions": transitions,
                    "episodes": episodes,
                    "graph_nodes": bundle.graph.node_count,
                    "graph_edges": bundle.graph.edge_count,
                    "persisted": should_persist
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

        Commands::FindingList { target, op_state } => {
            let db_path = PathBuf::from(&config.storage.path);
            let items = finding_list(&db_path, &target, op_state.as_deref())?;

            println!("Target: {}", target);
            println!("Findings operativos: {}", items.len());

            if items.is_empty() {
                println!();
                println!("No se encontraron resultados.");
            } else {
                println!();
                println!("Resultados:");
                for item in items {
                    println!(
                        "- [{}][{}] {} | id={} | score={}",
                        item.severity, item.op_state, item.title, item.finding_id, item.score
                    );
                    println!("    category={}", item.category);
                    println!("    resource={}", item.resource);
                    println!("    analytic_state={}", item.analytic_state);
                }
            }
        }

        Commands::FindingAck { finding_id } => {
            let db_path = PathBuf::from(&config.storage.path);
            set_finding_op_state(&db_path, &finding_id, Some("acknowledged"), None, None)?;
            println!("Finding actualizado: {} -> acknowledged", finding_id);
        }

        Commands::FindingResolve { finding_id } => {
            let db_path = PathBuf::from(&config.storage.path);
            set_finding_op_state(&db_path, &finding_id, Some("resolved"), None, None)?;
            println!("Finding actualizado: {} -> resolved", finding_id);
        }

        Commands::FindingAccept { finding_id } => {
            let db_path = PathBuf::from(&config.storage.path);
            set_finding_op_state(&db_path, &finding_id, Some("accepted"), None, None)?;
            println!("Finding actualizado: {} -> accepted", finding_id);
        }

        Commands::FindingAssign { finding_id, owner } => {
            let db_path = PathBuf::from(&config.storage.path);
            set_finding_op_state(&db_path, &finding_id, None, Some(&owner), None)?;
            println!("Finding asignado: {} -> {}", finding_id, owner);
        }

        Commands::FindingNote { finding_id, note } => {
            let db_path = PathBuf::from(&config.storage.path);
            set_finding_op_state(&db_path, &finding_id, None, None, Some(&note))?;
            println!("Nota agregada a {}.", finding_id);
        }

        Commands::ReportFindings { target } => {
            let db_path = PathBuf::from(&config.storage.path);
            let items = finding_list(&db_path, &target, None)?;

            println!("Target: {}", target);
            println!("Resumen operativo de findings:");

            let open = items.iter().filter(|i| i.op_state == "open").count();
            let ack = items
                .iter()
                .filter(|i| i.op_state == "acknowledged")
                .count();
            let accepted = items.iter().filter(|i| i.op_state == "accepted").count();
            let resolved = items.iter().filter(|i| i.op_state == "resolved").count();

            println!("  - open: {}", open);
            println!("  - acknowledged: {}", ack);
            println!("  - accepted: {}", accepted);
            println!("  - resolved: {}", resolved);
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
    let bundle = build_analysis_bundle(config, target, dir, policy_path)?;
    Ok(bundle.graph)
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

fn require_latest_graph(store: &AtlasStore, target: &str) -> Result<atlas_graph::ExposureGraph> {
    store.load_latest_graph(target)?.ok_or_else(|| {
        anyhow!("no existe un grafo persistido para {target}; ejecuta primero `atlas graph {target} --persist`")
    })
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

fn load_job_by_id(store: &AtlasStore, job_id: &str) -> Result<AtlasJob> {
    store
        .list_jobs()?
        .into_iter()
        .find(|job| job.job_id == job_id)
        .ok_or_else(|| anyhow!("job no encontrado: {job_id}"))
}

async fn run_job_once(
    config: &AppConfig,
    store: &AtlasStore,
    job: &AtlasJob,
    persist_flag: bool,
) -> Result<PathBuf> {
    config.profile(&job.profile)?;

    let result = atlas_discovery::scan_target(&job.target).await?;
    let snapshot = atlas_snapshot::Snapshot::new(result);
    let dir = PathBuf::from(".snapshots");
    let snapshot_path = atlas_snapshot::save_snapshot(&snapshot, &dir)?;

    let should_persist = persist_flag || config.drift.persist_by_default;
    if should_persist {
        store.register_snapshot(&snapshot_path, &snapshot)?;
    }

    if should_persist {
        let bundle = build_analysis_bundle(
            config,
            &job.target,
            &dir,
            job.policy_path.as_deref().map(Path::new),
        )?;

        if let Some(timeline) = &bundle.timeline {
            for (pair, transition) in bundle
                .snapshot_inputs
                .windows(2)
                .zip(timeline.transitions.iter())
            {
                let older = &pair[0];
                let newer = &pair[1];
                store.register_drift_report(
                    &job.target,
                    &older.path,
                    &newer.path,
                    job.policy_path.as_deref().map(Path::new),
                    &transition.report,
                )?;
            }
        }

        if let Some(collection) = &bundle.episodes {
            store.store_episodes(&job.target, &collection.episodes)?;
        }

        store.store_graph(&job.target, &bundle.graph)?;
    }

    Ok(snapshot_path)
}

fn delete_job_record(db_path: &Path, job_id: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;
    conn.execute("DELETE FROM jobs WHERE job_id = ?1", params![job_id])?;
    Ok(())
}

fn build_job_history(
    store: &AtlasStore,
    limit: usize,
    target_filter: Option<&str>,
    job_id_filter: Option<&str>,
) -> Result<Vec<JobHistoryEntry>> {
    let events = store.list_telemetry(limit)?;
    let mut items = Vec::new();

    for event in events {
        if !matches!(
            event.name.as_str(),
            "job-create"
                | "job-enable"
                | "job-disable"
                | "job-delete"
                | "job-run"
                | "scheduler-run"
                | "scheduler-status"
        ) {
            continue;
        }

        let metadata =
            serde_json::from_str::<Value>(&event.metadata_json).unwrap_or_else(|_| json!({}));

        let metadata_job_id = metadata
            .get("job_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(filter) = target_filter {
            if event.target.as_deref() != Some(filter) {
                continue;
            }
        }

        if let Some(filter) = job_id_filter {
            if metadata_job_id.as_deref() != Some(filter) {
                continue;
            }
        }

        items.push(JobHistoryEntry {
            created_at: event.created_at,
            command: event.name,
            target: event.target,
            job_id: metadata_job_id,
            metadata,
        });
    }

    Ok(items)
}

#[derive(Debug, Clone)]
struct FindingOperationalItem {
    finding_id: String,
    severity: String,
    title: String,
    category: String,
    resource: String,
    score: u32,
    analytic_state: String,
    op_state: String,
}

fn ensure_operational_findings_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS finding_ops (
            finding_id TEXT PRIMARY KEY,
            op_state TEXT NOT NULL DEFAULT 'open',
            owner TEXT,
            note TEXT,
            updated_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn finding_exists(conn: &Connection, finding_id: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM findings WHERE finding_id = ?1")?;
    let count: i64 = stmt.query_row([finding_id], |row| row.get(0))?;
    Ok(count > 0)
}

fn set_finding_op_state(
    db_path: &Path,
    finding_id: &str,
    op_state: Option<&str>,
    owner: Option<&str>,
    note: Option<&str>,
) -> Result<()> {
    let conn = Connection::open(db_path)?;
    ensure_operational_findings_schema(&conn)?;

    if !finding_exists(&conn, finding_id)? {
        bail!("finding no encontrado: {finding_id}");
    }

    let current = conn.query_row(
        "SELECT op_state, owner, note FROM finding_ops WHERE finding_id = ?1",
        [finding_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    );

    let (current_state, current_owner, current_note) = match current {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => (None, None, None),
        Err(err) => return Err(err.into()),
    };

    let final_state = op_state
        .map(|s| s.to_string())
        .or(current_state)
        .unwrap_or_else(|| "open".to_string());

    let final_owner = owner.map(|s| s.to_string()).or(current_owner);
    let final_note = note.map(|s| s.to_string()).or(current_note);

    conn.execute(
        r#"
        INSERT INTO finding_ops (finding_id, op_state, owner, note, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(finding_id) DO UPDATE SET
            op_state = excluded.op_state,
            owner = excluded.owner,
            note = excluded.note,
            updated_at = excluded.updated_at
        "#,
        params![
            finding_id,
            final_state,
            final_owner,
            final_note,
            Utc::now().to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn finding_list(
    db_path: &Path,
    target: &str,
    op_state_filter: Option<&str>,
) -> Result<Vec<FindingOperationalItem>> {
    let conn = Connection::open(db_path)?;
    ensure_operational_findings_schema(&conn)?;

    let mut stmt = conn.prepare(
        r#"
        SELECT
            f.finding_id,
            f.severity,
            f.title,
            f.category,
            f.resource,
            f.score,
            f.state,
            COALESCE(o.op_state, 'open') AS op_state
        FROM findings f
        LEFT JOIN finding_ops o ON o.finding_id = f.finding_id
        WHERE f.target = ?1
        ORDER BY f.score DESC, f.created_at DESC
        "#,
    )?;

    let rows = stmt.query_map([target], |row| {
        Ok(FindingOperationalItem {
            finding_id: row.get(0)?,
            severity: row.get(1)?,
            title: row.get(2)?,
            category: row.get(3)?,
            resource: row.get(4)?,
            score: row.get::<_, i64>(5)? as u32,
            analytic_state: row.get(6)?,
            op_state: row.get(7)?,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    if let Some(filter) = op_state_filter {
        items.retain(|i| i.op_state.eq_ignore_ascii_case(filter));
    }

    Ok(items)
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

fn print_human_saved_query_batch(summary: &SavedQueryBatchSummary) {
    println!("Target: {}", summary.target);
    println!("Queries evaluadas: {}", summary.total_queries);
    println!("Queries con matches: {}", summary.matched_queries);

    if summary.results.is_empty() {
        println!();
        println!("No hay queries guardadas.");
        return;
    }

    println!();
    println!("Resultados por query:");
    for item in &summary.results {
        println!(
            "- {} | matches={} | returned={}",
            item.name, item.total_matches, item.returned_matches
        );
        println!("    expression={}", item.expression);

        if !item.top_labels.is_empty() {
            println!("    top={}", item.top_labels.join(", "));
        }
    }
}

fn print_human_policy_check(summary: &PolicyCheckSummary) {
    println!("Policy: {}", summary.path);
    println!("Válida: {}", if summary.valid { "sí" } else { "no" });

    println!();
    println!("Resumen:");
    println!(
        "  - allowlisted_resources: {}",
        summary.allowlisted_resources
    );
    println!(
        "  - allowlisted_categories: {}",
        summary.allowlisted_categories
    );
    println!("  - critical_resources: {}", summary.critical_resources);
    println!("  - critical_patterns: {}", summary.critical_patterns);
    println!(
        "  - environment_overrides: {}",
        summary.environment_overrides
    );
    println!("  - temporary_exceptions: {}", summary.temporary_exceptions);
    println!("  - baseline_resources: {}", summary.baseline_resources);
    println!("  - baseline_categories: {}", summary.baseline_categories);

    if !summary.details.is_empty() {
        println!();
        println!("Detalles:");
        for line in &summary.details {
            println!("  - {}", line);
        }
    }
}

fn print_human_scheduler_status(summary: &SchedulerStatusSummary) {
    println!("Scheduler status:");
    println!("  - total_jobs: {}", summary.total_jobs);
    println!("  - enabled_jobs: {}", summary.enabled_jobs);
    println!("  - disabled_jobs: {}", summary.disabled_jobs);
    println!("  - due_jobs: {}", summary.due_jobs);

    if summary.jobs.is_empty() {
        println!();
        println!("No hay jobs configurados.");
        return;
    }

    println!();
    println!("Jobs:");
    for item in &summary.jobs {
        println!(
            "- {} | target={} | profile={} | interval={}s | enabled={} | due_now={}",
            item.job_id,
            item.target,
            item.profile,
            item.interval_seconds,
            if item.enabled { "yes" } else { "no" },
            if item.due_now { "yes" } else { "no" }
        );
        println!(
            "    last_run_at={}",
            item.last_run_at.clone().unwrap_or_else(|| "-".to_string())
        );
        if let Some(policy_path) = &item.policy_path {
            println!("    policy={}", policy_path);
        }
    }
}
