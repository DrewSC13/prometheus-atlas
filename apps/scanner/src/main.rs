use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "atlas")]
#[command(about = "Prometheus Atlas - Security Drift Scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            json,
            output,
        } => {
            let result = atlas_discovery::scan_target(&target).await?;

            if json {
                atlas_output::write_json_output(&result, output.as_deref())?;
            } else {
                atlas_output::print_human_scan_result(&result);
            }
        }

        Commands::Snapshot { target, dir } => {
            let result = atlas_discovery::scan_target(&target).await?;
            let snapshot = atlas_snapshot::Snapshot::new(result);
            let path = atlas_snapshot::save_snapshot(&snapshot, &dir)?;

            println!("Snapshot guardado en: {}", path.display());
        }

        Commands::Diff {
            older,
            newer,
            json,
            output,
        } => {
            let older_snapshot = atlas_snapshot::load_snapshot(&older)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer)?;
            let report = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

            if json {
                atlas_output::write_json_output(&report, output.as_deref())?;
            } else {
                print_human_diff_report(&report);
            }
        }

        Commands::Drift {
            older,
            newer,
            policy,
            json,
            output,
        } => {
            let older_snapshot = atlas_snapshot::load_snapshot(&older)?;
            let newer_snapshot = atlas_snapshot::load_snapshot(&newer)?;
            let diff = atlas_diff::diff_snapshots(&older_snapshot, &newer_snapshot);

            let policy = match policy {
                Some(path) => Some(atlas_drift::DriftPolicy::load_from_path(&path)?),
                None => None,
            };

            let drift = atlas_drift::analyze_diff_with_policy(&diff, policy.as_ref());

            if json {
                atlas_output::write_json_output(&drift, output.as_deref())?;
            } else {
                print_human_drift_report(&drift);
            }
        }

        Commands::Timeline {
            target,
            dir,
            policy,
            json,
            output,
        } => {
            let snapshots = atlas_snapshot::load_all_snapshots_for_target(&dir, &target)?;

            let policy = match policy {
                Some(path) => Some(atlas_drift::DriftPolicy::load_from_path(&path)?),
                None => None,
            };

            let timeline =
                atlas_drift::build_timeline_report(&target, &snapshots, policy.as_ref())?;

            if json {
                atlas_output::write_json_output(&timeline, output.as_deref())?;
            } else {
                print_human_timeline_report(&timeline);
            }
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
            "  - recurso={} | severidad={} | score={}",
            group.resource, group.highest_severity, group.total_score
        );

        for finding in &group.findings {
            println!(
                "      [{}] {} | categoría={} | entorno={} | score={}",
                finding.severity,
                finding.title,
                finding.category,
                finding.environment,
                finding.score
            );
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
