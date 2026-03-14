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
    /// Ejecuta un escaneo de descubrimiento sobre un objetivo
    Scan {
        /// Dominio objetivo
        target: String,

        /// Imprime el resultado en JSON
        #[arg(long)]
        json: bool,

        /// Guarda la salida JSON en un archivo
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Ejecuta un escaneo y guarda un snapshot en disco
    Snapshot {
        /// Dominio objetivo
        target: String,

        /// Directorio base donde se almacenarán los snapshots
        #[arg(long, default_value = ".snapshots")]
        dir: PathBuf,
    },

    /// Compara dos snapshots y muestra las diferencias
    Diff {
        /// Snapshot anterior
        older: PathBuf,

        /// Snapshot más reciente
        newer: PathBuf,

        /// Imprime el diff en JSON
        #[arg(long)]
        json: bool,

        /// Guarda el diff JSON en un archivo
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Clasifica el diff como hallazgos de Security Drift
    Drift {
        /// Snapshot anterior
        older: PathBuf,

        /// Snapshot más reciente
        newer: PathBuf,

        /// Política de baseline / allowlist en JSON
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Imprime el reporte de drift en JSON
        #[arg(long)]
        json: bool,

        /// Guarda el reporte de drift JSON en un archivo
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

    if !report.new_ips.is_empty() {
        println!();
        println!("IPs nuevas:");
        for ip in &report.new_ips {
            println!("  + {ip}");
        }
    }

    if !report.removed_ips.is_empty() {
        println!();
        println!("IPs removidas:");
        for ip in &report.removed_ips {
            println!("  - {ip}");
        }
    }

    if !report.new_subdomains.is_empty() {
        println!();
        println!("Subdominios nuevos:");
        for sub in &report.new_subdomains {
            println!("  + {sub}");
        }
    }

    if !report.removed_subdomains.is_empty() {
        println!();
        println!("Subdominios removidos:");
        for sub in &report.removed_subdomains {
            println!("  - {sub}");
        }
    }

    if !report.new_services.is_empty() {
        println!();
        println!("Servicios nuevos:");
        for service in &report.new_services {
            let server = service.server.as_deref().unwrap_or("desconocido");
            println!(
                "  + {} [{}] status={} server={}",
                service.url, service.scheme, service.status, server
            );
        }
    }

    if !report.removed_services.is_empty() {
        println!();
        println!("Servicios removidos:");
        for service in &report.removed_services {
            let server = service.server.as_deref().unwrap_or("desconocido");
            println!(
                "  - {} [{}] status={} server={}",
                service.url, service.scheme, service.status, server
            );
        }
    }

    if !report.changed_services.is_empty() {
        println!();
        println!("Servicios modificados:");
        for change in &report.changed_services {
            println!("  * {}", change.url);
            println!(
                "      status: {} -> {}",
                change.before_status, change.after_status
            );
            println!(
                "      server: {} -> {}",
                change.before_server.as_deref().unwrap_or("desconocido"),
                change.after_server.as_deref().unwrap_or("desconocido")
            );
        }
    }

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
