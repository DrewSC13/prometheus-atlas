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
    }

    Ok(())
}
