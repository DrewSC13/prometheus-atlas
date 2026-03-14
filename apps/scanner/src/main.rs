use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;

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
        output: Option<String>,
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
                let rendered = serde_json::to_string_pretty(&result)?;

                if let Some(path) = output {
                    fs::write(path, rendered)?;
                } else {
                    println!("{rendered}");
                }
            } else {
                println!("Target: {}", result.target);
                println!("IPs resueltas: {}", result.resolved_ips.len());

                for ip in &result.resolved_ips {
                    println!("  - {ip}");
                }

                println!("Subdominios descubiertos: {}", result.subdomains.len());
                for sub in &result.subdomains {
                    println!("  - {sub}");
                }

                println!("Servicios HTTP detectados: {}", result.services.len());
                for service in &result.services {
                    let server = service.server.as_deref().unwrap_or("desconocido");
                    println!(
                        "  - {} [{}] status={} server={}",
                        service.url, service.scheme, service.status, server
                    );
                }
            }
        }
    }

    Ok(())
}
