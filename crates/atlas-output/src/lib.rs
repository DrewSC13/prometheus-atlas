use anyhow::{Context, Result};
use atlas_core::ScanResult;
use std::fs;
use std::path::Path;

pub fn print_human_scan_result(result: &ScanResult) {
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

pub fn write_json_output<T: serde::Serialize>(value: &T, output: Option<&Path>) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value)?;

    if let Some(path) = output {
        fs::write(path, rendered)
            .with_context(|| format!("no se pudo escribir la salida JSON en {}", path.display()))?;
    } else {
        println!("{rendered}");
    }

    Ok(())
}
