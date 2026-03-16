use anyhow::{Context, Result};
use atlas_core::ScanResult;
use atlas_graph::ExposureGraph;
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

pub fn print_human_exposure_graph(graph: &ExposureGraph) {
    println!("Target: {}", graph.target);
    println!("Generated at: {}", graph.generated_at);
    println!("Nodes: {}", graph.node_count);
    println!("Edges: {}", graph.edge_count);

    println!();
    println!("Nodos por tipo:");
    println!("  - Targets: {}", graph.stats.targets);
    println!("  - Subdomains: {}", graph.stats.subdomains);
    println!("  - IPs: {}", graph.stats.ips);
    println!("  - Services: {}", graph.stats.services);
    println!("  - Technologies: {}", graph.stats.technologies);
    println!("  - Episodes: {}", graph.stats.episodes);

    println!();
    println!("Relaciones por tipo:");
    println!("  - contains: {}", graph.stats.contains_edges);
    println!("  - resolves_to: {}", graph.stats.resolves_to_edges);
    println!("  - exposes: {}", graph.stats.exposes_edges);
    println!("  - fingerprints_as: {}", graph.stats.fingerprints_as_edges);
    println!("  - participates_in: {}", graph.stats.participates_in_edges);
    println!("  - belongs_to: {}", graph.stats.belongs_to_edges);

    println!();
    println!("Topología:");
    println!("  - Connected nodes: {}", graph.topology.connected_nodes);
    println!("  - Isolated nodes: {}", graph.topology.isolated_nodes);
    println!("  - Max degree: {}", graph.topology.max_degree);

    if !graph.topology.highest_degree_nodes.is_empty() {
        println!();
        println!("Nodos con mayor grado:");
        for node in &graph.topology.highest_degree_nodes {
            println!(
                "  - {} [{}] | degree={} | id={}",
                node.label, node.kind, node.degree, node.node_id
            );
        }
    }

    if !graph.edges.is_empty() {
        println!();
        println!("Relaciones:");
        for edge in &graph.edges {
            println!(
                "  - {} -> {} | kind={} | weight={}",
                edge.from, edge.to, edge.kind, edge.weight
            );
        }
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
