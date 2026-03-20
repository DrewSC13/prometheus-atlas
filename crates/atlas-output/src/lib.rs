use anyhow::{Context, Result};
use atlas_core::ScanResult;
use atlas_graph::ExposureGraph;
use atlas_query::{GraphStatsReport, QueryResult};
use atlas_report::ExecutiveReport;
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

pub fn print_human_graph_stats(report: &GraphStatsReport) {
    println!("Target: {}", report.target);
    println!("Generated at: {}", report.generated_at);
    println!("Nodes: {}", report.node_count);
    println!("Edges: {}", report.edge_count);

    println!();
    println!("Nodos por tipo:");
    println!("  - Targets: {}", report.stats.targets);
    println!("  - Subdomains: {}", report.stats.subdomains);
    println!("  - IPs: {}", report.stats.ips);
    println!("  - Services: {}", report.stats.services);
    println!("  - Technologies: {}", report.stats.technologies);
    println!("  - Episodes: {}", report.stats.episodes);

    println!();
    println!("Relaciones por tipo:");
    println!("  - contains: {}", report.stats.contains_edges);
    println!("  - resolves_to: {}", report.stats.resolves_to_edges);
    println!("  - exposes: {}", report.stats.exposes_edges);
    println!(
        "  - fingerprints_as: {}",
        report.stats.fingerprints_as_edges
    );
    println!(
        "  - participates_in: {}",
        report.stats.participates_in_edges
    );
    println!("  - belongs_to: {}", report.stats.belongs_to_edges);

    println!();
    println!("Topología:");
    println!("  - Connected nodes: {}", report.topology.connected_nodes);
    println!("  - Isolated nodes: {}", report.topology.isolated_nodes);
    println!("  - Max degree: {}", report.topology.max_degree);

    if !report.topology.highest_degree_nodes.is_empty() {
        println!();
        println!("Nodos con mayor grado:");
        for node in &report.topology.highest_degree_nodes {
            println!(
                "  - {} [{}] | degree={} | id={}",
                node.label, node.kind, node.degree, node.node_id
            );
        }
    }
}

pub fn print_human_query_result(result: &QueryResult) {
    println!("Target: {}", result.target);
    println!("Query: {}", result.raw_query);
    println!("Matches: {}", result.summary.total_matches);
    println!("Returned: {}", result.summary.returned_matches);
    println!("Max degree: {}", result.summary.max_degree);

    if result.limit > 0 {
        println!("Limit: {}", result.limit);
    }

    if result.offset > 0 {
        println!("Offset: {}", result.offset);
    }

    if let Some(sort) = &result.sort {
        println!("Sort: {} {}", sort.field, sort.direction);
    }

    if result.explain {
        println!("Explain: true");
    }

    if !result.summary.kind_counts.is_empty() {
        println!();
        println!("Distribución por tipo:");
        for (kind, count) in &result.summary.kind_counts {
            println!("  - {}: {}", kind, count);
        }
    }

    if result.matched_nodes.is_empty() {
        println!();
        println!("No se encontraron resultados.");
        return;
    }

    println!();
    println!("Resultados:");
    for node in &result.matched_nodes {
        println!(
            "  - {} [{}] | degree={} | id={}",
            node.label, node.kind, node.degree, node.node_id
        );

        if !node.attributes.is_empty() {
            for (key, value) in &node.attributes {
                println!("      {}={}", key, value);
            }
        }

        if !node.explanations.is_empty() {
            for explanation in &node.explanations {
                println!("      why: {}", explanation);
            }
        }
    }
}

pub fn print_human_executive_report(report: &ExecutiveReport) {
    println!("Target: {}", report.target);
    println!("Generated at: {}", report.generated_at);
    println!("Snapshots: {}", report.snapshot_count);

    if let Some(latest) = report.latest_snapshot_at {
        println!("Latest snapshot: {}", latest);
    }

    println!(
        "Policy applied: {}",
        if report.policy_applied { "yes" } else { "no" }
    );

    println!();
    println!("Resumen ejecutivo:");
    println!("  - Score acumulado: {}", report.overview.total_score);
    println!("  - Severidad global: {}", report.overview.overall_severity);
    println!(
        "  - Hallazgos acumulados: {}",
        report.overview.total_findings
    );
    println!(
        "  - Recursos únicos afectados: {}",
        report.overview.unique_resources
    );
    println!(
        "  - Hallazgos críticos: {}",
        report.overview.critical_findings
    );
    println!(
        "  - Hallazgos recurrentes: {}",
        report.overview.recurring_findings
    );
    println!(
        "  - Hallazgos persistentes: {}",
        report.overview.persistent_findings
    );

    println!();
    println!("Resumen de grafo:");
    println!("  - Nodes: {}", report.graph.node_count);
    println!("  - Edges: {}", report.graph.edge_count);
    println!("  - Connected nodes: {}", report.graph.connected_nodes);
    println!("  - Isolated nodes: {}", report.graph.isolated_nodes);
    println!("  - Max degree: {}", report.graph.max_degree);

    if !report.graph.highest_degree_labels.is_empty() {
        println!("  - Hubs:");
        for label in &report.graph.highest_degree_labels {
            println!("      {}", label);
        }
    }

    println!();
    println!("Resumen de episodios:");
    println!("  - Total episodes: {}", report.episodes.total_episodes);

    if !report.episodes.by_state.is_empty() {
        println!("  - By state:");
        for (state, count) in &report.episodes.by_state {
            println!("      {}: {}", state, count);
        }
    }

    if !report.episodes.by_kind.is_empty() {
        println!("  - By kind:");
        for (kind, count) in &report.episodes.by_kind {
            println!("      {}: {}", kind, count);
        }
    }

    if !report.top_findings.is_empty() {
        println!();
        println!("Top findings:");
        for finding in &report.top_findings {
            println!(
                "  - [{}] {} | resource={} | category={} | state={} | score={}",
                finding.severity,
                finding.title,
                finding.resource,
                finding.category,
                finding.state,
                finding.score
            );
        }
    }

    if !report.hotspots.is_empty() {
        println!();
        println!("Hotspots:");
        for hotspot in &report.hotspots {
            println!(
                "  - {} | score={} | occurrences={}",
                hotspot.resource, hotspot.total_score, hotspot.occurrences
            );
            if !hotspot.categories.is_empty() {
                println!("      categories={}", hotspot.categories.join(", "));
            }
        }
    }

    if !report.episodes.top_episodes.is_empty() {
        println!();
        println!("Top episodes:");
        for episode in &report.episodes.top_episodes {
            println!(
                "  - [{}] {} | kind={} | score={} | state={} | resources={}",
                episode.severity,
                episode.title,
                episode.kind,
                episode.score,
                episode.state,
                episode.resource_count
            );
        }
    }

    if !report.recommendations.is_empty() {
        println!();
        println!("Recomendaciones:");
        for recommendation in &report.recommendations {
            println!("  - {}", recommendation);
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
