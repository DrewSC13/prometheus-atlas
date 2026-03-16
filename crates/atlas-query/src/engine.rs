use anyhow::{anyhow, Result};
use atlas_graph::{ExposureGraph, GraphNode, NodeKind};

use crate::query::{Comparator, QueryClause, QueryField, QueryPreset, QueryRequest};
use crate::results::{QueryMatch, QueryResult, QuerySummary};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStatsReport {
    pub target: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub node_count: usize,
    pub edge_count: usize,
    pub stats: atlas_graph::GraphStats,
    pub topology: atlas_graph::GraphTopologySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSearchRequest {
    pub kind: Option<NodeKind>,
    pub label_contains: Option<String>,
    pub min_degree: Option<usize>,
    pub limit: usize,
}

pub fn build_graph_stats_report(graph: &ExposureGraph) -> GraphStatsReport {
    GraphStatsReport {
        target: graph.target.clone(),
        generated_at: graph.generated_at,
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        stats: graph.stats.clone(),
        topology: graph.topology.clone(),
    }
}

pub fn graph_search(graph: &ExposureGraph, request: &GraphSearchRequest) -> QueryResult {
    let degree_map = build_degree_map(graph);

    let mut matches = Vec::new();
    for node in &graph.nodes {
        let degree = degree_map.get(&node.node_id).copied().unwrap_or(0);

        if let Some(kind) = &request.kind {
            if &node.kind != kind {
                continue;
            }
        }

        if let Some(label_contains) = &request.label_contains {
            if !node
                .label
                .to_ascii_lowercase()
                .contains(&label_contains.to_ascii_lowercase())
            {
                continue;
            }
        }

        if let Some(min_degree) = request.min_degree {
            if degree < min_degree {
                continue;
            }
        }

        matches.push(QueryMatch {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            kind: node.kind.clone(),
            degree,
            attributes: node.attributes.clone(),
        });
    }

    sort_matches(&mut matches);
    matches.truncate(request.limit);

    QueryResult {
        target: graph.target.clone(),
        raw_query: "graph-search".to_string(),
        summary: summarize_matches(&matches),
        matched_nodes: matches,
    }
}

pub fn execute_query(graph: &ExposureGraph, request: &QueryRequest) -> Result<QueryResult> {
    let degree_map = build_degree_map(graph);

    let mut matches = Vec::new();
    for node in &graph.nodes {
        if !matches_preset(node, request.preset.as_ref(), &degree_map) {
            continue;
        }

        if !matches_all_clauses(graph, node, &request.clauses, &degree_map)? {
            continue;
        }

        matches.push(QueryMatch {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            kind: node.kind.clone(),
            degree: degree_map.get(&node.node_id).copied().unwrap_or(0),
            attributes: node.attributes.clone(),
        });
    }

    sort_matches(&mut matches);
    matches.truncate(request.limit);

    Ok(QueryResult {
        target: graph.target.clone(),
        raw_query: request.raw.clone(),
        summary: summarize_matches(&matches),
        matched_nodes: matches,
    })
}

fn matches_preset(
    node: &GraphNode,
    preset: Option<&QueryPreset>,
    degree_map: &BTreeMap<String, usize>,
) -> bool {
    match preset {
        None => true,
        Some(QueryPreset::Services) => node.kind == NodeKind::Service,
        Some(QueryPreset::Technologies) => node.kind == NodeKind::Technology,
        Some(QueryPreset::Episodes) => node.kind == NodeKind::Episode,
        Some(QueryPreset::Subdomains) => node.kind == NodeKind::Subdomain,
        Some(QueryPreset::Targets) => node.kind == NodeKind::Target,
        Some(QueryPreset::Ips) => node.kind == NodeKind::Ip,
        Some(QueryPreset::HighDegree) => degree_map.get(&node.node_id).copied().unwrap_or(0) >= 3,
    }
}

fn matches_all_clauses(
    graph: &ExposureGraph,
    node: &GraphNode,
    clauses: &[QueryClause],
    degree_map: &BTreeMap<String, usize>,
) -> Result<bool> {
    for clause in clauses {
        if !matches_clause(graph, node, clause, degree_map)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn matches_clause(
    graph: &ExposureGraph,
    node: &GraphNode,
    clause: &QueryClause,
    degree_map: &BTreeMap<String, usize>,
) -> Result<bool> {
    match clause.field {
        QueryField::Kind => {
            let expected = NodeKind::from_str(&clause.value)
                .or_else(|_| parse_node_kind_loose(&clause.value))?;
            Ok(compare_string(
                &node.kind.to_string(),
                &expected.to_string(),
                &clause.comparator,
            ))
        }
        QueryField::Label => Ok(compare_string(
            &node.label,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Technology => Ok(matches_technology_filter(
            graph,
            node,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Degree => {
            let degree = degree_map.get(&node.node_id).copied().unwrap_or(0);
            let expected = clause
                .value
                .parse::<usize>()
                .map_err(|_| anyhow!("degree debe ser numérico"))?;
            Ok(compare_number(degree, expected, &clause.comparator))
        }
        QueryField::EpisodeKind => {
            let value = node.attributes.get("kind").cloned().unwrap_or_default();
            Ok(compare_string(&value, &clause.value, &clause.comparator))
        }
        QueryField::Severity => {
            let value = node
                .attributes
                .get("severity")
                .cloned()
                .or_else(|| node.attributes.get("highest_severity").cloned())
                .unwrap_or_default();
            Ok(compare_string(&value, &clause.value, &clause.comparator))
        }
        QueryField::Criticality => {
            let value = node
                .attributes
                .get("criticality")
                .cloned()
                .or_else(|| node.attributes.get("highest_criticality").cloned())
                .unwrap_or_default();
            Ok(compare_string(&value, &clause.value, &clause.comparator))
        }
        QueryField::State => {
            let value = node
                .attributes
                .get("state")
                .cloned()
                .or_else(|| node.attributes.get("states").cloned())
                .unwrap_or_default();
            Ok(compare_string(&value, &clause.value, &clause.comparator))
        }
    }
}

fn matches_technology_filter(
    graph: &ExposureGraph,
    node: &GraphNode,
    expected: &str,
    comparator: &Comparator,
) -> bool {
    match node.kind {
        NodeKind::Service => {
            let technologies = collect_service_technologies(graph, &node.node_id);
            technologies
                .iter()
                .any(|tech| compare_string(tech, expected, comparator))
        }
        NodeKind::Technology => compare_string(&node.label, expected, comparator),
        _ => false,
    }
}

fn collect_service_technologies(graph: &ExposureGraph, service_id: &str) -> Vec<String> {
    let mut tech_ids = Vec::new();

    for edge in &graph.edges {
        if edge.from == service_id && matches!(edge.kind, atlas_graph::EdgeKind::FingerprintsAs) {
            tech_ids.push(edge.to.clone());
        }
    }

    let mut labels = Vec::new();
    for node in &graph.nodes {
        if tech_ids.iter().any(|id| id == &node.node_id) {
            labels.push(node.label.clone());
        }
    }

    labels
}

fn compare_string(left: &str, right: &str, comparator: &Comparator) -> bool {
    let left_norm = left.to_ascii_lowercase();
    let right_norm = right.to_ascii_lowercase();

    match comparator {
        Comparator::Eq => {
            if left_norm == right_norm {
                true
            } else {
                left_norm
                    .split(',')
                    .map(|s| s.trim())
                    .any(|value| value == right_norm)
            }
        }
        Comparator::Contains => left_norm.contains(&right_norm),
        Comparator::Gt | Comparator::Gte | Comparator::Lt | Comparator::Lte => false,
    }
}

fn compare_number(left: usize, right: usize, comparator: &Comparator) -> bool {
    match comparator {
        Comparator::Eq => left == right,
        Comparator::Gt => left > right,
        Comparator::Gte => left >= right,
        Comparator::Lt => left < right,
        Comparator::Lte => left <= right,
        Comparator::Contains => false,
    }
}

fn build_degree_map(graph: &ExposureGraph) -> BTreeMap<String, usize> {
    let mut degree_map = BTreeMap::new();

    for node in &graph.nodes {
        degree_map.entry(node.node_id.clone()).or_insert(0);
    }

    for edge in &graph.edges {
        *degree_map.entry(edge.from.clone()).or_insert(0) += 1;
        *degree_map.entry(edge.to.clone()).or_insert(0) += 1;
    }

    degree_map
}

fn summarize_matches(matches: &[QueryMatch]) -> QuerySummary {
    let mut summary = QuerySummary::default();

    for item in matches {
        summary.total_matches += 1;
        summary.max_degree = summary.max_degree.max(item.degree);
        *summary
            .kind_counts
            .entry(item.kind.to_string())
            .or_insert(0) += 1;
    }

    summary
}

fn sort_matches(matches: &mut [QueryMatch]) {
    matches.sort_by(|a, b| {
        b.degree
            .cmp(&a.degree)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.label.cmp(&b.label))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
}

fn parse_node_kind_loose(input: &str) -> Result<NodeKind> {
    match input.to_ascii_lowercase().as_str() {
        "target" | "targets" => Ok(NodeKind::Target),
        "subdomain" | "subdomains" => Ok(NodeKind::Subdomain),
        "ip" | "ips" => Ok(NodeKind::Ip),
        "service" | "services" => Ok(NodeKind::Service),
        "technology" | "technologies" | "tech" => Ok(NodeKind::Technology),
        "episode" | "episodes" => Ok(NodeKind::Episode),
        other => Err(anyhow!("node kind no soportado: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_graph::{EdgeKind, ExposureGraph, GraphEdge, GraphNode, NodeKind};
    use std::collections::BTreeMap;

    fn sample_graph() -> ExposureGraph {
        let mut graph = ExposureGraph::empty("example.com");

        let service_id = "service1".to_string();
        let tech_id = "tech1".to_string();
        let episode_id = "episode1".to_string();

        graph.nodes.push(GraphNode {
            node_id: service_id.clone(),
            kind: NodeKind::Service,
            label: "http://admin.example.com".to_string(),
            target: "example.com".to_string(),
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::from([
                ("severity".to_string(), "HIGH".to_string()),
                ("state".to_string(), "New".to_string()),
            ]),
        });

        graph.nodes.push(GraphNode {
            node_id: tech_id.clone(),
            kind: NodeKind::Technology,
            label: "cloudflare".to_string(),
            target: "example.com".to_string(),
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        });

        graph.nodes.push(GraphNode {
            node_id: episode_id.clone(),
            kind: NodeKind::Episode,
            label: "Infra shift".to_string(),
            target: "example.com".to_string(),
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::from([
                ("kind".to_string(), "InfrastructureShift".to_string()),
                ("criticality".to_string(), "HIGH".to_string()),
                ("state".to_string(), "New".to_string()),
            ]),
        });

        graph.edges.push(GraphEdge {
            edge_id: "e1".to_string(),
            from: service_id.clone(),
            to: tech_id,
            kind: EdgeKind::FingerprintsAs,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        });

        graph.edges.push(GraphEdge {
            edge_id: "e2".to_string(),
            from: service_id,
            to: episode_id,
            kind: EdgeKind::ParticipatesIn,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        });

        graph.recompute_metadata();
        graph
    }

    #[test]
    fn finds_services_by_preset() {
        let graph = sample_graph();
        let request = crate::parser::parse_query("services", 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
        assert_eq!(result.matched_nodes[0].kind, NodeKind::Service);
    }

    #[test]
    fn finds_service_by_technology() {
        let graph = sample_graph();
        let request = crate::parser::parse_query("services technology=cloudflare", 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
    }

    #[test]
    fn finds_episodes_by_kind() {
        let graph = sample_graph();
        let request =
            crate::parser::parse_query("episodes episode_kind=InfrastructureShift", 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
        assert_eq!(result.matched_nodes[0].kind, NodeKind::Episode);
    }

    #[test]
    fn graph_search_filters_by_label() {
        let graph = sample_graph();
        let result = graph_search(
            &graph,
            &GraphSearchRequest {
                kind: Some(NodeKind::Service),
                label_contains: Some("admin".to_string()),
                min_degree: Some(1),
                limit: 10,
            },
        );

        assert_eq!(result.summary.total_matches, 1);
    }
}
