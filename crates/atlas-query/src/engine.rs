use anyhow::{anyhow, Result};
use atlas_graph::{EdgeKind, ExposureGraph, GraphNode, NodeKind};

use crate::query::{
    Comparator, QueryClause, QueryExpr, QueryField, QueryPreset, QueryRequest, SortDirection,
    SortField,
};
use crate::results::{QueryMatch, QueryResult, QuerySummary};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
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
            explanations: Vec::new(),
        });
    }

    sort_matches_default(&mut matches);
    matches.truncate(request.limit);

    QueryResult {
        target: graph.target.clone(),
        raw_query: "graph-search".to_string(),
        summary: summarize_matches(&matches, matches.len()),
        matched_nodes: matches,
        limit: request.limit,
        offset: 0,
        sort: None,
        explain: false,
    }
}

pub fn execute_query(graph: &ExposureGraph, request: &QueryRequest) -> Result<QueryResult> {
    let degree_map = build_degree_map(graph);

    let mut all_matches = Vec::new();
    for node in &graph.nodes {
        if !matches_preset(node, request.preset.as_ref(), &degree_map) {
            continue;
        }

        if let Some(expr) = &request.expr {
            if !matches_expr(graph, node, expr, &degree_map)? {
                continue;
            }
        }

        let explanations = if request.explain {
            collect_explanations(graph, node, request, &degree_map)?
        } else {
            Vec::new()
        };

        all_matches.push(QueryMatch {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            kind: node.kind.clone(),
            degree: degree_map.get(&node.node_id).copied().unwrap_or(0),
            attributes: node.attributes.clone(),
            explanations,
        });
    }

    sort_matches(graph, &degree_map, &mut all_matches, request);

    let total_matches = all_matches.len();
    let offset = request.offset.min(total_matches);
    let limit = request.limit;

    let matched_nodes = all_matches
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    Ok(QueryResult {
        target: graph.target.clone(),
        raw_query: request.raw.clone(),
        summary: summarize_matches(&matched_nodes, total_matches),
        matched_nodes,
        limit,
        offset,
        sort: request.sort.clone(),
        explain: request.explain,
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

fn matches_expr(
    graph: &ExposureGraph,
    node: &GraphNode,
    expr: &QueryExpr,
    degree_map: &BTreeMap<String, usize>,
) -> Result<bool> {
    match expr {
        QueryExpr::Clause(clause) => matches_clause(graph, node, clause, degree_map),
        QueryExpr::And(items) => {
            for item in items {
                if !matches_expr(graph, node, item, degree_map)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        QueryExpr::Or(items) => {
            for item in items {
                if matches_expr(graph, node, item, degree_map)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        QueryExpr::Not(item) => Ok(!matches_expr(graph, node, item, degree_map)?),
    }
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
            let expected = parse_usize(&clause.value, "degree")?;
            Ok(compare_number(degree, expected, &clause.comparator))
        }
        QueryField::EpisodeKind => {
            let value = attribute(node, "kind");
            Ok(compare_string(&value, &clause.value, &clause.comparator))
        }
        QueryField::Severity => {
            let value = attribute_with_fallback(node, &["severity", "highest_severity"]);
            Ok(compare_ranked_string(
                &value,
                &clause.value,
                &clause.comparator,
                severity_rank,
            ))
        }
        QueryField::Criticality => {
            let value = attribute_with_fallback(node, &["criticality", "highest_criticality"]);
            Ok(compare_ranked_string(
                &value,
                &clause.value,
                &clause.comparator,
                criticality_rank,
            ))
        }
        QueryField::State => {
            let value = attribute_with_fallback(node, &["state", "states"]);
            Ok(compare_ranked_string(
                &value,
                &clause.value,
                &clause.comparator,
                state_rank,
            ))
        }
        QueryField::FirstSeen => compare_datetime_clause(node.first_seen, &clause.value, &clause.comparator),
        QueryField::LastSeen => compare_datetime_clause(node.last_seen, &clause.value, &clause.comparator),
        QueryField::Source => Ok(compare_string(
            &attribute(node, "source"),
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Target => Ok(compare_string(
            &node.target,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Title => Ok(compare_string(
            &attribute(node, "title"),
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Provider => Ok(compare_string(
            &attribute(node, "provider"),
            &clause.value,
            &clause.comparator,
        )),
        QueryField::Status => {
            let left = attribute(node, "status");
            let right = clause.value.parse::<usize>().ok();
            if let Some(expected) = right {
                let actual = left.parse::<usize>().unwrap_or(0);
                Ok(compare_number(actual, expected, &clause.comparator))
            } else {
                Ok(compare_string(&left, &clause.value, &clause.comparator))
            }
        }
        QueryField::Scheme => Ok(compare_string(
            &attribute(node, "scheme"),
            &clause.value,
            &clause.comparator,
        )),
        QueryField::TlsEnabled => {
            let actual = normalize_bool(&attribute(node, "tls_enabled"));
            let expected = normalize_bool(&clause.value);
            Ok(compare_bool(actual, expected, &clause.comparator))
        }
        QueryField::Score => {
            let actual = attribute_with_fallback(node, &["score", "total_score"])
                .parse::<usize>()
                .unwrap_or(0);
            let expected = parse_usize(&clause.value, "score")?;
            Ok(compare_number(actual, expected, &clause.comparator))
        }
        QueryField::ResourceCount => {
            let actual = attribute(node, "resource_count").parse::<usize>().unwrap_or(0);
            let expected = parse_usize(&clause.value, "resource_count")?;
            Ok(compare_number(actual, expected, &clause.comparator))
        }
        QueryField::NeighborKind => Ok(matches_neighbor_kind(
            graph,
            node,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::EdgeKind => Ok(matches_edge_kind(
            graph,
            node,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::ConnectedTo => Ok(matches_connected_to(
            graph,
            node,
            &clause.value,
            &clause.comparator,
        )),
        QueryField::InEpisode => {
            let actual = node_in_episode(graph, &node.node_id);
            let expected = normalize_bool(&clause.value);
            Ok(compare_bool(actual, expected, &clause.comparator))
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

fn matches_neighbor_kind(
    graph: &ExposureGraph,
    node: &GraphNode,
    expected: &str,
    comparator: &Comparator,
) -> bool {
    graph_neighbors(graph, &node.node_id)
        .iter()
        .any(|neighbor| compare_string(&neighbor.kind.to_string(), expected, comparator))
}

fn matches_edge_kind(
    graph: &ExposureGraph,
    node: &GraphNode,
    expected: &str,
    comparator: &Comparator,
) -> bool {
    graph.edges.iter().any(|edge| {
        (edge.from == node.node_id || edge.to == node.node_id)
            && compare_string(&edge.kind.to_string(), expected, comparator)
    })
}

fn matches_connected_to(
    graph: &ExposureGraph,
    node: &GraphNode,
    expected: &str,
    comparator: &Comparator,
) -> bool {
    graph_neighbors(graph, &node.node_id)
        .iter()
        .any(|neighbor| compare_string(&neighbor.label, expected, comparator))
}

fn collect_service_technologies(graph: &ExposureGraph, service_id: &str) -> Vec<String> {
    let mut tech_ids = Vec::new();

    for edge in &graph.edges {
        if edge.from == service_id && matches!(edge.kind, EdgeKind::FingerprintsAs) {
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

fn graph_neighbors<'a>(graph: &'a ExposureGraph, node_id: &str) -> Vec<&'a GraphNode> {
    let mut neighbor_ids = Vec::new();

    for edge in &graph.edges {
        if edge.from == node_id {
            neighbor_ids.push(edge.to.clone());
        } else if edge.to == node_id {
            neighbor_ids.push(edge.from.clone());
        }
    }

    graph.nodes
        .iter()
        .filter(|node| neighbor_ids.iter().any(|id| id == &node.node_id))
        .collect()
}

fn node_in_episode(graph: &ExposureGraph, node_id: &str) -> bool {
    graph.edges.iter().any(|edge| {
        if !(edge.from == node_id || edge.to == node_id) {
            return false;
        }

        if edge.kind != EdgeKind::ParticipatesIn {
            return false;
        }

        graph.nodes.iter().any(|node| {
            node.kind == NodeKind::Episode && (node.node_id == edge.from || node.node_id == edge.to)
        })
    })
}

fn attribute(node: &GraphNode, key: &str) -> String {
    node.attributes.get(key).cloned().unwrap_or_default()
}

fn attribute_with_fallback(node: &GraphNode, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = node.attributes.get(*key) {
            return value.clone();
        }
    }
    String::new()
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

fn compare_ranked_string(
    left: &str,
    right: &str,
    comparator: &Comparator,
    ranker: fn(&str) -> Option<usize>,
) -> bool {
    match comparator {
        Comparator::Eq | Comparator::Contains => compare_string(left, right, comparator),
        Comparator::Gt | Comparator::Gte | Comparator::Lt | Comparator::Lte => {
            let left_rank = ranker(left);
            let right_rank = ranker(right);
            match (left_rank, right_rank) {
                (Some(l), Some(r)) => compare_number(l, r, comparator),
                _ => false,
            }
        }
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

fn compare_bool(left: bool, right: bool, comparator: &Comparator) -> bool {
    match comparator {
        Comparator::Eq => left == right,
        Comparator::Contains | Comparator::Gt | Comparator::Gte | Comparator::Lt | Comparator::Lte => false,
    }
}

fn compare_datetime_clause(
    actual: Option<chrono::DateTime<chrono::Utc>>,
    expected_raw: &str,
    comparator: &Comparator,
) -> Result<bool> {
    let actual = match actual {
        Some(value) => value,
        None => return Ok(false),
    };

    let expected = parse_datetime(expected_raw)?;
    Ok(compare_datetime(actual, expected, comparator))
}

fn compare_datetime(
    left: chrono::DateTime<chrono::Utc>,
    right: chrono::DateTime<chrono::Utc>,
    comparator: &Comparator,
) -> bool {
    match comparator {
        Comparator::Eq => left == right,
        Comparator::Gt => left > right,
        Comparator::Gte => left >= right,
        Comparator::Lt => left < right,
        Comparator::Lte => left <= right,
        Comparator::Contains => false,
    }
}

fn parse_datetime(input: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }

    let date = chrono::NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|_| anyhow!("fecha inválida: {input}. Usa RFC3339 o YYYY-MM-DD"))?;

    let naive = date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow!("fecha inválida: {input}"))?;

    Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        naive,
        chrono::Utc,
    ))
}

fn parse_usize(input: &str, field: &str) -> Result<usize> {
    input
        .parse::<usize>()
        .map_err(|_| anyhow!("{field} debe ser numérico"))
}

fn normalize_bool(input: &str) -> bool {
    matches!(input.to_ascii_lowercase().as_str(), "true" | "yes" | "1")
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

fn summarize_matches(matches: &[QueryMatch], total_matches: usize) -> QuerySummary {
    let mut summary = QuerySummary::default();
    summary.total_matches = total_matches;
    summary.returned_matches = matches.len();

    for item in matches {
        summary.max_degree = summary.max_degree.max(item.degree);
        *summary
            .kind_counts
            .entry(item.kind.to_string())
            .or_insert(0) += 1;
    }

    summary
}

fn sort_matches(
    graph: &ExposureGraph,
    degree_map: &BTreeMap<String, usize>,
    matches: &mut [QueryMatch],
    request: &QueryRequest,
) {
    if let Some(sort) = &request.sort {
        matches.sort_by(|a, b| {
            let node_a = graph.nodes.iter().find(|n| n.node_id == a.node_id);
            let node_b = graph.nodes.iter().find(|n| n.node_id == b.node_id);

            let ordering = match sort.field {
                SortField::Degree => a.degree.cmp(&b.degree),
                SortField::Label => a.label.cmp(&b.label),
                SortField::Kind => a.kind.cmp(&b.kind),
                SortField::FirstSeen => node_a
                    .and_then(|n| n.first_seen)
                    .cmp(&node_b.and_then(|n| n.first_seen)),
                SortField::LastSeen => node_a
                    .and_then(|n| n.last_seen)
                    .cmp(&node_b.and_then(|n| n.last_seen)),
                SortField::Score => sort_number_attr(a, b, "score", "total_score"),
                SortField::Severity => sort_ranked_attr(a, b, &["severity", "highest_severity"], severity_rank),
                SortField::Criticality => {
                    sort_ranked_attr(a, b, &["criticality", "highest_criticality"], criticality_rank)
                }
            };

            let ordering = match sort.direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            };

            ordering
                .then_with(|| b.degree.cmp(&a.degree))
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.label.cmp(&b.label))
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
    } else {
        let _ = degree_map;
        sort_matches_default(matches);
    }
}

fn sort_matches_default(matches: &mut [QueryMatch]) {
    matches.sort_by(|a, b| {
        b.degree
            .cmp(&a.degree)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.label.cmp(&b.label))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
}

fn sort_number_attr(a: &QueryMatch, b: &QueryMatch, primary: &str, fallback: &str) -> Ordering {
    let a_value = a
        .attributes
        .get(primary)
        .or_else(|| a.attributes.get(fallback))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let b_value = b
        .attributes
        .get(primary)
        .or_else(|| b.attributes.get(fallback))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    a_value.cmp(&b_value)
}

fn sort_ranked_attr(
    a: &QueryMatch,
    b: &QueryMatch,
    keys: &[&str],
    ranker: fn(&str) -> Option<usize>,
) -> Ordering {
    let a_value = attribute_from_match(a, keys).and_then(ranker).unwrap_or(0);
    let b_value = attribute_from_match(b, keys).and_then(ranker).unwrap_or(0);
    a_value.cmp(&b_value)
}

fn attribute_from_match<'a>(item: &'a QueryMatch, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(value) = item.attributes.get(*key) {
            return Some(value.as_str());
        }
    }
    None
}

fn collect_explanations(
    graph: &ExposureGraph,
    node: &GraphNode,
    request: &QueryRequest,
    degree_map: &BTreeMap<String, usize>,
) -> Result<Vec<String>> {
    let mut explanations = Vec::new();

    if let Some(preset) = &request.preset {
        explanations.push(format!("preset matched: {}", preset));
    }

    if let Some(expr) = &request.expr {
        collect_expr_reasons(graph, node, expr, degree_map, &mut explanations)?;
    }

    Ok(explanations)
}

fn collect_expr_reasons(
    graph: &ExposureGraph,
    node: &GraphNode,
    expr: &QueryExpr,
    degree_map: &BTreeMap<String, usize>,
    out: &mut Vec<String>,
) -> Result<()> {
    match expr {
        QueryExpr::Clause(clause) => {
            if matches_clause(graph, node, clause, degree_map)? {
                out.push(format!(
                    "matched clause: {}{}{}",
                    clause.field, clause.comparator, clause.value
                ));
            }
        }
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            for item in items {
                collect_expr_reasons(graph, node, item, degree_map, out)?;
            }
        }
        QueryExpr::Not(inner) => {
            if !matches_expr(graph, node, inner, degree_map)? {
                out.push("matched NOT clause".to_string());
            }
        }
    }

    Ok(())
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

fn severity_rank(input: &str) -> Option<usize> {
    match input.to_ascii_lowercase().as_str() {
        "info" => Some(1),
        "low" => Some(2),
        "medium" => Some(3),
        "high" => Some(4),
        "critical" => Some(5),
        _ => None,
    }
}

fn criticality_rank(input: &str) -> Option<usize> {
    match input.to_ascii_lowercase().as_str() {
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

fn state_rank(input: &str) -> Option<usize> {
    match input.to_ascii_lowercase().as_str() {
        "new" => Some(1),
        "recurrent" => Some(2),
        "persistent" => Some(3),
        "suppressed" => Some(4),
        "resolved" => Some(5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_graph::{GraphEdge, GraphNode};
    use chrono::{Duration, Utc};
    use std::collections::BTreeMap;

    fn sample_graph() -> ExposureGraph {
        let now = Utc::now();
        let earlier = now - Duration::days(5);

        let mut graph = ExposureGraph::empty("example.com");

        let service_id = "service1".to_string();
        let tech_id = "tech1".to_string();
        let episode_id = "episode1".to_string();
        let subdomain_id = "sub1".to_string();

        graph.nodes.push(GraphNode {
            node_id: service_id.clone(),
            kind: NodeKind::Service,
            label: "https://admin.example.com".to_string(),
            target: "example.com".to_string(),
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::from([
                ("severity".to_string(), "HIGH".to_string()),
                ("state".to_string(), "New".to_string()),
                ("status".to_string(), "200".to_string()),
                ("scheme".to_string(), "https".to_string()),
                ("provider".to_string(), "cloudflare".to_string()),
                ("title".to_string(), "Admin Panel".to_string()),
                ("tls_enabled".to_string(), "true".to_string()),
            ]),
        });

        graph.nodes.push(GraphNode {
            node_id: tech_id.clone(),
            kind: NodeKind::Technology,
            label: "cloudflare".to_string(),
            target: "example.com".to_string(),
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
        });

        graph.nodes.push(GraphNode {
            node_id: episode_id.clone(),
            kind: NodeKind::Episode,
            label: "Infra shift".to_string(),
            target: "example.com".to_string(),
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::from([
                ("kind".to_string(), "InfrastructureShift".to_string()),
                ("criticality".to_string(), "HIGH".to_string()),
                ("state".to_string(), "New".to_string()),
                ("score".to_string(), "120".to_string()),
                ("resource_count".to_string(), "2".to_string()),
            ]),
        });

        graph.nodes.push(GraphNode {
            node_id: subdomain_id.clone(),
            kind: NodeKind::Subdomain,
            label: "admin.example.com".to_string(),
            target: "example.com".to_string(),
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::new(),
        });

        graph.edges.push(GraphEdge {
            edge_id: "e1".to_string(),
            from: service_id.clone(),
            to: tech_id,
            kind: EdgeKind::FingerprintsAs,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::new(),
        });

        graph.edges.push(GraphEdge {
            edge_id: "e2".to_string(),
            from: service_id.clone(),
            to: episode_id,
            kind: EdgeKind::ParticipatesIn,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: Some(earlier),
            last_seen: Some(now),
            attributes: BTreeMap::new(),
        });

        graph.edges.push(GraphEdge {
            edge_id: "e3".to_string(),
            from: subdomain_id,
            to: service_id,
            kind: EdgeKind::Exposes,
            target: "example.com".to_string(),
            weight: 1,
            first_seen: Some(earlier),
            last_seen: Some(now),
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

    #[test]
    fn boolean_or_query_matches_multiple_kinds() {
        let graph = sample_graph();
        let request = crate::parser::parse_query(
            r#"kind=service OR (kind=episode AND criticality>=high)"#,
            20,
        )
        .unwrap();

        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 2);
    }

    #[test]
    fn quoted_title_query_matches_service() {
        let graph = sample_graph();
        let request = crate::parser::parse_query(r#"services title~"admin panel""#, 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
    }

    #[test]
    fn not_clause_excludes_service() {
        let graph = sample_graph();
        let request = crate::parser::parse_query(r#"services NOT provider=cloudflare"#, 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 0);
    }

    #[test]
    fn relation_filters_work() {
        let graph = sample_graph();
        let request = crate::parser::parse_query(
            r#"services connected_to=admin.example.com AND in_episode=true AND edge_kind=participates_in"#,
            20,
        )
        .unwrap();

        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
    }

    #[test]
    fn time_filters_work() {
        let graph = sample_graph();
        let threshold = (Utc::now() - Duration::days(2)).format("%Y-%m-%d").to_string();
        let query = format!("services last_seen>={threshold}");
        let request = crate::parser::parse_query(&query, 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 1);
    }

    #[test]
    fn explain_populates_reasons() {
        let graph = sample_graph();
        let request =
            crate::parser::parse_query(r#"EXPLAIN services technology=cloudflare"#, 20).unwrap();
        let result = execute_query(&graph, &request).unwrap();
        assert!(result.explain);
        assert!(!result.matched_nodes[0].explanations.is_empty());
    }

    #[test]
    fn order_limit_offset_work() {
        let graph = sample_graph();
        let request = crate::parser::parse_query(
            r#"kind=service OR kind=subdomain ORDER BY label ASC LIMIT 1 OFFSET 1"#,
            50,
        )
        .unwrap();

        let result = execute_query(&graph, &request).unwrap();
        assert_eq!(result.summary.total_matches, 2);
        assert_eq!(result.summary.returned_matches, 1);
    }
}