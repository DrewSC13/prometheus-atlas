use anyhow::{anyhow, Result};
use atlas_drift::{AssetType, TimelineReport};
use atlas_episodes::EpisodeCollection;
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeKind {
    Target,
    Subdomain,
    Ip,
    Service,
    Technology,
    Episode,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::Target => write!(f, "Target"),
            NodeKind::Subdomain => write!(f, "Subdomain"),
            NodeKind::Ip => write!(f, "Ip"),
            NodeKind::Service => write!(f, "Service"),
            NodeKind::Technology => write!(f, "Technology"),
            NodeKind::Episode => write!(f, "Episode"),
        }
    }
}

impl FromStr for NodeKind {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        match input {
            "Target" => Ok(Self::Target),
            "Subdomain" => Ok(Self::Subdomain),
            "Ip" => Ok(Self::Ip),
            "Service" => Ok(Self::Service),
            "Technology" => Ok(Self::Technology),
            "Episode" => Ok(Self::Episode),
            other => Err(anyhow!("node kind no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    Contains,
    ResolvesTo,
    Exposes,
    FingerprintsAs,
    ParticipatesIn,
    BelongsTo,
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeKind::Contains => write!(f, "contains"),
            EdgeKind::ResolvesTo => write!(f, "resolves_to"),
            EdgeKind::Exposes => write!(f, "exposes"),
            EdgeKind::FingerprintsAs => write!(f, "fingerprints_as"),
            EdgeKind::ParticipatesIn => write!(f, "participates_in"),
            EdgeKind::BelongsTo => write!(f, "belongs_to"),
        }
    }
}

impl FromStr for EdgeKind {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        match input {
            "contains" => Ok(Self::Contains),
            "resolves_to" => Ok(Self::ResolvesTo),
            "exposes" => Ok(Self::Exposes),
            "fingerprints_as" => Ok(Self::FingerprintsAs),
            "participates_in" => Ok(Self::ParticipatesIn),
            "belongs_to" => Ok(Self::BelongsTo),
            other => Err(anyhow!("edge kind no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub node_id: String,
    pub kind: NodeKind,
    pub label: String,
    pub target: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub target: String,
    pub weight: u32,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphStats {
    pub targets: usize,
    pub subdomains: usize,
    pub ips: usize,
    pub services: usize,
    pub technologies: usize,
    pub episodes: usize,

    pub contains_edges: usize,
    pub resolves_to_edges: usize,
    pub exposes_edges: usize,
    pub fingerprints_as_edges: usize,
    pub participates_in_edges: usize,
    pub belongs_to_edges: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedGraphNode {
    pub node_id: String,
    pub label: String,
    pub kind: NodeKind,
    pub degree: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphTopologySummary {
    pub connected_nodes: usize,
    pub isolated_nodes: usize,
    pub max_degree: usize,
    pub highest_degree_nodes: Vec<RankedGraphNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureGraph {
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub node_count: usize,
    pub edge_count: usize,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub stats: GraphStats,
    pub topology: GraphTopologySummary,
}

impl ExposureGraph {
    pub fn empty(target: &str) -> Self {
        let mut graph = Self {
            target: target.to_string(),
            generated_at: Utc::now(),
            node_count: 0,
            edge_count: 0,
            nodes: Vec::new(),
            edges: Vec::new(),
            stats: GraphStats::default(),
            topology: GraphTopologySummary::default(),
        };

        let target_node = GraphNode {
            node_id: stable_node_id(&NodeKind::Target, target),
            kind: NodeKind::Target,
            label: target.to_string(),
            target: target.to_string(),
            first_seen: None,
            last_seen: None,
            attributes: BTreeMap::new(),
        };

        graph.upsert_node(target_node);
        graph.recompute_metadata();
        graph
    }

    pub fn merge(&mut self, other: &ExposureGraph) {
        for node in &other.nodes {
            self.upsert_node(node.clone());
        }

        for edge in &other.edges {
            self.upsert_edge(edge.clone());
        }

        if other.generated_at > self.generated_at {
            self.generated_at = other.generated_at;
        }

        self.recompute_metadata();
    }

    pub fn recompute_metadata(&mut self) {
        self.nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        self.edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
        self.node_count = self.nodes.len();
        self.edge_count = self.edges.len();
        self.stats = compute_stats(&self.nodes, &self.edges);
        self.topology = compute_topology(&self.nodes, &self.edges);
    }

    fn upsert_node(&mut self, node: GraphNode) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.node_id == node.node_id) {
            existing.first_seen = min_datetime(existing.first_seen, node.first_seen);
            existing.last_seen = max_datetime(existing.last_seen, node.last_seen);

            for (key, value) in node.attributes {
                existing.attributes.entry(key).or_insert(value);
            }
            return;
        }

        self.nodes.push(node);
    }

    fn upsert_edge(&mut self, edge: GraphEdge) {
        if let Some(existing) = self.edges.iter_mut().find(|e| e.edge_id == edge.edge_id) {
            existing.weight = existing.weight.max(edge.weight);
            existing.first_seen = min_datetime(existing.first_seen, edge.first_seen);
            existing.last_seen = max_datetime(existing.last_seen, edge.last_seen);

            for (key, value) in edge.attributes {
                existing.attributes.entry(key).or_insert(value);
            }
            return;
        }

        self.edges.push(edge);
    }
}

pub fn build_full_graph(
    target: &str,
    latest_snapshot: Option<&Snapshot>,
    timeline: Option<&TimelineReport>,
    episodes: Option<&EpisodeCollection>,
) -> ExposureGraph {
    let mut graph = ExposureGraph::empty(target);

    if let Some(snapshot) = latest_snapshot {
        graph.merge(&build_graph_from_snapshot(snapshot));
    }

    if let Some(timeline) = timeline {
        graph.merge(&build_graph_from_timeline(timeline));
    }

    if let Some(episodes) = episodes {
        graph.merge(&build_graph_from_episode_collection(episodes));
    }

    graph.recompute_metadata();
    graph
}

pub fn build_graph_from_snapshot(snapshot: &Snapshot) -> ExposureGraph {
    let mut graph = ExposureGraph::empty(&snapshot.target);
    let target_id = stable_node_id(&NodeKind::Target, &snapshot.target);

    if let Some(target_node) = graph.nodes.iter_mut().find(|n| n.node_id == target_id) {
        target_node.first_seen = Some(snapshot.timestamp);
        target_node.last_seen = Some(snapshot.timestamp);
        target_node.attributes.insert(
            "snapshot_version".to_string(),
            snapshot.snapshot_version.to_string(),
        );
        target_node.attributes.insert(
            "snapshot_timestamp".to_string(),
            snapshot.timestamp.to_rfc3339(),
        );
    }

    let mut known_subdomains: BTreeSet<String> = snapshot.scan.subdomains.iter().cloned().collect();
    known_subdomains.insert(snapshot.target.clone());

    for subdomain in &known_subdomains {
        let subdomain_id = stable_node_id(&NodeKind::Subdomain, subdomain);

        graph.upsert_node(GraphNode {
            node_id: subdomain_id.clone(),
            kind: NodeKind::Subdomain,
            label: subdomain.clone(),
            target: snapshot.target.clone(),
            first_seen: Some(snapshot.timestamp),
            last_seen: Some(snapshot.timestamp),
            attributes: BTreeMap::from([
                ("source".to_string(), "snapshot".to_string()),
                (
                    "snapshot_timestamp".to_string(),
                    snapshot.timestamp.to_rfc3339(),
                ),
            ]),
        });

        graph.upsert_edge(GraphEdge {
            edge_id: stable_edge_id(&target_id, &subdomain_id, &EdgeKind::Contains),
            from: target_id.clone(),
            to: subdomain_id.clone(),
            kind: EdgeKind::Contains,
            target: snapshot.target.clone(),
            weight: 1,
            first_seen: Some(snapshot.timestamp),
            last_seen: Some(snapshot.timestamp),
            attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
        });

        for ip in &snapshot.scan.resolved_ips {
            let ip_id = stable_node_id(&NodeKind::Ip, ip);

            graph.upsert_node(GraphNode {
                node_id: ip_id.clone(),
                kind: NodeKind::Ip,
                label: ip.clone(),
                target: snapshot.target.clone(),
                first_seen: Some(snapshot.timestamp),
                last_seen: Some(snapshot.timestamp),
                attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
            });

            graph.upsert_edge(GraphEdge {
                edge_id: stable_edge_id(&subdomain_id, &ip_id, &EdgeKind::ResolvesTo),
                from: subdomain_id.clone(),
                to: ip_id,
                kind: EdgeKind::ResolvesTo,
                target: snapshot.target.clone(),
                weight: 1,
                first_seen: Some(snapshot.timestamp),
                last_seen: Some(snapshot.timestamp),
                attributes: BTreeMap::from([
                    ("source".to_string(), "snapshot".to_string()),
                    ("inferred".to_string(), "true".to_string()),
                    (
                        "reason".to_string(),
                        "scan_result_only_has_target_level_resolved_ips".to_string(),
                    ),
                ]),
            });
        }
    }

    for service in &snapshot.scan.services {
        let parent_label = if service.host.trim().is_empty() {
            snapshot.target.as_str()
        } else {
            service.host.as_str()
        };

        let parent_kind = NodeKind::Subdomain;

        let parent_id = stable_node_id(&parent_kind, parent_label);

        graph.upsert_node(GraphNode {
            node_id: parent_id.clone(),
            kind: parent_kind,
            label: parent_label.to_string(),
            target: snapshot.target.clone(),
            first_seen: Some(snapshot.timestamp),
            last_seen: Some(snapshot.timestamp),
            attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
        });

        let service_id = stable_node_id(&NodeKind::Service, &service.url);
        let mut service_attrs = BTreeMap::new();
        service_attrs.insert("scheme".to_string(), service.scheme.clone());
        service_attrs.insert("status".to_string(), service.status.to_string());
        service_attrs.insert("host".to_string(), service.host.clone());
        service_attrs.insert("tls_enabled".to_string(), service.tls_enabled.to_string());
        if let Some(server) = &service.server {
            service_attrs.insert("server".to_string(), server.clone());
        }
        if let Some(provider) = &service.provider {
            service_attrs.insert("provider".to_string(), provider.clone());
        }
        if let Some(content_type) = &service.content_type {
            service_attrs.insert("content_type".to_string(), content_type.clone());
        }
        if let Some(title) = &service.title {
            service_attrs.insert("title".to_string(), title.clone());
        }

        graph.upsert_node(GraphNode {
            node_id: service_id.clone(),
            kind: NodeKind::Service,
            label: service.url.clone(),
            target: snapshot.target.clone(),
            first_seen: Some(snapshot.timestamp),
            last_seen: Some(snapshot.timestamp),
            attributes: service_attrs,
        });

        graph.upsert_edge(GraphEdge {
            edge_id: stable_edge_id(&parent_id, &service_id, &EdgeKind::Exposes),
            from: parent_id.clone(),
            to: service_id.clone(),
            kind: EdgeKind::Exposes,
            target: snapshot.target.clone(),
            weight: 1,
            first_seen: Some(snapshot.timestamp),
            last_seen: Some(snapshot.timestamp),
            attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
        });

        for technology in &service.technologies {
            let tech_id = stable_node_id(&NodeKind::Technology, technology);

            graph.upsert_node(GraphNode {
                node_id: tech_id.clone(),
                kind: NodeKind::Technology,
                label: technology.clone(),
                target: snapshot.target.clone(),
                first_seen: Some(snapshot.timestamp),
                last_seen: Some(snapshot.timestamp),
                attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
            });

            graph.upsert_edge(GraphEdge {
                edge_id: stable_edge_id(&service_id, &tech_id, &EdgeKind::FingerprintsAs),
                from: service_id.clone(),
                to: tech_id,
                kind: EdgeKind::FingerprintsAs,
                target: snapshot.target.clone(),
                weight: 1,
                first_seen: Some(snapshot.timestamp),
                last_seen: Some(snapshot.timestamp),
                attributes: BTreeMap::from([("source".to_string(), "snapshot".to_string())]),
            });
        }
    }

    graph.recompute_metadata();
    graph
}

pub fn build_graph_from_timeline(report: &TimelineReport) -> ExposureGraph {
    #[derive(Default)]
    struct ResourceAgg {
        occurrences: usize,
        total_score: u32,
        first_seen: Option<DateTime<Utc>>,
        last_seen: Option<DateTime<Utc>>,
        highest_severity: String,
        highest_criticality: String,
        states: BTreeSet<String>,
        categories: BTreeSet<String>,
        asset_types: BTreeSet<String>,
    }

    let mut graph = ExposureGraph::empty(&report.target);
    let target_id = stable_node_id(&NodeKind::Target, &report.target);

    let mut resources: BTreeMap<String, ResourceAgg> = BTreeMap::new();

    for transition in &report.transitions {
        for finding in &transition.report.findings {
            let entry = resources.entry(finding.resource.clone()).or_default();
            entry.occurrences += 1;
            entry.total_score += finding.score;
            entry.first_seen = min_datetime(entry.first_seen, Some(transition.older_timestamp));
            entry.last_seen = max_datetime(entry.last_seen, Some(transition.newer_timestamp));
            entry.highest_severity =
                max_string(entry.highest_severity.clone(), finding.severity.to_string());
            entry.highest_criticality = max_string(
                entry.highest_criticality.clone(),
                finding.criticality.to_string(),
            );
            entry.states.insert(finding.state.to_string());
            entry.categories.insert(finding.category.clone());
            entry.asset_types.insert(finding.asset_type.to_string());
        }
    }

    for (resource, agg) in resources {
        let kind = infer_node_kind_from_resource(&resource);
        let node_id = stable_node_id(&kind, &resource);

        let mut attrs = BTreeMap::new();
        attrs.insert("source".to_string(), "timeline".to_string());
        attrs.insert("occurrences".to_string(), agg.occurrences.to_string());
        attrs.insert("total_score".to_string(), agg.total_score.to_string());
        attrs.insert("highest_severity".to_string(), agg.highest_severity);
        attrs.insert("highest_criticality".to_string(), agg.highest_criticality);
        attrs.insert(
            "states".to_string(),
            agg.states.into_iter().collect::<Vec<_>>().join(","),
        );
        attrs.insert(
            "categories".to_string(),
            agg.categories.into_iter().collect::<Vec<_>>().join(","),
        );
        attrs.insert(
            "asset_types".to_string(),
            agg.asset_types.into_iter().collect::<Vec<_>>().join(","),
        );

        graph.upsert_node(GraphNode {
            node_id: node_id.clone(),
            kind,
            label: resource.clone(),
            target: report.target.clone(),
            first_seen: agg.first_seen,
            last_seen: agg.last_seen,
            attributes: attrs,
        });

        graph.upsert_edge(GraphEdge {
            edge_id: stable_edge_id(&target_id, &node_id, &EdgeKind::BelongsTo),
            from: target_id.clone(),
            to: node_id,
            kind: EdgeKind::BelongsTo,
            target: report.target.clone(),
            weight: 1,
            first_seen: agg.first_seen,
            last_seen: agg.last_seen,
            attributes: BTreeMap::from([("source".to_string(), "timeline".to_string())]),
        });
    }

    graph.recompute_metadata();
    graph
}

pub fn build_graph_from_episode_collection(collection: &EpisodeCollection) -> ExposureGraph {
    let mut graph = ExposureGraph::empty(&collection.target);
    let target_id = stable_node_id(&NodeKind::Target, &collection.target);

    for episode in &collection.episodes {
        let episode_id = stable_node_id(&NodeKind::Episode, &episode.episode_id);

        let mut episode_attrs = BTreeMap::new();
        episode_attrs.insert("episode_id".to_string(), episode.episode_id.clone());
        episode_attrs.insert("kind".to_string(), episode.kind.to_string());
        episode_attrs.insert("severity".to_string(), episode.severity.to_string());
        episode_attrs.insert("criticality".to_string(), episode.criticality.to_string());
        episode_attrs.insert("state".to_string(), episode.state.to_string());
        episode_attrs.insert("score".to_string(), episode.score.to_string());
        episode_attrs.insert(
            "resource_count".to_string(),
            episode.resource_count.to_string(),
        );

        graph.upsert_node(GraphNode {
            node_id: episode_id.clone(),
            kind: NodeKind::Episode,
            label: episode.title.clone(),
            target: collection.target.clone(),
            first_seen: Some(episode.started_at),
            last_seen: Some(episode.ended_at),
            attributes: episode_attrs,
        });

        graph.upsert_edge(GraphEdge {
            edge_id: stable_edge_id(&target_id, &episode_id, &EdgeKind::Contains),
            from: target_id.clone(),
            to: episode_id.clone(),
            kind: EdgeKind::Contains,
            target: collection.target.clone(),
            weight: 1,
            first_seen: Some(episode.started_at),
            last_seen: Some(episode.ended_at),
            attributes: BTreeMap::from([("source".to_string(), "episodes".to_string())]),
        });

        for resource in &episode.resources {
            let kind = infer_node_kind_from_resource(resource);
            let resource_id = stable_node_id(&kind, resource);

            graph.upsert_node(GraphNode {
                node_id: resource_id.clone(),
                kind,
                label: resource.clone(),
                target: collection.target.clone(),
                first_seen: Some(episode.started_at),
                last_seen: Some(episode.ended_at),
                attributes: BTreeMap::from([("source".to_string(), "episodes".to_string())]),
            });

            graph.upsert_edge(GraphEdge {
                edge_id: stable_edge_id(&resource_id, &episode_id, &EdgeKind::ParticipatesIn),
                from: resource_id,
                to: episode_id.clone(),
                kind: EdgeKind::ParticipatesIn,
                target: collection.target.clone(),
                weight: 1,
                first_seen: Some(episode.started_at),
                last_seen: Some(episode.ended_at),
                attributes: BTreeMap::from([("source".to_string(), "episodes".to_string())]),
            });
        }
    }

    graph.recompute_metadata();
    graph
}

pub fn infer_node_kind_from_resource(resource: &str) -> NodeKind {
    if resource.parse::<IpAddr>().is_ok() {
        NodeKind::Ip
    } else if resource.starts_with("http://") || resource.starts_with("https://") {
        NodeKind::Service
    } else if resource.contains('.') {
        NodeKind::Subdomain
    } else {
        NodeKind::Target
    }
}

pub fn infer_node_kind_from_asset_type(asset_type: &AssetType, resource: &str) -> NodeKind {
    match asset_type {
        AssetType::Ip => NodeKind::Ip,
        AssetType::Subdomain => NodeKind::Subdomain,
        AssetType::Service => NodeKind::Service,
        AssetType::Unknown => infer_node_kind_from_resource(resource),
    }
}

fn stable_node_id(kind: &NodeKind, raw: &str) -> String {
    stable_hash(&format!("node|{}|{}", kind, raw))
}

fn stable_edge_id(from: &str, to: &str, kind: &EdgeKind) -> String {
    stable_hash(&format!("edge|{}|{}|{}", from, to, kind))
}

fn stable_hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let hex = hex::encode(digest);
    hex[..24].to_string()
}

fn compute_stats(nodes: &[GraphNode], edges: &[GraphEdge]) -> GraphStats {
    let mut stats = GraphStats::default();

    for node in nodes {
        match node.kind {
            NodeKind::Target => stats.targets += 1,
            NodeKind::Subdomain => stats.subdomains += 1,
            NodeKind::Ip => stats.ips += 1,
            NodeKind::Service => stats.services += 1,
            NodeKind::Technology => stats.technologies += 1,
            NodeKind::Episode => stats.episodes += 1,
        }
    }

    for edge in edges {
        match edge.kind {
            EdgeKind::Contains => stats.contains_edges += 1,
            EdgeKind::ResolvesTo => stats.resolves_to_edges += 1,
            EdgeKind::Exposes => stats.exposes_edges += 1,
            EdgeKind::FingerprintsAs => stats.fingerprints_as_edges += 1,
            EdgeKind::ParticipatesIn => stats.participates_in_edges += 1,
            EdgeKind::BelongsTo => stats.belongs_to_edges += 1,
        }
    }

    stats
}

fn compute_topology(nodes: &[GraphNode], edges: &[GraphEdge]) -> GraphTopologySummary {
    let mut degree_map: BTreeMap<String, usize> = BTreeMap::new();

    for node in nodes {
        degree_map.entry(node.node_id.clone()).or_insert(0);
    }

    for edge in edges {
        *degree_map.entry(edge.from.clone()).or_insert(0) += 1;
        *degree_map.entry(edge.to.clone()).or_insert(0) += 1;
    }

    let connected_nodes = degree_map.values().filter(|degree| **degree > 0).count();
    let isolated_nodes = degree_map.values().filter(|degree| **degree == 0).count();
    let max_degree = degree_map.values().copied().max().unwrap_or(0);

    let mut highest_degree_nodes = Vec::new();
    for node in nodes {
        let degree = degree_map.get(&node.node_id).copied().unwrap_or(0);
        highest_degree_nodes.push(RankedGraphNode {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            kind: node.kind.clone(),
            degree,
        });
    }

    highest_degree_nodes.sort_by(|a, b| {
        b.degree
            .cmp(&a.degree)
            .then_with(|| a.label.cmp(&b.label))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    highest_degree_nodes.truncate(5);

    GraphTopologySummary {
        connected_nodes,
        isolated_nodes,
        max_degree,
        highest_degree_nodes,
    }
}

fn min_datetime(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn max_datetime(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn max_string(a: String, b: String) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => b,
        (false, true) => a,
        (false, false) => std::cmp::max(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::{HttpService, ScanResult, SecurityHeaders};
    use atlas_correlation::CorrelationKind;
    use atlas_drift::{
        AssetType, CategoryAggregate, Criticality, DriftFinding, Environment, FindingState,
        ResourceAggregate, Severity, TimelineExecutiveSummary, TimelineTransition,
    };
    use atlas_episodes::{EpisodeState, RiskEpisode};

    fn headers() -> SecurityHeaders {
        SecurityHeaders {
            strict_transport_security: false,
            content_security_policy: false,
            x_frame_options: false,
            x_content_type_options: false,
            referrer_policy: false,
        }
    }

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            snapshot_version: 2,
            timestamp: Utc::now(),
            target: "example.com".to_string(),
            scan: ScanResult {
                target: "example.com".to_string(),
                resolved_ips: vec!["1.1.1.1".to_string()],
                subdomains: vec!["admin.example.com".to_string()],
                services: vec![HttpService {
                    host: "admin.example.com".to_string(),
                    url: "https://admin.example.com".to_string(),
                    scheme: "https".to_string(),
                    status: 200,
                    server: Some("nginx".to_string()),
                    title: Some("Admin".to_string()),
                    content_type: Some("text/html".to_string()),
                    technologies: vec!["nginx".to_string(), "rust".to_string()],
                    provider: Some("cloudflare".to_string()),
                    tls_enabled: true,
                    security_headers: headers(),
                }],
            },
        }
    }

    #[test]
    fn builds_snapshot_graph_with_expected_nodes_and_edges() {
        let graph = build_graph_from_snapshot(&sample_snapshot());

        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Target));
        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Subdomain));
        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Ip));
        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Service));
        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Technology));

        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::Contains));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::ResolvesTo));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::Exposes));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.kind == EdgeKind::FingerprintsAs));
    }

    #[test]
    fn builds_episode_graph_with_participation_edges() {
        let collection = EpisodeCollection {
            target: "example.com".to_string(),
            episode_count: 1,
            episodes: vec![RiskEpisode {
                episode_id: "ep-1".to_string(),
                target: "example.com".to_string(),
                title: "Episodio test".to_string(),
                kind: atlas_correlation_kind_placeholder(),
                severity: Severity::High,
                criticality: Criticality::Critical,
                score: 150,
                state: EpisodeState::New,
                resource_count: 2,
                resources: vec![
                    "admin.example.com".to_string(),
                    "https://admin.example.com".to_string(),
                ],
                cluster_ids: vec!["c1".to_string()],
                started_at: Utc::now(),
                ended_at: Utc::now(),
                summary: "summary".to_string(),
                explanation: vec!["exp".to_string()],
            }],
        };

        let graph = build_graph_from_episode_collection(&collection);

        assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::Episode));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.kind == EdgeKind::ParticipatesIn));
    }

    #[test]
    fn merge_deduplicates_nodes_and_edges() {
        let snapshot = sample_snapshot();
        let mut graph_a = build_graph_from_snapshot(&snapshot);
        let graph_b = build_graph_from_snapshot(&snapshot);

        let before_nodes = graph_a.node_count;
        let before_edges = graph_a.edge_count;

        graph_a.merge(&graph_b);

        assert_eq!(graph_a.node_count, before_nodes);
        assert_eq!(graph_a.edge_count, before_edges);
    }

    #[test]
    fn builds_timeline_graph() {
        let finding = DriftFinding {
            finding_id: "f1".to_string(),
            severity: Severity::High,
            score: 90,
            category: "new_admin_subdomain".to_string(),
            title: "Nuevo subdominio administrativo".to_string(),
            resource: "admin.example.com".to_string(),
            asset_type: AssetType::Subdomain,
            environment: Environment::Admin,
            criticality: Criticality::Critical,
            state: FindingState::Persistent,
            tags: vec!["admin".to_string()],
            description: "desc".to_string(),
        };

        let now = Utc::now();

        let timeline = TimelineReport {
            target: "example.com".to_string(),
            snapshot_count: 3,
            transition_count: 1,
            transitions: vec![TimelineTransition {
                older_timestamp: now,
                newer_timestamp: now,
                report: atlas_drift::DriftReport {
                    target: "example.com".to_string(),
                    older_timestamp: now,
                    newer_timestamp: now,
                    findings: vec![finding],
                    suppressed_findings: vec![],
                    groups: vec![],
                    summary: atlas_drift::DriftSummary::default(),
                },
            }],
            executive: TimelineExecutiveSummary {
                total_score: 90,
                overall_severity: Severity::High,
                total_findings: 1,
                unique_resources: 1,
                critical_findings: 1,
                recurring_findings: 0,
                persistent_findings: 1,
                asset_types: atlas_drift::AssetTypeSummary::default(),
                top_resources: vec![ResourceAggregate {
                    resource: "admin.example.com".to_string(),
                    occurrences: 1,
                    total_score: 90,
                }],
                top_categories: vec![CategoryAggregate {
                    category: "new_admin_subdomain".to_string(),
                    occurrences: 1,
                    total_score: 90,
                }],
            },
        };

        let graph = build_graph_from_timeline(&timeline);
        assert!(graph.nodes.iter().any(|n| n.label == "admin.example.com"));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::BelongsTo));
    }

    fn atlas_correlation_kind_placeholder() -> CorrelationKind {
        CorrelationKind::AdministrativeExposure
    }
}
