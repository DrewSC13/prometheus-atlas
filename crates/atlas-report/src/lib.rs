use atlas_drift::{Severity, TimelineReport};
use atlas_episodes::{EpisodeCollection, EpisodeState};
use atlas_graph::ExposureGraph;
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReport {
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub snapshot_count: usize,
    pub latest_snapshot_at: Option<DateTime<Utc>>,
    pub policy_applied: bool,
    pub overview: OverviewSection,
    pub top_findings: Vec<ExecutiveFinding>,
    pub hotspots: Vec<ResourceHotspot>,
    pub episodes: EpisodeOverview,
    pub graph: GraphOverview,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewSection {
    pub total_score: u32,
    pub overall_severity: String,
    pub total_findings: usize,
    pub unique_resources: usize,
    pub critical_findings: usize,
    pub recurring_findings: usize,
    pub persistent_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveFinding {
    pub finding_id: String,
    pub title: String,
    pub category: String,
    pub resource: String,
    pub severity: String,
    pub criticality: String,
    pub state: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceHotspot {
    pub resource: String,
    pub total_score: u32,
    pub occurrences: usize,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeOverview {
    pub total_episodes: usize,
    pub by_state: BTreeMap<String, usize>,
    pub by_kind: BTreeMap<String, usize>,
    pub top_episodes: Vec<ExecutiveEpisode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveEpisode {
    pub episode_id: String,
    pub title: String,
    pub kind: String,
    pub severity: String,
    pub criticality: String,
    pub state: String,
    pub score: u32,
    pub resource_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphOverview {
    pub node_count: usize,
    pub edge_count: usize,
    pub connected_nodes: usize,
    pub isolated_nodes: usize,
    pub max_degree: usize,
    pub highest_degree_labels: Vec<String>,
}

pub fn build_executive_report(
    target: &str,
    snapshots: &[Snapshot],
    timeline: Option<&TimelineReport>,
    episodes: Option<&EpisodeCollection>,
    graph: &ExposureGraph,
    policy_applied: bool,
) -> ExecutiveReport {
    let generated_at = Utc::now();
    let latest_snapshot_at = snapshots.last().map(|snapshot| snapshot.timestamp);

    let overview = build_overview(timeline);
    let top_findings = build_top_findings(timeline);
    let hotspots = build_hotspots(timeline);
    let episode_overview = build_episode_overview(episodes);
    let graph_overview = build_graph_overview(graph);
    let recommendations = build_recommendations(
        timeline,
        episodes,
        graph,
        policy_applied,
        &top_findings,
        &hotspots,
    );

    ExecutiveReport {
        target: target.to_string(),
        generated_at,
        snapshot_count: snapshots.len(),
        latest_snapshot_at,
        policy_applied,
        overview,
        top_findings,
        hotspots,
        episodes: episode_overview,
        graph: graph_overview,
        recommendations,
    }
}

fn build_overview(timeline: Option<&TimelineReport>) -> OverviewSection {
    if let Some(timeline) = timeline {
        OverviewSection {
            total_score: timeline.executive.total_score,
            overall_severity: timeline.executive.overall_severity.to_string(),
            total_findings: timeline.executive.total_findings,
            unique_resources: timeline.executive.unique_resources,
            critical_findings: timeline.executive.critical_findings,
            recurring_findings: timeline.executive.recurring_findings,
            persistent_findings: timeline.executive.persistent_findings,
        }
    } else {
        OverviewSection {
            total_score: 0,
            overall_severity: Severity::Info.to_string(),
            total_findings: 0,
            unique_resources: 0,
            critical_findings: 0,
            recurring_findings: 0,
            persistent_findings: 0,
        }
    }
}

fn build_top_findings(timeline: Option<&TimelineReport>) -> Vec<ExecutiveFinding> {
    let Some(timeline) = timeline else {
        return Vec::new();
    };

    let mut findings = timeline
        .transitions
        .iter()
        .flat_map(|transition| transition.report.findings.iter())
        .map(|finding| ExecutiveFinding {
            finding_id: finding.finding_id.clone(),
            title: finding.title.clone(),
            category: finding.category.clone(),
            resource: finding.resource.clone(),
            severity: finding.severity.to_string(),
            criticality: finding.criticality.to_string(),
            state: finding.state.to_string(),
            score: finding.score,
        })
        .collect::<Vec<_>>();

    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.resource.cmp(&b.resource))
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    findings.truncate(10);
    findings
}

fn build_hotspots(timeline: Option<&TimelineReport>) -> Vec<ResourceHotspot> {
    let Some(timeline) = timeline else {
        return Vec::new();
    };

    let mut by_resource: BTreeMap<String, (u32, usize, BTreeSet<String>)> = BTreeMap::new();

    for transition in &timeline.transitions {
        for finding in &transition.report.findings {
            let entry =
                by_resource
                    .entry(finding.resource.clone())
                    .or_insert((0, 0, BTreeSet::new()));
            entry.0 += finding.score;
            entry.1 += 1;
            entry.2.insert(finding.category.clone());
        }
    }

    let mut hotspots = by_resource
        .into_iter()
        .map(
            |(resource, (total_score, occurrences, categories))| ResourceHotspot {
                resource,
                total_score,
                occurrences,
                categories: categories.into_iter().collect(),
            },
        )
        .collect::<Vec<_>>();

    hotspots.sort_by(|a, b| {
        b.total_score
            .cmp(&a.total_score)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.resource.cmp(&b.resource))
    });
    hotspots.truncate(10);
    hotspots
}

fn build_episode_overview(episodes: Option<&EpisodeCollection>) -> EpisodeOverview {
    let Some(collection) = episodes else {
        return EpisodeOverview {
            total_episodes: 0,
            by_state: BTreeMap::new(),
            by_kind: BTreeMap::new(),
            top_episodes: Vec::new(),
        };
    };

    let mut by_state = BTreeMap::new();
    let mut by_kind = BTreeMap::new();

    for episode in &collection.episodes {
        *by_state.entry(episode.state.to_string()).or_insert(0) += 1;
        *by_kind.entry(episode.kind.to_string()).or_insert(0) += 1;
    }

    let mut top_episodes = collection
        .episodes
        .iter()
        .map(|episode| ExecutiveEpisode {
            episode_id: episode.episode_id.clone(),
            title: episode.title.clone(),
            kind: episode.kind.to_string(),
            severity: episode.severity.to_string(),
            criticality: episode.criticality.to_string(),
            state: episode.state.to_string(),
            score: episode.score,
            resource_count: episode.resource_count,
        })
        .collect::<Vec<_>>();

    top_episodes.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.episode_id.cmp(&b.episode_id))
    });
    top_episodes.truncate(5);

    EpisodeOverview {
        total_episodes: collection.episode_count,
        by_state,
        by_kind,
        top_episodes,
    }
}

fn build_graph_overview(graph: &ExposureGraph) -> GraphOverview {
    GraphOverview {
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        connected_nodes: graph.topology.connected_nodes,
        isolated_nodes: graph.topology.isolated_nodes,
        max_degree: graph.topology.max_degree,
        highest_degree_labels: graph
            .topology
            .highest_degree_nodes
            .iter()
            .map(|node| format!("{} [{}]", node.label, node.kind))
            .collect(),
    }
}

fn build_recommendations(
    timeline: Option<&TimelineReport>,
    episodes: Option<&EpisodeCollection>,
    graph: &ExposureGraph,
    policy_applied: bool,
    top_findings: &[ExecutiveFinding],
    hotspots: &[ResourceHotspot],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    if let Some(top) = top_findings.first() {
        recommendations.push(format!(
            "Investigar primero el hallazgo más severo: '{}' sobre {} (score {}).",
            top.title, top.resource, top.score
        ));
    }

    if hotspots
        .iter()
        .any(|item| item.resource.starts_with("http://"))
    {
        recommendations.push(
            "Priorizar migración o eliminación de servicios HTTP en claro detectados en hotspots."
                .to_string(),
        );
    }

    if let Some(timeline) = timeline {
        if timeline.executive.persistent_findings > 0 {
            recommendations.push(
                "Hay hallazgos persistentes; conviene abrir seguimiento formal para recursos reincidentes."
                    .to_string(),
            );
        }

        if timeline.executive.recurring_findings > 0 {
            recommendations.push(
                "Los hallazgos recurrentes sugieren drift operacional; revisar cambios frecuentes en superficie expuesta."
                    .to_string(),
            );
        }

        if timeline.executive.critical_findings > 0 {
            recommendations.push(
                "Existen activos críticos implicados; validar ownership, exposición pública y controles compensatorios."
                    .to_string(),
            );
        }
    }

    if let Some(collection) = episodes {
        if collection.episodes.iter().any(|episode| {
            matches!(
                episode.state,
                EpisodeState::Persistent | EpisodeState::Recurring
            )
        }) {
            recommendations.push(
                "Los episodios recurrentes/persistentes deben convertirse en iniciativas de remediación estructural."
                    .to_string(),
            );
        }
    }

    if graph.topology.max_degree >= 8 {
        recommendations.push(
            "Los nodos hub del grafo deberían revisarse primero, porque concentran relaciones y superficie de impacto."
                .to_string(),
        );
    }

    if policy_applied {
        recommendations.push(
            "El reporte fue generado con policy activa; revisar periódicamente suppressions y baselines para evitar ceguera operativa."
                .to_string(),
        );
    }

    if recommendations.is_empty() {
        recommendations.push(
            "No se identificaron señales críticas inmediatas; mantener monitoreo periódico y snapshots comparables."
                .to_string(),
        );
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_correlation::CorrelationKind;
    use atlas_drift::{
        AssetType, CategoryAggregate, Criticality, DriftFinding, DriftGroup, DriftReport,
        DriftSummary, Environment, FindingState, ResourceAggregate, Severity,
        TimelineExecutiveSummary, TimelineTransition,
    };
    use atlas_episodes::{EpisodeCollection, RiskEpisode};
    use atlas_graph::ExposureGraph;

    #[test]
    fn builds_report_from_analysis_objects() {
        let now = Utc::now();

        let snapshots = vec![Snapshot {
            snapshot_version: 2,
            timestamp: now,
            target: "example.com".to_string(),
            scan: atlas_core::ScanResult::default(),
        }];

        let finding = DriftFinding {
            finding_id: "f1".to_string(),
            severity: Severity::High,
            score: 95,
            category: "new_admin_subdomain".to_string(),
            title: "Nuevo subdominio administrativo".to_string(),
            resource: "admin.example.com".to_string(),
            asset_type: AssetType::Subdomain,
            environment: Environment::Admin,
            criticality: Criticality::Critical,
            state: FindingState::New,
            tags: vec!["admin".to_string()],
            description: "desc".to_string(),
        };

        let timeline = TimelineReport {
            target: "example.com".to_string(),
            snapshot_count: 2,
            transition_count: 1,
            transitions: vec![TimelineTransition {
                older_timestamp: now,
                newer_timestamp: now,
                report: DriftReport {
                    target: "example.com".to_string(),
                    older_timestamp: now,
                    newer_timestamp: now,
                    findings: vec![finding.clone()],
                    suppressed_findings: vec![],
                    groups: vec![DriftGroup {
                        resource: finding.resource.clone(),
                        findings: vec![finding.clone()],
                        highest_severity: finding.severity.clone(),
                        highest_criticality: finding.criticality.clone(),
                        total_score: finding.score,
                    }],
                    summary: DriftSummary {
                        high: 1,
                        medium: 0,
                        low: 0,
                        info: 0,
                        total_score: 95,
                        overall_severity: Severity::High,
                        critical_findings: 1,
                        asset_types: Default::default(),
                        states: Default::default(),
                    },
                },
            }],
            executive: TimelineExecutiveSummary {
                total_score: 95,
                overall_severity: Severity::High,
                total_findings: 1,
                unique_resources: 1,
                critical_findings: 1,
                recurring_findings: 0,
                persistent_findings: 0,
                asset_types: Default::default(),
                top_resources: vec![ResourceAggregate {
                    resource: "admin.example.com".to_string(),
                    occurrences: 1,
                    total_score: 95,
                }],
                top_categories: vec![CategoryAggregate {
                    category: "new_admin_subdomain".to_string(),
                    occurrences: 1,
                    total_score: 95,
                }],
            },
        };

        let episodes = EpisodeCollection {
            target: "example.com".to_string(),
            episode_count: 1,
            episodes: vec![RiskEpisode {
                episode_id: "ep1".to_string(),
                target: "example.com".to_string(),
                title: "Episodio administrativo".to_string(),
                kind: CorrelationKind::AdministrativeExposure,
                severity: Severity::High,
                criticality: Criticality::Critical,
                score: 180,
                state: EpisodeState::New,
                resource_count: 1,
                resources: vec!["admin.example.com".to_string()],
                cluster_ids: vec!["c1".to_string()],
                started_at: now,
                ended_at: now,
                summary: "sum".to_string(),
                explanation: vec!["exp".to_string()],
            }],
        };

        let graph = ExposureGraph::empty("example.com");

        let report = build_executive_report(
            "example.com",
            &snapshots,
            Some(&timeline),
            Some(&episodes),
            &graph,
            true,
        );

        assert_eq!(report.target, "example.com");
        assert_eq!(report.snapshot_count, 1);
        assert_eq!(report.overview.total_findings, 1);
        assert_eq!(report.episodes.total_episodes, 1);
        assert!(!report.recommendations.is_empty());
    }
}
