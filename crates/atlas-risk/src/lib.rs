use atlas_drift::TimelineReport;
use atlas_episodes::EpisodeCollection;
use atlas_graph::{ExposureGraph, NodeKind};
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskSeverity::Low => write!(f, "LOW"),
            RiskSeverity::Medium => write!(f, "MEDIUM"),
            RiskSeverity::High => write!(f, "HIGH"),
            RiskSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskItem {
    pub rule_id: String,
    pub title: String,
    pub severity: RiskSeverity,
    pub score: u32,
    pub resource: String,
    pub kind: String,
    pub description: String,
    pub recommendation: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub total_risks: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total_score: u32,
    pub top_risks: Vec<RiskItem>,
    pub risks: Vec<RiskItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSummary {
    pub subdomains: usize,
    pub ips: usize,
    pub services: usize,
    pub technologies: usize,
    pub episodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureSummary {
    pub critical_risks: usize,
    pub high_risks: usize,
    pub medium_risks: usize,
    pub low_risks: usize,
    pub total_risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftSummaryView {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub recurring_findings: usize,
    pub persistent_findings: usize,
    pub top_resources: Vec<SummaryResourceHotspot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryResourceHotspot {
    pub resource: String,
    pub occurrences: usize,
    pub total_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummaryView {
    pub node_count: usize,
    pub edge_count: usize,
    pub connected_nodes: usize,
    pub isolated_nodes: usize,
    pub max_degree: usize,
    pub hubs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub snapshot_count: usize,
    pub latest_snapshot_at: Option<DateTime<Utc>>,
    pub assets: AssetSummary,
    pub exposure: ExposureSummary,
    pub drift: Option<DriftSummaryView>,
    pub graph: GraphSummaryView,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub created_at: DateTime<Utc>,
    pub severity: RiskSeverity,
    pub title: String,
    pub resource: String,
    pub message: String,
}

pub fn build_risk_report(
    target: &str,
    timeline: Option<&TimelineReport>,
    episodes: Option<&EpisodeCollection>,
    graph: &ExposureGraph,
) -> RiskReport {
    let generated_at = Utc::now();
    let mut risks = Vec::new();
    let mut seen = BTreeSet::new();
    let degree_map = build_degree_map(graph);

    for node in &graph.nodes {
        if node.kind == NodeKind::Service {
            let scheme = node.attributes.get("scheme").cloned().unwrap_or_default();
            let tls_enabled = node
                .attributes
                .get("tls_enabled")
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let title = node.attributes.get("title").cloned().unwrap_or_default();
            let status = node.attributes.get("status").cloned().unwrap_or_default();
            let provider = node.attributes.get("provider").cloned().unwrap_or_default();

            if scheme.eq_ignore_ascii_case("http") {
                push_risk(
                    &mut risks,
                    &mut seen,
                    RiskItem {
                        rule_id: "plaintext-http-service".to_string(),
                        title: "Servicio HTTP expuesto sin cifrado".to_string(),
                        severity: if is_admin_label(&node.label) {
                            RiskSeverity::Critical
                        } else {
                            RiskSeverity::High
                        },
                        score: if is_admin_label(&node.label) { 95 } else { 70 },
                        resource: node.label.clone(),
                        kind: "service".to_string(),
                        description: format!(
                            "El servicio {} está expuesto sobre HTTP sin TLS.",
                            node.label
                        ),
                        recommendation:
                            "Migrar el servicio a HTTPS o retirar la exposición pública."
                                .to_string(),
                        evidence: compact_evidence(&[
                            Some(format!("scheme={scheme}")),
                            Some(format!("status={status}")),
                            non_empty_kv("provider", &provider),
                            non_empty_kv("title", &title),
                        ]),
                    },
                );
            }

            if is_admin_label(&node.label) {
                push_risk(
                    &mut risks,
                    &mut seen,
                    RiskItem {
                        rule_id: "admin-surface-exposed".to_string(),
                        title: "Superficie administrativa expuesta".to_string(),
                        severity: if tls_enabled {
                            RiskSeverity::High
                        } else {
                            RiskSeverity::Critical
                        },
                        score: if tls_enabled { 85 } else { 100 },
                        resource: node.label.clone(),
                        kind: "service".to_string(),
                        description: format!(
                            "El servicio {} presenta patrón administrativo y está expuesto.",
                            node.label
                        ),
                        recommendation:
                            "Restringir acceso, validar autenticación fuerte y limitar exposición."
                                .to_string(),
                        evidence: compact_evidence(&[
                            Some("pattern=admin".to_string()),
                            Some(format!("tls_enabled={tls_enabled}")),
                            Some(format!(
                                "degree={}",
                                degree_map.get(&node.node_id).copied().unwrap_or(0)
                            )),
                        ]),
                    },
                );
            }

            if !tls_enabled && scheme.eq_ignore_ascii_case("https") {
                push_risk(
                    &mut risks,
                    &mut seen,
                    RiskItem {
                        rule_id: "https-without-tls-flag".to_string(),
                        title: "Servicio HTTPS con señal inconsistente de TLS".to_string(),
                        severity: RiskSeverity::Medium,
                        score: 40,
                        resource: node.label.clone(),
                        kind: "service".to_string(),
                        description: format!(
                            "El servicio {} usa esquema HTTPS pero tls_enabled=false.",
                            node.label
                        ),
                        recommendation:
                            "Validar la detección HTTP/TLS y revisar la configuración del servicio."
                                .to_string(),
                        evidence: vec!["scheme=https".to_string(), "tls_enabled=false".to_string()],
                    },
                );
            }
        }

        if node.kind == NodeKind::Subdomain && is_admin_label(&node.label) {
            push_risk(
                &mut risks,
                &mut seen,
                RiskItem {
                    rule_id: "admin-subdomain-exposed".to_string(),
                    title: "Subdominio administrativo detectado".to_string(),
                    severity: RiskSeverity::High,
                    score: 65,
                    resource: node.label.clone(),
                    kind: "subdomain".to_string(),
                    description: format!(
                        "El subdominio {} parece pertenecer a una superficie administrativa.",
                        node.label
                    ),
                    recommendation:
                        "Validar si el subdominio debe seguir expuesto y confirmar ownership."
                            .to_string(),
                    evidence: vec!["pattern=admin".to_string()],
                },
            );
        }

        let degree = degree_map.get(&node.node_id).copied().unwrap_or(0);
        if degree >= 8 && matches!(node.kind, NodeKind::Service | NodeKind::Subdomain) {
            push_risk(
                &mut risks,
                &mut seen,
                RiskItem {
                    rule_id: "high-degree-hub".to_string(),
                    title: "Nodo hub con alta conectividad".to_string(),
                    severity: RiskSeverity::Medium,
                    score: 35,
                    resource: node.label.clone(),
                    kind: node.kind.to_string(),
                    description: format!(
                        "El nodo {} concentra relaciones en el grafo (degree={}).",
                        node.label, degree
                    ),
                    recommendation:
                        "Revisar primero este nodo durante análisis de impacto y remediación."
                            .to_string(),
                    evidence: vec![format!("degree={degree}")],
                },
            );
        }
    }

    if let Some(timeline) = timeline {
        if timeline.executive.critical_findings > 0 && timeline.executive.persistent_findings > 0 {
            push_risk(
                &mut risks,
                &mut seen,
                RiskItem {
                    rule_id: "persistent-critical-drift".to_string(),
                    title: "Drift crítico persistente".to_string(),
                    severity: RiskSeverity::Critical,
                    score: 110,
                    resource: target.to_string(),
                    kind: "target".to_string(),
                    description:
                        "Existen hallazgos críticos persistentes en el timeline del target."
                            .to_string(),
                    recommendation:
                        "Priorizar remediación estructural de los recursos reincidentes."
                            .to_string(),
                    evidence: vec![
                        format!("critical_findings={}", timeline.executive.critical_findings),
                        format!(
                            "persistent_findings={}",
                            timeline.executive.persistent_findings
                        ),
                        format!("total_score={}", timeline.executive.total_score),
                    ],
                },
            );
        }

        for item in timeline.executive.top_resources.iter().take(3) {
            if item.total_score >= 80 {
                push_risk(
                    &mut risks,
                    &mut seen,
                    RiskItem {
                        rule_id: "hotspot-resource".to_string(),
                        title: "Recurso hotspot con score acumulado alto".to_string(),
                        severity: if item.total_score >= 140 {
                            RiskSeverity::High
                        } else {
                            RiskSeverity::Medium
                        },
                        score: item.total_score.min(160),
                        resource: item.resource.clone(),
                        kind: "resource".to_string(),
                        description: format!(
                            "El recurso {} acumula score {} en el timeline.",
                            item.resource, item.total_score
                        ),
                        recommendation:
                            "Analizar historial del recurso y validar si requiere hardening específico."
                                .to_string(),
                        evidence: vec![
                            format!("occurrences={}", item.occurrences),
                            format!("total_score={}", item.total_score),
                        ],
                    },
                );
            }
        }
    }

    if let Some(collection) = episodes {
        for episode in collection.episodes.iter().take(5) {
            let severity = if episode.score >= 180 {
                RiskSeverity::Critical
            } else if episode.score >= 120 {
                RiskSeverity::High
            } else {
                RiskSeverity::Medium
            };

            push_risk(
                &mut risks,
                &mut seen,
                RiskItem {
                    rule_id: "high-risk-episode".to_string(),
                    title: "Episodio de riesgo relevante".to_string(),
                    severity,
                    score: episode.score,
                    resource: episode.title.clone(),
                    kind: "episode".to_string(),
                    description: format!(
                        "El episodio '{}' refleja un evento compuesto de riesgo sobre {} recursos.",
                        episode.title, episode.resource_count
                    ),
                    recommendation:
                        "Revisar el episodio completo y coordinar remediación sobre los recursos asociados."
                            .to_string(),
                    evidence: vec![
                        format!("episode_kind={}", episode.kind),
                        format!("state={}", episode.state),
                        format!("resource_count={}", episode.resource_count),
                    ],
                },
            );
        }
    }

    risks.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.resource.cmp(&b.resource))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut total_score = 0u32;

    for item in &risks {
        total_score += item.score;
        match item.severity {
            RiskSeverity::Critical => critical += 1,
            RiskSeverity::High => high += 1,
            RiskSeverity::Medium => medium += 1,
            RiskSeverity::Low => low += 1,
        }
    }

    let mut top_risks = risks.clone();
    top_risks.truncate(10);

    RiskReport {
        target: target.to_string(),
        generated_at,
        total_risks: risks.len(),
        critical,
        high,
        medium,
        low,
        total_score,
        top_risks,
        risks,
    }
}

pub fn build_summary_report(
    target: &str,
    snapshots: &[Snapshot],
    timeline: Option<&TimelineReport>,
    episodes: Option<&EpisodeCollection>,
    graph: &ExposureGraph,
) -> SummaryReport {
    let risk = build_risk_report(target, timeline, episodes, graph);

    let assets = AssetSummary {
        subdomains: graph.stats.subdomains,
        ips: graph.stats.ips,
        services: graph.stats.services,
        technologies: graph.stats.technologies,
        episodes: graph.stats.episodes,
    };

    let exposure = ExposureSummary {
        critical_risks: risk.critical,
        high_risks: risk.high,
        medium_risks: risk.medium,
        low_risks: risk.low,
        total_risk_score: risk.total_score,
    };

    let drift = timeline.map(|timeline| DriftSummaryView {
        total_findings: timeline.executive.total_findings,
        critical_findings: timeline.executive.critical_findings,
        recurring_findings: timeline.executive.recurring_findings,
        persistent_findings: timeline.executive.persistent_findings,
        top_resources: timeline
            .executive
            .top_resources
            .iter()
            .take(5)
            .map(|item| SummaryResourceHotspot {
                resource: item.resource.clone(),
                occurrences: item.occurrences,
                total_score: item.total_score,
            })
            .collect(),
    });

    let graph_summary = GraphSummaryView {
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        connected_nodes: graph.topology.connected_nodes,
        isolated_nodes: graph.topology.isolated_nodes,
        max_degree: graph.topology.max_degree,
        hubs: graph
            .topology
            .highest_degree_nodes
            .iter()
            .map(|node| format!("{} [{}]", node.label, node.kind))
            .collect(),
    };

    let recommendations = build_summary_recommendations(&risk, &graph_summary, drift.as_ref());

    SummaryReport {
        target: target.to_string(),
        generated_at: Utc::now(),
        snapshot_count: snapshots.len(),
        latest_snapshot_at: snapshots.last().map(|snapshot| snapshot.timestamp),
        assets,
        exposure,
        drift,
        graph: graph_summary,
        recommendations,
    }
}

pub fn build_basic_alerts(report: &RiskReport) -> Vec<AlertEvent> {
    let mut alerts = Vec::new();

    for risk in report
        .risks
        .iter()
        .filter(|item| matches!(item.severity, RiskSeverity::Critical | RiskSeverity::High))
        .take(10)
    {
        alerts.push(AlertEvent {
            created_at: Utc::now(),
            severity: risk.severity.clone(),
            title: risk.title.clone(),
            resource: risk.resource.clone(),
            message: format!(
                "{} | resource={} | score={} | recommendation={}",
                risk.description, risk.resource, risk.score, risk.recommendation
            ),
        });
    }

    alerts
}

fn build_summary_recommendations(
    risk: &RiskReport,
    graph: &GraphSummaryView,
    drift: Option<&DriftSummaryView>,
) -> Vec<String> {
    let mut items = Vec::new();

    if let Some(top) = risk.top_risks.first() {
        items.push(format!(
            "Investigar primero '{}' sobre {} (score {}).",
            top.title, top.resource, top.score
        ));
    }

    if risk.critical > 0 {
        items.push(
            "Existen riesgos críticos; conviene activar remediación inmediata y validación manual."
                .to_string(),
        );
    }

    if let Some(drift) = drift {
        if drift.persistent_findings > 0 {
            items.push(
                "Hay drift persistente; priorizar recursos reincidentes y revisar ownership."
                    .to_string(),
            );
        }

        if drift.recurring_findings > 0 {
            items.push(
                "Los hallazgos recurrentes sugieren cambios operativos frecuentes en superficie expuesta."
                    .to_string(),
            );
        }
    }

    if graph.max_degree >= 8 {
        items.push(
            "Los hubs del grafo deben revisarse primero por su concentración de relaciones."
                .to_string(),
        );
    }

    if items.is_empty() {
        items.push(
            "No se detectan señales críticas inmediatas; mantener snapshots y monitoreo continuo."
                .to_string(),
        );
    }

    items
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

fn push_risk(risks: &mut Vec<RiskItem>, seen: &mut BTreeSet<String>, item: RiskItem) {
    let key = format!("{}|{}", item.rule_id, item.resource);
    if seen.insert(key) {
        risks.push(item);
    }
}

fn is_admin_label(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("admin")
}

fn non_empty_kv(key: &str, value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(format!("{key}={value}"))
    }
}

fn compact_evidence(items: &[Option<String>]) -> Vec<String> {
    items.iter().flatten().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::{HttpService, ScanResult, SecurityHeaders};
    use atlas_drift::{
        AssetType, CategoryAggregate, Criticality, DriftFinding, DriftGroup, DriftReport,
        DriftSummary, Environment, FindingState, ResourceAggregate, Severity,
        TimelineExecutiveSummary, TimelineTransition,
    };
    use atlas_episodes::{EpisodeCollection, EpisodeState, RiskEpisode};
    use atlas_graph::{build_full_graph, ExposureGraph};
    use chrono::Utc;

    fn headers() -> SecurityHeaders {
        SecurityHeaders {
            strict_transport_security: false,
            content_security_policy: false,
            x_frame_options: false,
            x_content_type_options: false,
            referrer_policy: false,
        }
    }

    fn snapshot() -> Snapshot {
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
                    url: "http://admin.example.com".to_string(),
                    scheme: "http".to_string(),
                    status: 200,
                    server: Some("nginx".to_string()),
                    title: Some("Admin".to_string()),
                    content_type: Some("text/html".to_string()),
                    technologies: vec!["nginx".to_string()],
                    provider: Some("cloudflare".to_string()),
                    tls_enabled: false,
                    security_headers: headers(),
                }],
            },
        }
    }

    fn timeline() -> TimelineReport {
        let now = Utc::now();
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
            state: FindingState::Persistent,
            tags: vec!["admin".to_string()],
            description: "desc".to_string(),
        };

        TimelineReport {
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
                persistent_findings: 1,
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
        }
    }

    fn episodes() -> EpisodeCollection {
        let now = Utc::now();
        EpisodeCollection {
            target: "example.com".to_string(),
            episode_count: 1,
            episodes: vec![RiskEpisode {
                episode_id: "ep1".to_string(),
                target: "example.com".to_string(),
                title: "Admin exposure".to_string(),
                kind: atlas_correlation::CorrelationKind::AdministrativeExposure,
                severity: Severity::High,
                criticality: Criticality::Critical,
                score: 180,
                state: EpisodeState::New,
                resource_count: 1,
                resources: vec!["admin.example.com".to_string()],
                cluster_ids: vec!["c1".to_string()],
                started_at: now,
                ended_at: now,
                summary: "summary".to_string(),
                explanation: vec!["exp".to_string()],
            }],
        }
    }

    #[test]
    fn builds_risk_report() {
        let snapshot = snapshot();
        let timeline = timeline();
        let episodes = episodes();
        let graph = build_full_graph(
            "example.com",
            Some(&snapshot),
            Some(&timeline),
            Some(&episodes),
        );

        let report = build_risk_report("example.com", Some(&timeline), Some(&episodes), &graph);
        assert!(!report.risks.is_empty());
        assert!(report.total_score > 0);
    }

    #[test]
    fn builds_summary_report() {
        let snapshot = snapshot();
        let timeline = timeline();
        let graph = ExposureGraph::empty("example.com");

        let summary =
            build_summary_report("example.com", &[snapshot], Some(&timeline), None, &graph);

        assert_eq!(summary.target, "example.com");
        assert_eq!(summary.snapshot_count, 1);
    }

    #[test]
    fn builds_alerts() {
        let report = RiskReport {
            target: "example.com".to_string(),
            generated_at: Utc::now(),
            total_risks: 1,
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            total_score: 100,
            top_risks: vec![RiskItem {
                rule_id: "r1".to_string(),
                title: "Critical risk".to_string(),
                severity: RiskSeverity::Critical,
                score: 100,
                resource: "admin.example.com".to_string(),
                kind: "service".to_string(),
                description: "desc".to_string(),
                recommendation: "fix".to_string(),
                evidence: vec![],
            }],
            risks: vec![RiskItem {
                rule_id: "r1".to_string(),
                title: "Critical risk".to_string(),
                severity: RiskSeverity::Critical,
                score: 100,
                resource: "admin.example.com".to_string(),
                kind: "service".to_string(),
                description: "desc".to_string(),
                recommendation: "fix".to_string(),
                evidence: vec![],
            }],
        };

        let alerts = build_basic_alerts(&report);
        assert_eq!(alerts.len(), 1);
    }
}
