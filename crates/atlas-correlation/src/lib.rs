use anyhow::Result;
use atlas_drift::{Criticality, DriftFinding, DriftReport, Environment, FindingState, Severity};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CorrelationKind {
    AdministrativeExposure,
    ServiceExpansion,
    InfrastructureShift,
    RiskyDeployment,
    NonProductionLeak,
    RecurringSurfaceChange,
    UnknownComposite,
}

impl std::fmt::Display for CorrelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationKind::AdministrativeExposure => write!(f, "AdministrativeExposure"),
            CorrelationKind::ServiceExpansion => write!(f, "ServiceExpansion"),
            CorrelationKind::InfrastructureShift => write!(f, "InfrastructureShift"),
            CorrelationKind::RiskyDeployment => write!(f, "RiskyDeployment"),
            CorrelationKind::NonProductionLeak => write!(f, "NonProductionLeak"),
            CorrelationKind::RecurringSurfaceChange => write!(f, "RecurringSurfaceChange"),
            CorrelationKind::UnknownComposite => write!(f, "UnknownComposite"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    pub window_minutes: i64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self { window_minutes: 30 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCluster {
    pub cluster_id: String,
    pub target: String,
    pub resources: Vec<String>,
    pub categories: Vec<String>,
    pub findings: Vec<DriftFinding>,
    pub kind: CorrelationKind,
    pub score: u32,
    pub dominant_severity: Severity,
    pub dominant_criticality: Criticality,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub explanation: Vec<String>,
}

pub fn correlate_report(report: &DriftReport) -> Result<Vec<CorrelationCluster>> {
    correlate_report_with_config(report, &CorrelationConfig::default())
}

pub fn correlate_report_with_config(
    report: &DriftReport,
    config: &CorrelationConfig,
) -> Result<Vec<CorrelationCluster>> {
    let _window = Duration::minutes(config.window_minutes);
    let mut buckets: BTreeMap<String, Vec<DriftFinding>> = BTreeMap::new();

    for finding in &report.findings {
        let affinity_key = build_affinity_key(finding);
        buckets
            .entry(affinity_key)
            .or_default()
            .push(finding.clone());
    }

    let mut clusters = Vec::new();

    for (_key, mut findings) in buckets {
        findings.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.resource.cmp(&b.resource))
                .then_with(|| a.category.cmp(&b.category))
        });

        let kind = infer_kind(&findings);
        let dominant_severity = findings
            .iter()
            .map(|f| f.severity.clone())
            .max()
            .unwrap_or(Severity::Info);

        let dominant_criticality = findings
            .iter()
            .map(|f| f.criticality.clone())
            .max()
            .unwrap_or(Criticality::Low);

        let score = compute_cluster_score(&findings, &kind);
        let resources = dedup_strings(findings.iter().map(|f| f.resource.clone()).collect());
        let categories = dedup_strings(findings.iter().map(|f| f.category.clone()).collect());
        let explanation = build_cluster_explanation(&findings, &kind, score);

        let cluster_id = build_cluster_id(
            &report.target,
            &resources,
            &categories,
            report.older_timestamp,
            report.newer_timestamp,
            &kind,
        );

        clusters.push(CorrelationCluster {
            cluster_id,
            target: report.target.clone(),
            resources,
            categories,
            findings,
            kind,
            score,
            dominant_severity,
            dominant_criticality,
            started_at: report.older_timestamp,
            ended_at: report.newer_timestamp,
            explanation,
        });
    }

    clusters.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(clusters)
}

fn build_affinity_key(finding: &DriftFinding) -> String {
    let base = base_resource(&finding.resource);
    let env = finding.environment.to_string();
    format!("{base}|{env}")
}

fn base_resource(resource: &str) -> String {
    resource
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

fn infer_kind(findings: &[DriftFinding]) -> CorrelationKind {
    let has_admin = findings
        .iter()
        .any(|f| matches!(f.environment, Environment::Admin));

    let has_nonprod = findings.iter().any(|f| {
        matches!(
            f.environment,
            Environment::Development | Environment::Staging | Environment::Test
        )
    });

    let has_backend_change = findings
        .iter()
        .any(|f| f.category == "service_backend_changed");

    let has_fingerprint_change = findings
        .iter()
        .any(|f| f.category == "service_fingerprint_changed");

    let has_service_available = findings
        .iter()
        .any(|f| f.category == "service_became_available");

    let has_recurrence = findings
        .iter()
        .any(|f| matches!(f.state, FindingState::Recurring | FindingState::Persistent));

    if has_admin {
        CorrelationKind::AdministrativeExposure
    } else if has_nonprod {
        CorrelationKind::NonProductionLeak
    } else if has_backend_change && has_fingerprint_change {
        CorrelationKind::InfrastructureShift
    } else if has_service_available && findings.len() >= 2 {
        CorrelationKind::RiskyDeployment
    } else if has_recurrence {
        CorrelationKind::RecurringSurfaceChange
    } else if findings.len() >= 2 {
        CorrelationKind::ServiceExpansion
    } else {
        CorrelationKind::UnknownComposite
    }
}

fn compute_cluster_score(findings: &[DriftFinding], kind: &CorrelationKind) -> u32 {
    let base: u32 = findings.iter().map(|f| f.score).sum();

    let bonus = match kind {
        CorrelationKind::AdministrativeExposure => 40,
        CorrelationKind::ServiceExpansion => 20,
        CorrelationKind::InfrastructureShift => 25,
        CorrelationKind::RiskyDeployment => 30,
        CorrelationKind::NonProductionLeak => 15,
        CorrelationKind::RecurringSurfaceChange => 35,
        CorrelationKind::UnknownComposite => 5,
    };

    let count_bonus = if findings.len() >= 4 {
        10
    } else if findings.len() >= 2 {
        5
    } else {
        0
    };

    let criticality_multiplier = if findings
        .iter()
        .any(|f| matches!(f.criticality, Criticality::Critical))
    {
        1.30
    } else if findings
        .iter()
        .any(|f| matches!(f.criticality, Criticality::High))
    {
        1.15
    } else {
        1.0
    };

    (((base + bonus + count_bonus) as f64) * criticality_multiplier).round() as u32
}

fn build_cluster_explanation(
    findings: &[DriftFinding],
    kind: &CorrelationKind,
    score: u32,
) -> Vec<String> {
    let mut reasons = Vec::new();

    reasons.push(format!(
        "Se correlacionaron {} hallazgos en un cluster de tipo {}.",
        findings.len(),
        kind
    ));

    reasons.push(format!("El score compuesto del cluster es {}.", score));

    let resources: BTreeSet<_> = findings.iter().map(|f| f.resource.clone()).collect();
    reasons.push(format!(
        "El cluster involucra {} recursos únicos.",
        resources.len()
    ));

    if findings
        .iter()
        .any(|f| matches!(f.criticality, Criticality::Critical))
    {
        reasons.push("Se aplicó ponderación adicional por activos críticos.".to_string());
    }

    if findings
        .iter()
        .any(|f| matches!(f.environment, Environment::Admin))
    {
        reasons.push("Se detectó contexto administrativo dentro del cluster.".to_string());
    }

    if findings
        .iter()
        .any(|f| f.category == "service_backend_changed")
        && findings
            .iter()
            .any(|f| f.category == "service_fingerprint_changed")
    {
        reasons.push(
            "Se detectó combinación de cambio de backend y fingerprint tecnológico.".to_string(),
        );
    }

    reasons
}

fn build_cluster_id(
    target: &str,
    resources: &[String],
    categories: &[String],
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    kind: &CorrelationKind,
) -> String {
    let raw = format!(
        "{}|{}|{}|{}|{}|{}",
        target,
        resources.join(","),
        categories.join(","),
        started_at,
        ended_at,
        kind
    );

    let digest = Sha256::digest(raw.as_bytes());
    let hex = hex::encode(digest);
    hex[..24].to_string()
}

fn dedup_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_drift::{AssetType, DriftSummary};

    fn finding(resource: &str, category: &str, env: Environment, score: u32) -> DriftFinding {
        DriftFinding {
            finding_id: format!("{category}:{resource}"),
            severity: Severity::High,
            score,
            category: category.to_string(),
            title: category.to_string(),
            resource: resource.to_string(),
            asset_type: if resource.starts_with("http") {
                AssetType::Service
            } else {
                AssetType::Subdomain
            },
            environment: env,
            criticality: Criticality::Critical,
            state: FindingState::New,
            tags: vec![],
            description: "test".to_string(),
        }
    }

    #[test]
    fn correlates_admin_cluster() {
        let report = DriftReport {
            target: "example.com".to_string(),
            older_timestamp: Utc::now(),
            newer_timestamp: Utc::now(),
            findings: vec![
                finding(
                    "admin.example.com",
                    "new_admin_subdomain",
                    Environment::Admin,
                    95,
                ),
                finding(
                    "http://admin.example.com",
                    "new_http_service",
                    Environment::Admin,
                    90,
                ),
            ],
            suppressed_findings: vec![],
            groups: vec![],
            summary: DriftSummary::default(),
        };

        let clusters = correlate_report(&report).unwrap();
        assert!(!clusters.is_empty());
        assert_eq!(clusters[0].kind, CorrelationKind::AdministrativeExposure);
    }
}
