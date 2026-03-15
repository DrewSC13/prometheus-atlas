use atlas_drift::{Criticality, DriftFinding, DriftReport, Severity, TimelineReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpisodeCategory {
    AdminExposure,
    ApiExposure,
    InfrastructureChange,
    ServiceInstability,
    RecurrentExposure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EpisodeSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for EpisodeSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpisodeSeverity::Low => write!(f, "LOW"),
            EpisodeSeverity::Medium => write!(f, "MEDIUM"),
            EpisodeSeverity::High => write!(f, "HIGH"),
            EpisodeSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEpisode {
    pub episode_id: String,
    pub resource: String,
    pub category: EpisodeCategory,
    pub severity: EpisodeSeverity,
    pub findings: Vec<DriftFinding>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLink {
    pub parent: String,
    pub child: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub finding_id: String,
    pub resource: String,
    pub category: String,
    pub base_score: u32,
    pub policy_adjustment: i32,
    pub criticality_multiplier: f32,
    pub final_score: u32,
    pub reasons: Vec<String>,
}

pub fn build_episodes(report: &DriftReport) -> Vec<RiskEpisode> {
    let mut episodes = Vec::new();
    let mut by_resource: BTreeMap<String, Vec<DriftFinding>> = BTreeMap::new();

    for finding in &report.findings {
        by_resource
            .entry(finding.resource.clone())
            .or_default()
            .push(finding.clone());
    }

    for (resource, findings) in by_resource {
        let tags = findings
            .iter()
            .flat_map(|f| f.tags.iter().cloned())
            .collect::<Vec<_>>();

        let has_admin = tags.iter().any(|t| t == "admin");
        let has_plaintext = tags.iter().any(|t| t == "plaintext");
        let has_json_api = tags.iter().any(|t| t == "tech:json-api");
        let has_backend_change = findings
            .iter()
            .any(|f| f.category == "service_backend_changed");
        let has_recurring = findings.iter().any(|f| {
            matches!(
                f.state,
                atlas_drift::FindingState::Recurring | atlas_drift::FindingState::Persistent
            )
        });

        let (category, severity, score) = if has_admin && has_plaintext {
            (
                EpisodeCategory::AdminExposure,
                EpisodeSeverity::Critical,
                findings.iter().map(|f| f.score).sum::<u32>() + 40,
            )
        } else if has_json_api {
            (
                EpisodeCategory::ApiExposure,
                EpisodeSeverity::High,
                findings.iter().map(|f| f.score).sum::<u32>() + 20,
            )
        } else if has_backend_change {
            (
                EpisodeCategory::InfrastructureChange,
                EpisodeSeverity::Medium,
                findings.iter().map(|f| f.score).sum::<u32>() + 10,
            )
        } else if has_recurring {
            (
                EpisodeCategory::RecurrentExposure,
                EpisodeSeverity::High,
                findings.iter().map(|f| f.score).sum::<u32>() + 30,
            )
        } else {
            (
                EpisodeCategory::ServiceInstability,
                severity_from_findings(&findings),
                findings.iter().map(|f| f.score).sum::<u32>(),
            )
        };

        episodes.push(RiskEpisode {
            episode_id: episode_id(&resource, &format!("{category:?}")),
            resource,
            category,
            severity,
            findings,
            score,
        });
    }

    episodes.sort_by(|a, b| b.score.cmp(&a.score));
    episodes
}

pub fn build_timeline_episodes(report: &TimelineReport) -> Vec<RiskEpisode> {
    let mut combined = Vec::new();

    for transition in &report.transitions {
        combined.extend(transition.report.findings.clone());
    }

    let synthetic = DriftReport {
        target: report.target.clone(),
        older_timestamp: report
            .transitions
            .first()
            .map(|t| t.older_timestamp)
            .unwrap_or_else(chrono::Utc::now),
        newer_timestamp: report
            .transitions
            .last()
            .map(|t| t.newer_timestamp)
            .unwrap_or_else(chrono::Utc::now),
        findings: combined,
        suppressed_findings: Vec::new(),
        groups: Vec::new(),
        summary: atlas_drift::DriftSummary::default(),
    };

    build_episodes(&synthetic)
}

pub fn build_resource_lineage(report: &DriftReport) -> Vec<ResourceLink> {
    let mut links = Vec::new();

    for finding in &report.findings {
        if finding.resource.starts_with("http://") || finding.resource.starts_with("https://") {
            let without_scheme = finding
                .resource
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .to_string();

            links.push(ResourceLink {
                parent: without_scheme,
                child: finding.resource.clone(),
                relation: "subdomain_to_service".to_string(),
            });
        }
    }

    links
}

pub fn explain_finding(finding: &DriftFinding) -> FindingExplanation {
    let mut reasons = Vec::new();
    let base_score = base_score_from_category(&finding.category);
    let policy_adjustment = finding.score as i32 - base_score as i32;

    if finding.tags.iter().any(|t| t == "baseline-adjusted") {
        reasons.push("Se aplicó ajuste por baseline.".to_string());
    }

    if matches!(finding.state, atlas_drift::FindingState::Recurring) {
        reasons.push("El hallazgo es recurrente.".to_string());
    }

    if matches!(finding.state, atlas_drift::FindingState::Persistent) {
        reasons.push("El hallazgo es persistente.".to_string());
    }

    let criticality_multiplier = match finding.criticality {
        Criticality::Critical => {
            reasons.push("Activo clasificado como CRITICAL.".to_string());
            1.4
        }
        Criticality::High => {
            reasons.push("Activo clasificado como HIGH.".to_string());
            1.2
        }
        Criticality::Medium => 1.0,
        Criticality::Low => 1.0,
    };

    reasons.push(format!(
        "Severidad final calculada como {} con score {}.",
        finding.severity, finding.score
    ));

    FindingExplanation {
        finding_id: finding.finding_id.clone(),
        resource: finding.resource.clone(),
        category: finding.category.clone(),
        base_score,
        policy_adjustment,
        criticality_multiplier,
        final_score: finding.score,
        reasons,
    }
}

fn base_score_from_category(category: &str) -> u32 {
    match category {
        "new_admin_subdomain" => 95,
        "new_http_service" => 90,
        "new_https_service" => 50,
        "service_became_available" => 60,
        "service_fingerprint_changed" => 40,
        "service_backend_changed" => 15,
        "new_ip" => 10,
        "new_subdomain" => 20,
        "removed_ip" => 3,
        "subdomain_removed" => 5,
        "service_removed" => 5,
        _ => 10,
    }
}

fn episode_id(resource: &str, category: &str) -> String {
    let raw = format!("{resource}|{category}");
    let digest = Sha256::digest(raw.as_bytes());
    let hex = hex::encode(digest);
    hex[..20].to_string()
}

fn severity_from_findings(findings: &[DriftFinding]) -> EpisodeSeverity {
    if findings.iter().any(|f| {
        matches!(f.severity, Severity::High) || matches!(f.criticality, Criticality::Critical)
    }) {
        EpisodeSeverity::High
    } else if findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Medium))
    {
        EpisodeSeverity::Medium
    } else {
        EpisodeSeverity::Low
    }
}

#[cfg(test)]
mod tests;
