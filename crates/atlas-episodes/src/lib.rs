use anyhow::Result;
use atlas_correlation::{CorrelationCluster, CorrelationKind};
use atlas_drift::{Criticality, FindingState, Severity, TimelineReport};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EpisodeState {
    New,
    Recurring,
    Persistent,
    Resolved,
}

impl std::fmt::Display for EpisodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpisodeState::New => write!(f, "New"),
            EpisodeState::Recurring => write!(f, "Recurring"),
            EpisodeState::Persistent => write!(f, "Persistent"),
            EpisodeState::Resolved => write!(f, "Resolved"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEpisode {
    pub episode_id: String,
    pub target: String,
    pub title: String,
    pub kind: CorrelationKind,
    pub severity: Severity,
    pub criticality: Criticality,
    pub score: u32,
    pub state: EpisodeState,
    pub resource_count: usize,
    pub resources: Vec<String>,
    pub cluster_ids: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub summary: String,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeCollection {
    pub target: String,
    pub episode_count: usize,
    pub episodes: Vec<RiskEpisode>,
}

pub fn build_episodes(clusters: &[CorrelationCluster]) -> Result<Vec<RiskEpisode>> {
    let mut episodes = Vec::new();

    for cluster in clusters {
        let state = infer_episode_state(cluster);
        let title = infer_episode_title(cluster);
        let summary = build_summary(cluster, &state);

        episodes.push(RiskEpisode {
            episode_id: cluster.cluster_id.clone(),
            target: cluster.target.clone(),
            title,
            kind: cluster.kind.clone(),
            severity: cluster.dominant_severity.clone(),
            criticality: cluster.dominant_criticality.clone(),
            score: cluster.score,
            state,
            resource_count: cluster.resources.len(),
            resources: cluster.resources.clone(),
            cluster_ids: vec![cluster.cluster_id.clone()],
            started_at: cluster.started_at,
            ended_at: cluster.ended_at,
            summary,
            explanation: cluster.explanation.clone(),
        });
    }

    episodes.sort_by_key(|b| std::cmp::Reverse(b.score));
    Ok(episodes)
}

pub fn build_episodes_for_timeline(
    target: &str,
    _timeline: &TimelineReport,
    clusters_by_transition: &[Vec<CorrelationCluster>],
) -> Result<EpisodeCollection> {
    let mut all = Vec::new();

    for clusters in clusters_by_transition {
        let mut episodes = build_episodes(clusters)?;
        all.append(&mut episodes);
    }

    all.sort_by_key(|b| std::cmp::Reverse(b.score));

    Ok(EpisodeCollection {
        target: target.to_string(),
        episode_count: all.len(),
        episodes: all,
    })
}

fn infer_episode_state(cluster: &CorrelationCluster) -> EpisodeState {
    if cluster
        .findings
        .iter()
        .any(|f| matches!(f.state, FindingState::Persistent))
    {
        EpisodeState::Persistent
    } else if cluster
        .findings
        .iter()
        .any(|f| matches!(f.state, FindingState::Recurring))
    {
        EpisodeState::Recurring
    } else {
        EpisodeState::New
    }
}

fn infer_episode_title(cluster: &CorrelationCluster) -> String {
    match cluster.kind {
        CorrelationKind::AdministrativeExposure => {
            "Episodio de exposición administrativa".to_string()
        }
        CorrelationKind::ServiceExpansion => "Episodio de expansión de servicios".to_string(),
        CorrelationKind::InfrastructureShift => "Episodio de cambio de infraestructura".to_string(),
        CorrelationKind::RiskyDeployment => "Episodio de despliegue riesgoso".to_string(),
        CorrelationKind::NonProductionLeak => "Episodio de exposición no productiva".to_string(),
        CorrelationKind::RecurringSurfaceChange => {
            "Episodio de cambio recurrente de superficie".to_string()
        }
        CorrelationKind::UnknownComposite => "Episodio compuesto no clasificado".to_string(),
    }
}

fn build_summary(cluster: &CorrelationCluster, state: &EpisodeState) -> String {
    let unique_resources: BTreeSet<_> = cluster.resources.iter().collect();
    format!(
        "Cluster de tipo {} con {} hallazgos, {} recursos únicos, score {} y estado {}.",
        cluster.kind,
        cluster.findings.len(),
        unique_resources.len(),
        cluster.score,
        state
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_drift::{AssetType, Environment};

    #[test]
    fn builds_episode_from_cluster() {
        let cluster = CorrelationCluster {
            cluster_id: "abc123".to_string(),
            target: "example.com".to_string(),
            resources: vec![
                "admin.example.com".to_string(),
                "http://admin.example.com".to_string(),
            ],
            categories: vec![
                "new_admin_subdomain".to_string(),
                "new_http_service".to_string(),
            ],
            findings: vec![atlas_drift::DriftFinding {
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
                tags: vec![],
                description: "test".to_string(),
            }],
            kind: CorrelationKind::AdministrativeExposure,
            score: 180,
            dominant_severity: Severity::High,
            dominant_criticality: Criticality::Critical,
            started_at: Utc::now(),
            ended_at: Utc::now(),
            explanation: vec!["test".to_string()],
        };

        let episodes = build_episodes(&[cluster]).unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].resource_count, 2);
    }
}
