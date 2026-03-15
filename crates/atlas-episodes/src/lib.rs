use atlas_correlation::RiskEpisode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeWindow {
    pub resource: String,
    pub episode_id: String,
    pub severity: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub score: u32,
    pub finding_count: usize,
}

pub fn summarize_episodes(
    episodes: &[RiskEpisode],
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
) -> Vec<EpisodeWindow> {
    episodes
        .iter()
        .map(|episode| EpisodeWindow {
            resource: episode.resource.clone(),
            episode_id: episode.episode_id.clone(),
            severity: episode.severity.to_string(),
            started_at,
            ended_at,
            score: episode.score,
            finding_count: episode.findings.len(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_correlation::{EpisodeCategory, EpisodeSeverity, RiskEpisode};

    #[test]
    fn summarizes_risk_episodes() {
        let episodes = vec![RiskEpisode {
            episode_id: "ep-1".to_string(),
            resource: "admin.example.com".to_string(),
            category: EpisodeCategory::AdminExposure,
            severity: EpisodeSeverity::Critical,
            findings: vec![],
            score: 100,
        }];

        let started_at = Utc::now();
        let ended_at = Utc::now();

        let windows = summarize_episodes(&episodes, started_at, ended_at);

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].resource, "admin.example.com");
        assert_eq!(windows[0].score, 100);
    }
}
