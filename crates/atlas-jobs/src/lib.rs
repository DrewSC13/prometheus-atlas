use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasJob {
    pub job_id: String,
    pub target: String,
    pub profile: String,
    pub interval_seconds: u64,
    pub enabled: bool,
    pub policy_path: Option<String>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl AtlasJob {
    pub fn new(
        target: impl Into<String>,
        profile: impl Into<String>,
        interval_seconds: u64,
        policy_path: Option<String>,
        enabled: bool,
    ) -> Self {
        Self {
            job_id: Uuid::new_v4().to_string(),
            target: target.into(),
            profile: profile.into(),
            interval_seconds,
            enabled,
            policy_path,
            last_run_at: None,
            created_at: Utc::now(),
        }
    }

    pub fn next_run_at(&self) -> DateTime<Utc> {
        match self.last_run_at {
            Some(last_run_at) => last_run_at + Duration::seconds(self.interval_seconds as i64),
            None => self.created_at,
        }
    }

    pub fn is_due_at(&self, now: DateTime<Utc>) -> bool {
        self.enabled && self.next_run_at() <= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_job_is_due_immediately() {
        let job = AtlasJob::new("example.com", "standard", 3600, None, true);
        assert!(job.is_due_at(Utc::now()));
    }

    #[test]
    fn disabled_job_is_not_due() {
        let job = AtlasJob::new("example.com", "standard", 3600, None, false);
        assert!(!job.is_due_at(Utc::now()));
    }
}
