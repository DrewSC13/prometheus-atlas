use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasJob {
    pub job_id: String,
    pub target: String,
    pub policy_path: Option<String>,
    pub profile: String,
    pub interval_seconds: u64,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl AtlasJob {
    pub fn new(
        target: &str,
        policy_path: Option<String>,
        profile: &str,
        interval_seconds: u64,
    ) -> Result<Self> {
        if interval_seconds == 0 {
            bail!("interval_seconds debe ser mayor a 0");
        }

        if target.trim().is_empty() {
            bail!("target no puede estar vacío");
        }

        if profile.trim().is_empty() {
            bail!("profile no puede estar vacío");
        }

        Ok(Self {
            job_id: Uuid::new_v4().to_string(),
            target: target.to_string(),
            policy_path,
            profile: profile.to_string(),
            interval_seconds,
            enabled: true,
            last_run_at: None,
            created_at: Utc::now(),
        })
    }

    pub fn should_run_now(&self, now: DateTime<Utc>) -> bool {
        if !self.enabled {
            return false;
        }

        match self.last_run_at {
            Some(last) => (now - last).num_seconds() >= self.interval_seconds as i64,
            None => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRunPlan {
    pub job_id: String,
    pub target: String,
    pub policy_path: Option<String>,
    pub profile: String,
}

pub fn scheduler_plan(jobs: &[AtlasJob], now: DateTime<Utc>) -> Vec<JobRunPlan> {
    jobs.iter()
        .filter(|job| job.should_run_now(now))
        .map(|job| JobRunPlan {
            job_id: job.job_id.clone(),
            target: job.target.clone(),
            policy_path: job.policy_path.clone(),
            profile: job.profile.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_selects_due_jobs() {
        let mut job = AtlasJob::new("example.com", None, "standard", 60).unwrap();
        job.last_run_at = Some(Utc::now() - chrono::Duration::seconds(120));

        let planned = scheduler_plan(&[job], Utc::now());
        assert_eq!(planned.len(), 1);
    }

    #[test]
    fn disabled_job_is_not_selected() {
        let mut job = AtlasJob::new("example.com", None, "standard", 60).unwrap();
        job.enabled = false;

        let planned = scheduler_plan(&[job], Utc::now());
        assert!(planned.is_empty());
    }
}
