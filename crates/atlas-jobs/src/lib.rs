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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobTrigger {
    Manual,
    Scheduled,
    Replay,
    Api,
}

impl JobTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
            Self::Replay => "replay",
            Self::Api => "api",
        }
    }
}

impl std::fmt::Display for JobTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDispatchRequest {
    pub tenant_id: String,
    pub project_id: String,
    pub job_id: String,
    pub target: String,
    pub profile: String,
    pub policy_path: Option<String>,
    pub trigger: JobTrigger,
    pub requested_by: Option<String>,
    pub persist_artifacts: bool,
    pub max_attempts: u32,
    pub available_at: Option<DateTime<Utc>>,
}

impl JobDispatchRequest {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        job_id: impl Into<String>,
        target: impl Into<String>,
        profile: impl Into<String>,
        trigger: JobTrigger,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            job_id: job_id.into(),
            target: target.into(),
            profile: profile.into(),
            policy_path: None,
            trigger,
            requested_by: None,
            persist_artifacts: false,
            max_attempts: 3,
            available_at: None,
        }
    }

    pub fn from_job(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        job: &AtlasJob,
        trigger: JobTrigger,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            job_id: job.job_id.clone(),
            target: job.target.clone(),
            profile: job.profile.clone(),
            policy_path: job.policy_path.clone(),
            trigger,
            requested_by: None,
            persist_artifacts: false,
            max_attempts: 3,
            available_at: None,
        }
    }

    pub fn requested_by(mut self, subject: impl Into<String>) -> Self {
        self.requested_by = Some(subject.into());
        self
    }

    pub fn persist_artifacts(mut self, persist: bool) -> Self {
        self.persist_artifacts = persist;
        self
    }

    pub fn available_at(mut self, when: DateTime<Utc>) -> Self {
        self.available_at = Some(when);
        self
    }

    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
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

    #[test]
    fn dispatch_request_can_be_built_from_job() {
        let job = AtlasJob::new("example.com", "standard", 3600, None, true);
        let req =
            JobDispatchRequest::from_job("tenant-a", "project-x", &job, JobTrigger::Scheduled);

        assert_eq!(req.tenant_id, "tenant-a");
        assert_eq!(req.project_id, "project-x");
        assert_eq!(req.job_id, job.job_id);
        assert_eq!(req.target, "example.com");
        assert_eq!(req.profile, "standard");
        assert_eq!(req.trigger, JobTrigger::Scheduled);
    }
}
