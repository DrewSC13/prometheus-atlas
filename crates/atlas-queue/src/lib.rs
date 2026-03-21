use atlas_jobs::JobDispatchRequest;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobQueueStatus {
    Pending,
    Claimed,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobQueueStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for JobQueueStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for JobQueueStatus {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "claimed" => Ok(Self::Claimed),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("job queue status no soportado: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobQueueItem {
    pub queue_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub job_id: String,
    pub target: String,
    pub profile: String,
    pub policy_path: Option<String>,
    pub trigger: String,
    pub requested_by: Option<String>,
    pub persist_artifacts: bool,
    pub status: JobQueueStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub available_at: DateTime<Utc>,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

impl JobQueueItem {
    pub fn from_dispatch(request: JobDispatchRequest) -> Self {
        let now = Utc::now();
        Self {
            queue_id: Uuid::new_v4().to_string(),
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            job_id: request.job_id,
            target: request.target,
            profile: request.profile,
            policy_path: request.policy_path,
            trigger: request.trigger.to_string(),
            requested_by: request.requested_by,
            persist_artifacts: request.persist_artifacts,
            status: JobQueueStatus::Pending,
            attempts: 0,
            max_attempts: request.max_attempts,
            available_at: request.available_at.unwrap_or(now),
            claimed_by: None,
            claimed_at: None,
            lease_expires_at: None,
            created_at: now,
            updated_at: now,
            last_error: None,
        }
    }

    pub fn can_be_claimed_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.status, JobQueueStatus::Pending)
            && self.available_at <= now
            && self
                .lease_expires_at
                .map(|lease| lease <= now)
                .unwrap_or(true)
    }

    pub fn claim(&mut self, worker_id: impl Into<String>, lease_seconds: u64) {
        let now = Utc::now();
        self.status = JobQueueStatus::Claimed;
        self.claimed_by = Some(worker_id.into());
        self.claimed_at = Some(now);
        self.lease_expires_at = Some(now + Duration::seconds(lease_seconds as i64));
        self.updated_at = now;
    }

    pub fn start(&mut self) {
        self.status = JobQueueStatus::Running;
        self.updated_at = Utc::now();
    }

    pub fn succeed(&mut self) {
        self.status = JobQueueStatus::Succeeded;
        self.updated_at = Utc::now();
        self.lease_expires_at = None;
    }

    pub fn fail(&mut self, message: impl Into<String>, retry_delay_seconds: Option<u64>) {
        let now = Utc::now();
        self.attempts += 1;
        self.last_error = Some(message.into());
        self.updated_at = now;
        self.claimed_by = None;
        self.claimed_at = None;
        self.lease_expires_at = None;

        if self.attempts >= self.max_attempts {
            self.status = JobQueueStatus::Failed;
        } else {
            self.status = JobQueueStatus::Pending;
            if let Some(delay) = retry_delay_seconds {
                self.available_at = now + Duration::seconds(delay as i64);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecutionRecord {
    pub execution_id: String,
    pub queue_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub job_id: String,
    pub worker_id: Option<String>,
    pub status: JobQueueStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub result_json: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl JobExecutionRecord {
    pub fn from_queue(item: &JobQueueItem) -> Self {
        Self {
            execution_id: Uuid::new_v4().to_string(),
            queue_id: item.queue_id.clone(),
            tenant_id: item.tenant_id.clone(),
            project_id: item.project_id.clone(),
            job_id: item.job_id.clone(),
            worker_id: item.claimed_by.clone(),
            status: item.status,
            started_at: item.claimed_at,
            finished_at: None,
            result_json: None,
            error_message: None,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_jobs::{JobDispatchRequest, JobTrigger};

    #[test]
    fn queue_item_lifecycle_works() {
        let request = JobDispatchRequest::new(
            "tenant-a",
            "project-x",
            "job-1",
            "example.com",
            "standard",
            JobTrigger::Manual,
        );

        let mut item = JobQueueItem::from_dispatch(request);
        assert_eq!(item.status, JobQueueStatus::Pending);
        assert!(item.can_be_claimed_at(Utc::now()));

        item.claim("worker-1", 30);
        assert_eq!(item.status, JobQueueStatus::Claimed);

        item.start();
        assert_eq!(item.status, JobQueueStatus::Running);

        item.succeed();
        assert_eq!(item.status, JobQueueStatus::Succeeded);
    }

    #[test]
    fn queue_item_retries_until_failure() {
        let mut request = JobDispatchRequest::new(
            "tenant-a",
            "project-x",
            "job-1",
            "example.com",
            "standard",
            JobTrigger::Scheduled,
        );
        request.max_attempts = 2;

        let mut item = JobQueueItem::from_dispatch(request);
        item.fail("first error", Some(10));
        assert_eq!(item.status, JobQueueStatus::Pending);
        assert_eq!(item.attempts, 1);

        item.fail("second error", Some(10));
        assert_eq!(item.status, JobQueueStatus::Failed);
        assert_eq!(item.attempts, 2);
    }
}
