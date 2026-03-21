use atlas_jobs::{AtlasJob, JobDispatchRequest, JobTrigger};
use chrono::{DateTime, Utc};

pub fn select_due_jobs(jobs: &[AtlasJob], now: DateTime<Utc>) -> Vec<AtlasJob> {
    let mut due = jobs
        .iter()
        .filter(|job| job.is_due_at(now))
        .cloned()
        .collect::<Vec<_>>();

    due.sort_by(|a, b| {
        a.next_run_at()
            .cmp(&b.next_run_at())
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.job_id.cmp(&b.job_id))
    });

    due
}

pub fn build_dispatch_requests(
    tenant_id: &str,
    project_id: &str,
    jobs: &[AtlasJob],
    now: DateTime<Utc>,
) -> Vec<JobDispatchRequest> {
    select_due_jobs(jobs, now)
        .into_iter()
        .map(|job| {
            JobDispatchRequest::from_job(
                tenant_id.to_string(),
                project_id.to_string(),
                &job,
                JobTrigger::Scheduled,
            )
            .available_at(now)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn scheduler_selects_due_jobs() {
        let now = Utc::now();

        let mut due = AtlasJob::new("example.com", "standard", 3600, None, true);
        due.last_run_at = Some(now - Duration::seconds(7200));

        let mut not_due = AtlasJob::new("test.com", "standard", 3600, None, true);
        not_due.last_run_at = Some(now - Duration::seconds(10));

        let jobs = vec![due, not_due];
        let selected = select_due_jobs(&jobs, now);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].target, "example.com");
    }

    #[test]
    fn scheduler_ignores_disabled_jobs() {
        let now = Utc::now();

        let mut job = AtlasJob::new("example.com", "standard", 3600, None, false);
        job.last_run_at = Some(now - Duration::seconds(7200));

        let selected = select_due_jobs(&[job], now);
        assert!(selected.is_empty());
    }

    #[test]
    fn scheduler_builds_dispatch_requests() {
        let now = Utc::now();

        let mut due = AtlasJob::new("example.com", "standard", 3600, None, true);
        due.last_run_at = Some(now - Duration::seconds(7200));

        let requests = build_dispatch_requests("tenant-a", "project-x", &[due], now);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].tenant_id, "tenant-a");
        assert_eq!(requests[0].project_id, "project-x");
        assert_eq!(requests[0].trigger, JobTrigger::Scheduled);
    }
}
