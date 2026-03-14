use anyhow::{bail, Context, Result};
use atlas_diff::{DiffReport, ServiceChange};
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Severity::Info => 5,
            Severity::Low => 20,
            Severity::Medium => 50,
            Severity::High => 90,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Environment {
    Production,
    Admin,
    Development,
    Staging,
    Test,
    Unknown,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Production => write!(f, "Production"),
            Environment::Admin => write!(f, "Admin"),
            Environment::Development => write!(f, "Development"),
            Environment::Staging => write!(f, "Staging"),
            Environment::Test => write!(f, "Test"),
            Environment::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub severity: Severity,
    pub score: u32,
    pub category: String,
    pub title: String,
    pub resource: String,
    pub environment: Environment,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftSummary {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total_score: u32,
    pub overall_severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftGroup {
    pub resource: String,
    pub findings: Vec<DriftFinding>,
    pub highest_severity: Severity,
    pub total_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub target: String,
    pub older_timestamp: DateTime<Utc>,
    pub newer_timestamp: DateTime<Utc>,
    pub findings: Vec<DriftFinding>,
    pub suppressed_findings: Vec<DriftFinding>,
    pub groups: Vec<DriftGroup>,
    pub summary: DriftSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftPolicy {
    pub allowlisted_resources: Vec<String>,
    pub allowlisted_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineTransition {
    pub older_timestamp: DateTime<Utc>,
    pub newer_timestamp: DateTime<Utc>,
    pub report: DriftReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAggregate {
    pub resource: String,
    pub occurrences: usize,
    pub total_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryAggregate {
    pub category: String,
    pub occurrences: usize,
    pub total_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineExecutiveSummary {
    pub total_score: u32,
    pub overall_severity: Severity,
    pub total_findings: usize,
    pub unique_resources: usize,
    pub top_resources: Vec<ResourceAggregate>,
    pub top_categories: Vec<CategoryAggregate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineReport {
    pub target: String,
    pub snapshot_count: usize,
    pub transition_count: usize,
    pub transitions: Vec<TimelineTransition>,
    pub executive: TimelineExecutiveSummary,
}

impl DriftPolicy {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("no se pudo leer la policy {}", path.display()))?;

        let policy = serde_json::from_str::<DriftPolicy>(&content)
            .with_context(|| format!("no se pudo parsear la policy {}", path.display()))?;

        Ok(policy)
    }

    pub fn suppresses(&self, finding: &DriftFinding) -> bool {
        self.allowlisted_categories
            .iter()
            .any(|category| category == &finding.category)
            || self
                .allowlisted_resources
                .iter()
                .any(|pattern| matches_resource(pattern, &finding.resource))
    }
}

pub fn analyze_diff(diff: &DiffReport) -> DriftReport {
    analyze_diff_with_policy(diff, None)
}

pub fn analyze_diff_with_policy(diff: &DiffReport, policy: Option<&DriftPolicy>) -> DriftReport {
    let mut findings = Vec::new();

    for ip in &diff.new_ips {
        findings.push(DriftFinding {
            severity: Severity::Low,
            score: 10,
            category: "new_ip".to_string(),
            title: "Nueva IP detectada".to_string(),
            resource: ip.clone(),
            environment: Environment::Unknown,
            description: format!(
                "Se detectó una nueva dirección IP {} en el snapshot más reciente.",
                ip
            ),
        });
    }

    for ip in &diff.removed_ips {
        findings.push(DriftFinding {
            severity: Severity::Info,
            score: 3,
            category: "removed_ip".to_string(),
            title: "IP removida".to_string(),
            resource: ip.clone(),
            environment: Environment::Unknown,
            description: format!(
                "La dirección IP {} dejó de aparecer en el snapshot más reciente.",
                ip
            ),
        });
    }

    for subdomain in &diff.new_subdomains {
        findings.push(classify_new_subdomain(subdomain));
    }

    for subdomain in &diff.removed_subdomains {
        findings.push(DriftFinding {
            severity: Severity::Info,
            score: 5,
            category: "subdomain_removed".to_string(),
            title: "Subdominio removido".to_string(),
            resource: subdomain.clone(),
            environment: infer_environment(subdomain),
            description: format!(
                "El subdominio {} ya no fue detectado en el snapshot más reciente.",
                subdomain
            ),
        });
    }

    for service in &diff.new_services {
        findings.push(classify_new_service(
            service.url.as_str(),
            service.scheme.as_str(),
        ));
    }

    for service in &diff.removed_services {
        findings.push(DriftFinding {
            severity: Severity::Info,
            score: 5,
            category: "service_removed".to_string(),
            title: "Servicio removido".to_string(),
            resource: service.url.clone(),
            environment: infer_environment(service.url.as_str()),
            description: format!(
                "El servicio {} dejó de estar presente entre snapshots.",
                service.url
            ),
        });
    }

    for change in &diff.changed_services {
        if let Some(finding) = classify_service_change(change) {
            findings.push(finding);
        }
    }

    let (suppressed_findings, active_findings) = apply_policy(findings, policy);
    let groups = group_findings(&active_findings);
    let summary = summarize(&active_findings);

    DriftReport {
        target: diff.target.clone(),
        older_timestamp: diff.older_timestamp,
        newer_timestamp: diff.newer_timestamp,
        findings: active_findings,
        suppressed_findings,
        groups,
        summary,
    }
}

pub fn build_timeline_report(
    target: &str,
    snapshots: &[Snapshot],
    policy: Option<&DriftPolicy>,
) -> Result<TimelineReport> {
    if snapshots.len() < 2 {
        bail!("se requieren al menos 2 snapshots para construir un timeline");
    }

    let mut transitions = Vec::new();

    for pair in snapshots.windows(2) {
        let older = &pair[0];
        let newer = &pair[1];

        let diff = atlas_diff::diff_snapshots(older, newer);
        let report = analyze_diff_with_policy(&diff, policy);

        transitions.push(TimelineTransition {
            older_timestamp: older.timestamp,
            newer_timestamp: newer.timestamp,
            report,
        });
    }

    let executive = build_executive_summary(&transitions);

    Ok(TimelineReport {
        target: target.to_string(),
        snapshot_count: snapshots.len(),
        transition_count: transitions.len(),
        transitions,
        executive,
    })
}

fn build_executive_summary(transitions: &[TimelineTransition]) -> TimelineExecutiveSummary {
    let mut total_score = 0;
    let mut total_findings = 0;
    let mut unique_resources = BTreeSet::new();

    let mut resource_map: BTreeMap<String, ResourceAggregate> = BTreeMap::new();
    let mut category_map: BTreeMap<String, CategoryAggregate> = BTreeMap::new();

    for transition in transitions {
        total_score += transition.report.summary.total_score;
        total_findings += transition.report.findings.len();

        for finding in &transition.report.findings {
            unique_resources.insert(finding.resource.clone());

            resource_map
                .entry(finding.resource.clone())
                .and_modify(|entry| {
                    entry.occurrences += 1;
                    entry.total_score += finding.score;
                })
                .or_insert(ResourceAggregate {
                    resource: finding.resource.clone(),
                    occurrences: 1,
                    total_score: finding.score,
                });

            category_map
                .entry(finding.category.clone())
                .and_modify(|entry| {
                    entry.occurrences += 1;
                    entry.total_score += finding.score;
                })
                .or_insert(CategoryAggregate {
                    category: finding.category.clone(),
                    occurrences: 1,
                    total_score: finding.score,
                });
        }
    }

    let overall_severity = if total_score >= 300 {
        Severity::High
    } else if total_score >= 150 {
        Severity::Medium
    } else if total_score >= 30 {
        Severity::Low
    } else {
        Severity::Info
    };

    let mut top_resources: Vec<_> = resource_map.into_values().collect();
    top_resources.sort_by(|a, b| b.total_score.cmp(&a.total_score));
    top_resources.truncate(5);

    let mut top_categories: Vec<_> = category_map.into_values().collect();
    top_categories.sort_by(|a, b| b.total_score.cmp(&a.total_score));
    top_categories.truncate(5);

    TimelineExecutiveSummary {
        total_score,
        overall_severity,
        total_findings,
        unique_resources: unique_resources.len(),
        top_resources,
        top_categories,
    }
}

fn apply_policy(
    findings: Vec<DriftFinding>,
    policy: Option<&DriftPolicy>,
) -> (Vec<DriftFinding>, Vec<DriftFinding>) {
    if let Some(policy) = policy {
        let mut suppressed = Vec::new();
        let mut active = Vec::new();

        for finding in findings {
            if policy.suppresses(&finding) {
                suppressed.push(finding);
            } else {
                active.push(finding);
            }
        }

        (suppressed, active)
    } else {
        (Vec::new(), findings)
    }
}

fn classify_new_subdomain(subdomain: &str) -> DriftFinding {
    let environment = infer_environment(subdomain);
    let lowered = subdomain.to_lowercase();

    if lowered.starts_with("admin.") || lowered.contains(".admin.") {
        DriftFinding {
            severity: Severity::High,
            score: 95,
            category: "new_admin_subdomain".to_string(),
            title: "Nuevo subdominio administrativo".to_string(),
            resource: subdomain.to_string(),
            environment,
            description: format!(
                "Se detectó el subdominio {} con patrón administrativo, lo que puede indicar nueva superficie sensible expuesta.",
                subdomain
            ),
        }
    } else if lowered.starts_with("dev.")
        || lowered.starts_with("staging.")
        || lowered.contains(".dev.")
        || lowered.contains(".staging.")
        || lowered.starts_with("test.")
        || lowered.contains(".test.")
    {
        DriftFinding {
            severity: Severity::Medium,
            score: 55,
            category: "new_nonprod_subdomain".to_string(),
            title: "Nuevo subdominio no productivo".to_string(),
            resource: subdomain.to_string(),
            environment,
            description: format!(
                "Se detectó el subdominio {} asociado a entornos de desarrollo, prueba o staging.",
                subdomain
            ),
        }
    } else {
        DriftFinding {
            severity: Severity::Low,
            score: 20,
            category: "new_subdomain".to_string(),
            title: "Nuevo subdominio detectado".to_string(),
            resource: subdomain.to_string(),
            environment,
            description: format!(
                "Se detectó un nuevo subdominio {} que no existía en el snapshot anterior.",
                subdomain
            ),
        }
    }
}

fn classify_new_service(url: &str, scheme: &str) -> DriftFinding {
    let environment = infer_environment(url);

    match scheme {
        "http" => DriftFinding {
            severity: Severity::High,
            score: 90,
            category: "new_http_service".to_string(),
            title: "Nuevo servicio HTTP expuesto".to_string(),
            resource: url.to_string(),
            environment,
            description: format!(
                "Se detectó un nuevo servicio accesible por HTTP sin cifrado en {}.",
                url
            ),
        },
        "https" => DriftFinding {
            severity: Severity::Medium,
            score: 50,
            category: "new_https_service".to_string(),
            title: "Nuevo servicio HTTPS expuesto".to_string(),
            resource: url.to_string(),
            environment,
            description: format!("Se detectó un nuevo servicio HTTPS accesible en {}.", url),
        },
        _ => DriftFinding {
            severity: Severity::Low,
            score: 20,
            category: "new_service".to_string(),
            title: "Nuevo servicio detectado".to_string(),
            resource: url.to_string(),
            environment,
            description: format!("Se detectó un nuevo servicio expuesto en {}.", url),
        },
    }
}

fn classify_service_change(change: &ServiceChange) -> Option<DriftFinding> {
    let became_available =
        !is_success_status(change.before_status) && is_success_status(change.after_status);
    let changed_server = change.before_server != change.after_server;
    let environment = infer_environment(change.url.as_str());

    if became_available {
        return Some(DriftFinding {
            severity: Severity::Medium,
            score: 60,
            category: "service_became_available".to_string(),
            title: "Servicio ahora accesible".to_string(),
            resource: change.url.clone(),
            environment,
            description: format!(
                "El servicio {} cambió de estado {} a {}, lo que indica que ahora está accesible.",
                change.url, change.before_status, change.after_status
            ),
        });
    }

    if changed_server {
        return Some(DriftFinding {
            severity: Severity::Low,
            score: 15,
            category: "service_backend_changed".to_string(),
            title: "Cambio de servidor o backend".to_string(),
            resource: change.url.clone(),
            environment,
            description: format!(
                "El servicio {} cambió el encabezado Server de {:?} a {:?}.",
                change.url, change.before_server, change.after_server
            ),
        });
    }

    None
}

fn infer_environment(resource: &str) -> Environment {
    let lowered = resource.to_lowercase();

    if lowered.contains("admin") {
        Environment::Admin
    } else if lowered.contains("staging") {
        Environment::Staging
    } else if lowered.contains("dev") {
        Environment::Development
    } else if lowered.contains("test") {
        Environment::Test
    } else if lowered.contains("prod") || lowered.contains("www") {
        Environment::Production
    } else {
        Environment::Unknown
    }
}

fn group_findings(findings: &[DriftFinding]) -> Vec<DriftGroup> {
    let mut grouped: BTreeMap<String, Vec<DriftFinding>> = BTreeMap::new();

    for finding in findings {
        grouped
            .entry(finding.resource.clone())
            .or_default()
            .push(finding.clone());
    }

    let mut groups = Vec::new();

    for (resource, mut findings) in grouped {
        findings.sort_by(|a, b| b.score.cmp(&a.score));

        let highest_severity = findings
            .iter()
            .map(|f| f.severity.clone())
            .max()
            .unwrap_or(Severity::Info);

        let total_score = findings.iter().map(|f| f.score).sum();

        groups.push(DriftGroup {
            resource,
            findings,
            highest_severity,
            total_score,
        });
    }

    groups.sort_by(|a, b| b.total_score.cmp(&a.total_score));
    groups
}

fn summarize(findings: &[DriftFinding]) -> DriftSummary {
    let mut summary = DriftSummary::default();

    for finding in findings {
        match finding.severity {
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }

        summary.total_score += finding.score;
    }

    summary.overall_severity = if summary.high > 0 || summary.total_score >= 150 {
        Severity::High
    } else if summary.medium > 0 || summary.total_score >= 80 {
        Severity::Medium
    } else if summary.low > 0 || summary.total_score >= 20 {
        Severity::Low
    } else {
        Severity::Info
    };

    summary
}

fn is_success_status(status: u16) -> bool {
    (200..300).contains(&status)
}

fn matches_resource(pattern: &str, resource: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        resource.ends_with(suffix)
    } else {
        pattern == resource
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::{HttpService, ScanResult};
    use chrono::Utc;

    fn empty_diff() -> DiffReport {
        DiffReport {
            target: "example.com".to_string(),
            older_timestamp: Utc::now(),
            newer_timestamp: Utc::now(),
            new_ips: Vec::new(),
            removed_ips: Vec::new(),
            new_subdomains: Vec::new(),
            removed_subdomains: Vec::new(),
            new_services: Vec::new(),
            removed_services: Vec::new(),
            changed_services: Vec::new(),
        }
    }

    fn snapshot_with_target(target: &str) -> Snapshot {
        Snapshot {
            timestamp: Utc::now(),
            target: target.to_string(),
            scan: ScanResult {
                target: target.to_string(),
                resolved_ips: Vec::new(),
                subdomains: Vec::new(),
                services: Vec::new(),
            },
        }
    }

    #[test]
    fn classifies_admin_subdomain_as_high() {
        let mut diff = empty_diff();
        diff.new_subdomains.push("admin.example.com".to_string());

        let report = analyze_diff(&diff);

        assert_eq!(report.findings.len(), 1);
        assert!(matches!(report.findings[0].severity, Severity::High));
    }

    #[test]
    fn classifies_http_service_as_high() {
        let mut diff = empty_diff();
        diff.new_services.push(HttpService {
            host: "example.com".to_string(),
            url: "http://example.com".to_string(),
            scheme: "http".to_string(),
            status: 200,
            server: Some("nginx".to_string()),
        });

        let report = analyze_diff(&diff);

        assert_eq!(report.findings.len(), 1);
        assert!(matches!(report.findings[0].severity, Severity::High));
    }

    #[test]
    fn classifies_service_availability_change() {
        let mut diff = empty_diff();
        diff.changed_services.push(ServiceChange {
            host: "example.com".to_string(),
            url: "https://example.com".to_string(),
            scheme: "https".to_string(),
            before_status: 404,
            after_status: 200,
            before_server: Some("nginx".to_string()),
            after_server: Some("nginx".to_string()),
        });

        let report = analyze_diff(&diff);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.medium, 1);
    }

    #[test]
    fn suppresses_findings_with_policy() {
        let mut diff = empty_diff();
        diff.new_subdomains.push("dev.example.com".to_string());

        let policy = DriftPolicy {
            allowlisted_resources: vec!["dev.example.com".to_string()],
            allowlisted_categories: vec![],
        };

        let report = analyze_diff_with_policy(&diff, Some(&policy));

        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed_findings.len(), 1);
    }

    #[test]
    fn groups_findings_by_resource() {
        let mut diff = empty_diff();
        diff.new_subdomains.push("admin.example.com".to_string());
        diff.new_services.push(HttpService {
            host: "admin.example.com".to_string(),
            url: "http://admin.example.com".to_string(),
            scheme: "http".to_string(),
            status: 200,
            server: Some("nginx".to_string()),
        });

        let report = analyze_diff(&diff);

        assert!(!report.groups.is_empty());
        assert!(report.summary.total_score > 0);
    }

    #[test]
    fn builds_timeline_report() {
        let mut s1 = snapshot_with_target("example.com");
        let mut s2 = snapshot_with_target("example.com");
        let s3 = snapshot_with_target("example.com");

        s1.timestamp = Utc::now();
        s2.timestamp = s1.timestamp + chrono::Duration::minutes(5);

        s2.scan.subdomains.push("admin.example.com".to_string());

        let report = build_timeline_report("example.com", &[s1.clone(), s2.clone(), s3], None)
            .expect("timeline report should be built");

        assert_eq!(report.snapshot_count, 3);
        assert_eq!(report.transition_count, 2);
    }
}
