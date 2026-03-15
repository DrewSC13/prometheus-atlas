use anyhow::{bail, Context, Result};
use atlas_diff::{DiffReport, ServiceChange};
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Criticality::Low => write!(f, "LOW"),
            Criticality::Medium => write!(f, "MEDIUM"),
            Criticality::High => write!(f, "HIGH"),
            Criticality::Critical => write!(f, "CRITICAL"),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetType {
    Ip,
    Subdomain,
    Service,
    Unknown,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::Ip => write!(f, "Ip"),
            AssetType::Subdomain => write!(f, "Subdomain"),
            AssetType::Service => write!(f, "Service"),
            AssetType::Unknown => write!(f, "Unknown"),
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
    pub asset_type: AssetType,
    pub environment: Environment,
    pub criticality: Criticality,
    pub tags: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetTypeSummary {
    pub ips: usize,
    pub subdomains: usize,
    pub services: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftSummary {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total_score: u32,
    pub overall_severity: Severity,
    pub critical_findings: usize,
    pub asset_types: AssetTypeSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftGroup {
    pub resource: String,
    pub findings: Vec<DriftFinding>,
    pub highest_severity: Severity,
    pub highest_criticality: Criticality,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentOverride {
    pub pattern: String,
    pub environment: Environment,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftPolicy {
    pub allowlisted_resources: Vec<String>,
    pub allowlisted_categories: Vec<String>,
    pub critical_resources: Vec<String>,
    pub critical_patterns: Vec<String>,
    pub environment_overrides: Vec<EnvironmentOverride>,
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
pub struct TechnologyAggregate {
    pub technology: String,
    pub occurrences: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAggregate {
    pub provider: String,
    pub occurrences: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineExecutiveSummary {
    pub total_score: u32,
    pub overall_severity: Severity,
    pub total_findings: usize,
    pub unique_resources: usize,
    pub critical_findings: usize,
    pub asset_types: AssetTypeSummary,
    pub top_resources: Vec<ResourceAggregate>,
    pub top_categories: Vec<CategoryAggregate>,
    pub top_technologies: Vec<TechnologyAggregate>,
    pub top_providers: Vec<ProviderAggregate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineReport {
    pub target: String,
    pub snapshot_count: usize,
    pub transition_count: usize,
    pub transitions: Vec<TimelineTransition>,
    pub executive: TimelineExecutiveSummary,
}

struct FindingSpec {
    severity: Severity,
    score: u32,
    category: String,
    title: String,
    resource: String,
    environment: Environment,
    criticality: Criticality,
    tags: Vec<String>,
    description: String,
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

    pub fn is_critical_resource(&self, resource: &str) -> bool {
        self.critical_resources.iter().any(|r| r == resource)
            || self
                .critical_patterns
                .iter()
                .any(|pattern| matches_resource(pattern, resource))
    }
}

pub fn analyze_diff(diff: &DiffReport) -> DriftReport {
    analyze_diff_with_policy(diff, None)
}

pub fn analyze_diff_with_policy(diff: &DiffReport, policy: Option<&DriftPolicy>) -> DriftReport {
    let mut findings = Vec::new();

    for ip in &diff.new_ips {
        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Low,
            score: 10,
            category: "new_ip".to_string(),
            title: "Nueva IP detectada".to_string(),
            resource: ip.to_string(),
            environment: infer_environment_with_policy(ip, policy),
            criticality: classify_criticality(ip, policy, &Environment::Unknown, &AssetType::Ip),
            tags: vec!["network".to_string(), "new-exposure".to_string()],
            description: format!(
                "Se detectó una nueva dirección IP {} en el snapshot más reciente.",
                ip
            ),
        }));
    }

    for ip in &diff.removed_ips {
        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Info,
            score: 3,
            category: "removed_ip".to_string(),
            title: "IP removida".to_string(),
            resource: ip.to_string(),
            environment: infer_environment_with_policy(ip, policy),
            criticality: classify_criticality(ip, policy, &Environment::Unknown, &AssetType::Ip),
            tags: vec!["network".to_string(), "removed".to_string()],
            description: format!(
                "La dirección IP {} dejó de aparecer en el snapshot más reciente.",
                ip
            ),
        }));
    }

    for subdomain in &diff.new_subdomains {
        findings.push(classify_new_subdomain(subdomain, policy));
    }

    for subdomain in &diff.removed_subdomains {
        let environment = infer_environment_with_policy(subdomain, policy);
        let criticality =
            classify_criticality(subdomain, policy, &environment, &AssetType::Subdomain);

        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Info,
            score: 5,
            category: "subdomain_removed".to_string(),
            title: "Subdominio removido".to_string(),
            resource: subdomain.clone(),
            environment,
            criticality,
            tags: vec!["subdomain".to_string(), "removed".to_string()],
            description: format!(
                "El subdominio {} ya no fue detectado en el snapshot más reciente.",
                subdomain
            ),
        }));
    }

    for service in &diff.new_services {
        findings.push(classify_new_service(
            service.url.as_str(),
            service.scheme.as_str(),
            service.technologies.as_slice(),
            service.provider.as_deref(),
            &service.security_headers,
            policy,
        ));
    }

    for service in &diff.removed_services {
        let environment = infer_environment_with_policy(service.url.as_str(), policy);
        let criticality = classify_criticality(
            service.url.as_str(),
            policy,
            &environment,
            &AssetType::Service,
        );

        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Info,
            score: 5,
            category: "service_removed".to_string(),
            title: "Servicio removido".to_string(),
            resource: service.url.clone(),
            environment,
            criticality,
            tags: vec!["service".to_string(), "removed".to_string()],
            description: format!(
                "El servicio {} dejó de estar presente entre snapshots.",
                service.url
            ),
        }));
    }

    for change in &diff.changed_services {
        findings.extend(classify_service_change(change, policy));
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
    let mut critical_findings = 0;
    let mut asset_types = AssetTypeSummary::default();

    let mut resource_map: BTreeMap<String, ResourceAggregate> = BTreeMap::new();
    let mut category_map: BTreeMap<String, CategoryAggregate> = BTreeMap::new();
    let mut technology_map: BTreeMap<String, TechnologyAggregate> = BTreeMap::new();
    let mut provider_map: BTreeMap<String, ProviderAggregate> = BTreeMap::new();

    for transition in transitions {
        total_score += transition.report.summary.total_score;
        total_findings += transition.report.findings.len();
        critical_findings += transition.report.summary.critical_findings;

        for finding in &transition.report.findings {
            unique_resources.insert(finding.resource.clone());
            increment_asset_type(&mut asset_types, &finding.asset_type);

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

            for tag in &finding.tags {
                if let Some(tech) = tag.strip_prefix("tech:") {
                    technology_map
                        .entry(tech.to_string())
                        .and_modify(|entry| entry.occurrences += 1)
                        .or_insert(TechnologyAggregate {
                            technology: tech.to_string(),
                            occurrences: 1,
                        });
                }

                if let Some(provider) = tag.strip_prefix("provider:") {
                    provider_map
                        .entry(provider.to_string())
                        .and_modify(|entry| entry.occurrences += 1)
                        .or_insert(ProviderAggregate {
                            provider: provider.to_string(),
                            occurrences: 1,
                        });
                }
            }
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

    let mut top_technologies: Vec<_> = technology_map.into_values().collect();
    top_technologies.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
    top_technologies.truncate(5);

    let mut top_providers: Vec<_> = provider_map.into_values().collect();
    top_providers.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
    top_providers.truncate(5);

    TimelineExecutiveSummary {
        total_score,
        overall_severity,
        total_findings,
        unique_resources: unique_resources.len(),
        critical_findings,
        asset_types,
        top_resources,
        top_categories,
        top_technologies,
        top_providers,
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

fn classify_new_subdomain(subdomain: &str, policy: Option<&DriftPolicy>) -> DriftFinding {
    let environment = infer_environment_with_policy(subdomain, policy);
    let criticality = classify_criticality(subdomain, policy, &environment, &AssetType::Subdomain);
    let lowered = subdomain.to_lowercase();

    if lowered.starts_with("admin.") || lowered.contains(".admin.") {
        build_base_finding(FindingSpec {
            severity: Severity::High,
            score: 95,
            category: "new_admin_subdomain".to_string(),
            title: "Nuevo subdominio administrativo".to_string(),
            resource: subdomain.to_string(),
            environment,
            criticality: elevate_criticality(criticality, Criticality::High),
            tags: vec![
                "subdomain".to_string(),
                "admin".to_string(),
                "new-exposure".to_string(),
            ],
            description: format!(
                "Se detectó el subdominio {} con patrón administrativo, lo que puede indicar nueva superficie sensible expuesta.",
                subdomain
            ),
        })
    } else if lowered.starts_with("dev.")
        || lowered.starts_with("staging.")
        || lowered.contains(".dev.")
        || lowered.contains(".staging.")
        || lowered.starts_with("test.")
        || lowered.contains(".test.")
    {
        build_base_finding(FindingSpec {
            severity: Severity::Medium,
            score: 55,
            category: "new_nonprod_subdomain".to_string(),
            title: "Nuevo subdominio no productivo".to_string(),
            resource: subdomain.to_string(),
            environment,
            criticality,
            tags: vec![
                "subdomain".to_string(),
                "nonprod".to_string(),
                "new-exposure".to_string(),
            ],
            description: format!(
                "Se detectó el subdominio {} asociado a entornos de desarrollo, prueba o staging.",
                subdomain
            ),
        })
    } else {
        build_base_finding(FindingSpec {
            severity: Severity::Low,
            score: 20,
            category: "new_subdomain".to_string(),
            title: "Nuevo subdominio detectado".to_string(),
            resource: subdomain.to_string(),
            environment,
            criticality,
            tags: vec!["subdomain".to_string(), "new-exposure".to_string()],
            description: format!(
                "Se detectó un nuevo subdominio {} que no existía en el snapshot anterior.",
                subdomain
            ),
        })
    }
}

fn classify_new_service(
    url: &str,
    scheme: &str,
    technologies: &[String],
    provider: Option<&str>,
    security_headers: &atlas_core::SecurityHeaders,
    policy: Option<&DriftPolicy>,
) -> DriftFinding {
    let environment = infer_environment_with_policy(url, policy);
    let base_criticality = classify_criticality(url, policy, &environment, &AssetType::Service);

    let mut tags = vec!["service".to_string(), "new-exposure".to_string()];
    tags.extend(technology_tags(technologies));
    if let Some(provider) = provider {
        tags.push(format!("provider:{provider}"));
    }

    let missing_headers = count_missing_security_headers(security_headers);

    match scheme {
        "http" => {
            tags.push("plaintext".to_string());
            if matches!(environment, Environment::Admin) {
                tags.push("admin".to_string());
            }

            build_base_finding(FindingSpec {
                severity: Severity::High,
                score: 90 + (missing_headers as u32 * 2),
                category: "new_http_service".to_string(),
                title: "Nuevo servicio HTTP expuesto".to_string(),
                resource: url.to_string(),
                environment: environment.clone(),
                criticality: elevate_criticality(
                    base_criticality,
                    if matches!(environment, Environment::Admin) {
                        Criticality::Critical
                    } else {
                        Criticality::High
                    },
                ),
                tags,
                description: format!(
                    "Se detectó un nuevo servicio accesible por HTTP sin cifrado en {}.",
                    url
                ),
            })
        }
        "https" => {
            tags.push("tls".to_string());

            let severity = if technologies.iter().any(|t| t == "admin-ui") {
                Severity::High
            } else {
                Severity::Medium
            };

            let score = if technologies.iter().any(|t| t == "admin-ui") {
                70
            } else {
                50
            } + (missing_headers as u32 * 2);

            build_base_finding(FindingSpec {
                severity,
                score,
                category: "new_https_service".to_string(),
                title: "Nuevo servicio HTTPS expuesto".to_string(),
                resource: url.to_string(),
                environment,
                criticality: base_criticality,
                tags,
                description: format!("Se detectó un nuevo servicio HTTPS accesible en {}.", url),
            })
        }
        _ => build_base_finding(FindingSpec {
            severity: Severity::Low,
            score: 20,
            category: "new_service".to_string(),
            title: "Nuevo servicio detectado".to_string(),
            resource: url.to_string(),
            environment,
            criticality: base_criticality,
            tags,
            description: format!("Se detectó un nuevo servicio expuesto en {}.", url),
        }),
    }
}

fn classify_service_change(
    change: &ServiceChange,
    policy: Option<&DriftPolicy>,
) -> Vec<DriftFinding> {
    let mut findings = Vec::new();

    let became_available =
        !is_success_status(change.before_status) && is_success_status(change.after_status);
    let changed_server = change.before_server != change.after_server;
    let changed_provider = change.before_provider != change.after_provider;
    let changed_tech = change.before_technologies != change.after_technologies;
    let headers_weakened = security_headers_weakened(
        &change.before_security_headers,
        &change.after_security_headers,
    );

    let environment = infer_environment_with_policy(change.url.as_str(), policy);
    let criticality = classify_criticality(
        change.url.as_str(),
        policy,
        &environment,
        &AssetType::Service,
    );

    if became_available {
        findings.push(build_base_finding(FindingSpec {
            severity: if matches!(environment, Environment::Admin | Environment::Production) {
                Severity::High
            } else {
                Severity::Medium
            },
            score: if matches!(environment, Environment::Admin | Environment::Production) {
                75
            } else {
                60
            },
            category: "service_became_available".to_string(),
            title: "Servicio ahora accesible".to_string(),
            resource: change.url.clone(),
            environment: environment.clone(),
            criticality: criticality.clone(),
            tags: vec![
                "service".to_string(),
                "availability-change".to_string(),
                "service-available".to_string(),
            ],
            description: format!(
                "El servicio {} cambió de estado {} a {}, lo que indica que ahora está accesible.",
                change.url, change.before_status, change.after_status
            ),
        }));
    }

    if changed_server || changed_provider {
        let severity = if matches!(criticality, Criticality::Critical | Criticality::High) {
            Severity::Medium
        } else {
            Severity::Low
        };

        let score = if matches!(criticality, Criticality::Critical | Criticality::High) {
            30
        } else {
            15
        };

        let mut tags = vec!["service".to_string(), "backend-change".to_string()];
        if let Some(provider) = &change.after_provider {
            tags.push(format!("provider:{provider}"));
        }

        findings.push(build_base_finding(FindingSpec {
            severity,
            score,
            category: "service_backend_changed".to_string(),
            title: "Cambio de servidor o backend".to_string(),
            resource: change.url.clone(),
            environment: environment.clone(),
            criticality: criticality.clone(),
            tags,
            description: format!(
                "El servicio {} cambió backend/provider/server de {:?}/{:?} a {:?}/{:?}.",
                change.url,
                change.before_server,
                change.before_provider,
                change.after_server,
                change.after_provider
            ),
        }));
    }

    if changed_tech {
        let mut tags = vec!["service".to_string(), "technology-change".to_string()];
        tags.extend(technology_tags(&change.after_technologies));

        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Medium,
            score: 40,
            category: "service_fingerprint_changed".to_string(),
            title: "Fingerprint tecnológico cambiado".to_string(),
            resource: change.url.clone(),
            environment: environment.clone(),
            criticality: criticality.clone(),
            tags,
            description: format!(
                "El servicio {} cambió de tecnologías {:?} a {:?}.",
                change.url, change.before_technologies, change.after_technologies
            ),
        }));
    }

    if headers_weakened {
        findings.push(build_base_finding(FindingSpec {
            severity: Severity::Medium,
            score: 45,
            category: "security_headers_weakened".to_string(),
            title: "Headers de seguridad debilitados".to_string(),
            resource: change.url.clone(),
            environment,
            criticality,
            tags: vec![
                "service".to_string(),
                "security-headers".to_string(),
                "hardening-regression".to_string(),
            ],
            description: format!(
                "El servicio {} perdió uno o más headers de seguridad respecto al snapshot anterior.",
                change.url
            ),
        }));
    }

    findings
}

fn build_base_finding(mut spec: FindingSpec) -> DriftFinding {
    let asset_type = infer_asset_type(&spec.resource);

    if matches!(spec.criticality, Criticality::Critical) {
        spec.tags.push("critical-resource".to_string());
    }

    DriftFinding {
        severity: spec.severity,
        score: spec.score,
        category: spec.category,
        title: spec.title,
        resource: spec.resource,
        asset_type,
        environment: spec.environment,
        criticality: spec.criticality,
        tags: spec.tags,
        description: spec.description,
    }
}

fn infer_environment_with_policy(resource: &str, policy: Option<&DriftPolicy>) -> Environment {
    if let Some(policy) = policy {
        for override_rule in &policy.environment_overrides {
            if matches_resource(&override_rule.pattern, resource) {
                return override_rule.environment.clone();
            }
        }
    }

    infer_environment(resource)
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

fn infer_asset_type(resource: &str) -> AssetType {
    if resource.parse::<IpAddr>().is_ok() {
        AssetType::Ip
    } else if resource.starts_with("http://") || resource.starts_with("https://") {
        AssetType::Service
    } else if resource.contains('.') {
        AssetType::Subdomain
    } else {
        AssetType::Unknown
    }
}

fn classify_criticality(
    resource: &str,
    policy: Option<&DriftPolicy>,
    environment: &Environment,
    asset_type: &AssetType,
) -> Criticality {
    if let Some(policy) = policy {
        if policy.is_critical_resource(resource) {
            return Criticality::Critical;
        }
    }

    match (environment, asset_type) {
        (Environment::Admin, AssetType::Service) => Criticality::Critical,
        (Environment::Admin, _) => Criticality::High,
        (Environment::Production, AssetType::Service) => Criticality::High,
        (Environment::Production, _) => Criticality::Medium,
        (Environment::Staging, _) => Criticality::Medium,
        (Environment::Development, _) | (Environment::Test, _) => Criticality::Low,
        _ => Criticality::Low,
    }
}

fn elevate_criticality(current: Criticality, minimum: Criticality) -> Criticality {
    if current < minimum {
        minimum
    } else {
        current
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

        let highest_criticality = findings
            .iter()
            .map(|f| f.criticality.clone())
            .max()
            .unwrap_or(Criticality::Low);

        let total_score = findings.iter().map(|f| f.score).sum();

        groups.push(DriftGroup {
            resource,
            findings,
            highest_severity,
            highest_criticality,
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

        if matches!(
            finding.criticality,
            Criticality::Critical | Criticality::High
        ) {
            summary.critical_findings += 1;
        }

        increment_asset_type(&mut summary.asset_types, &finding.asset_type);

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

fn increment_asset_type(summary: &mut AssetTypeSummary, asset_type: &AssetType) {
    match asset_type {
        AssetType::Ip => summary.ips += 1,
        AssetType::Subdomain => summary.subdomains += 1,
        AssetType::Service => summary.services += 1,
        AssetType::Unknown => summary.unknown += 1,
    }
}

fn technology_tags(technologies: &[String]) -> Vec<String> {
    technologies
        .iter()
        .map(|tech| format!("tech:{tech}"))
        .collect()
}

fn count_missing_security_headers(headers: &atlas_core::SecurityHeaders) -> usize {
    [
        headers.strict_transport_security,
        headers.content_security_policy,
        headers.x_frame_options,
        headers.x_content_type_options,
        headers.referrer_policy,
    ]
    .iter()
    .filter(|present| !**present)
    .count()
}

fn security_headers_weakened(
    before: &atlas_core::SecurityHeaders,
    after: &atlas_core::SecurityHeaders,
) -> bool {
    (before.strict_transport_security && !after.strict_transport_security)
        || (before.content_security_policy && !after.content_security_policy)
        || (before.x_frame_options && !after.x_frame_options)
        || (before.x_content_type_options && !after.x_content_type_options)
        || (before.referrer_policy && !after.referrer_policy)
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
    use atlas_core::{HttpService, ScanResult, SecurityHeaders};
    use chrono::Utc;

    fn headers() -> SecurityHeaders {
        SecurityHeaders {
            strict_transport_security: false,
            content_security_policy: false,
            x_frame_options: false,
            x_content_type_options: false,
            referrer_policy: false,
        }
    }

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
            title: None,
            content_type: Some("text/html".to_string()),
            technologies: vec!["nginx".to_string()],
            provider: None,
            tls_enabled: false,
            security_headers: headers(),
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
            before_provider: None,
            after_provider: None,
            before_technologies: vec![],
            after_technologies: vec![],
            before_security_headers: headers(),
            after_security_headers: headers(),
        });

        let report = analyze_diff(&diff);

        assert!(!report.findings.is_empty());
    }

    #[test]
    fn suppresses_findings_with_policy() {
        let mut diff = empty_diff();
        diff.new_subdomains.push("dev.example.com".to_string());

        let policy = DriftPolicy {
            allowlisted_resources: vec!["dev.example.com".to_string()],
            allowlisted_categories: vec![],
            critical_resources: vec![],
            critical_patterns: vec![],
            environment_overrides: vec![],
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
            title: None,
            content_type: Some("text/html".to_string()),
            technologies: vec!["nginx".to_string()],
            provider: None,
            tls_enabled: false,
            security_headers: headers(),
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

    #[test]
    fn marks_critical_resources_from_policy() {
        let mut diff = empty_diff();
        diff.new_services.push(HttpService {
            host: "api.example.com".to_string(),
            url: "https://api.example.com".to_string(),
            scheme: "https".to_string(),
            status: 200,
            server: Some("nginx".to_string()),
            title: None,
            content_type: Some("application/json".to_string()),
            technologies: vec!["nginx".to_string(), "json-api".to_string()],
            provider: None,
            tls_enabled: true,
            security_headers: headers(),
        });

        let policy = DriftPolicy {
            allowlisted_resources: vec![],
            allowlisted_categories: vec![],
            critical_resources: vec!["https://api.example.com".to_string()],
            critical_patterns: vec![],
            environment_overrides: vec![],
        };

        let report = analyze_diff_with_policy(&diff, Some(&policy));

        assert!(matches!(
            report.findings[0].criticality,
            Criticality::Critical
        ));
    }

    #[test]
    fn infers_asset_type_for_ip() {
        let finding = build_base_finding(FindingSpec {
            severity: Severity::Low,
            score: 10,
            category: "new_ip".to_string(),
            title: "Nueva IP detectada".to_string(),
            resource: "1.1.1.1".to_string(),
            environment: Environment::Unknown,
            criticality: Criticality::Low,
            tags: vec![],
            description: "desc".to_string(),
        });

        assert!(matches!(finding.asset_type, AssetType::Ip));
    }

    #[test]
    fn detects_security_header_regression() {
        let mut before = headers();
        before.content_security_policy = true;

        let after = headers();

        assert!(security_headers_weakened(&before, &after));
    }
}
