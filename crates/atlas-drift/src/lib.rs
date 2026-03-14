use atlas_diff::{DiffReport, ServiceChange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub resource: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftSummary {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub target: String,
    pub older_timestamp: DateTime<Utc>,
    pub newer_timestamp: DateTime<Utc>,
    pub findings: Vec<DriftFinding>,
    pub summary: DriftSummary,
}

pub fn analyze_diff(diff: &DiffReport) -> DriftReport {
    let mut findings = Vec::new();

    for subdomain in &diff.new_subdomains {
        findings.push(classify_new_subdomain(subdomain));
    }

    for service in &diff.new_services {
        findings.push(classify_new_service(
            service.url.as_str(),
            service.scheme.as_str(),
        ));
    }

    for change in &diff.changed_services {
        if let Some(finding) = classify_service_change(change) {
            findings.push(finding);
        }
    }

    for service in &diff.removed_services {
        findings.push(DriftFinding {
            severity: Severity::Info,
            category: "service_removed".to_string(),
            title: "Servicio removido".to_string(),
            resource: service.url.clone(),
            description: format!(
                "El servicio {} dejó de estar presente entre snapshots.",
                service.url
            ),
        });
    }

    for subdomain in &diff.removed_subdomains {
        findings.push(DriftFinding {
            severity: Severity::Info,
            category: "subdomain_removed".to_string(),
            title: "Subdominio removido".to_string(),
            resource: subdomain.clone(),
            description: format!(
                "El subdominio {} ya no fue detectado en el snapshot más reciente.",
                subdomain
            ),
        });
    }

    let summary = summarize(&findings);

    DriftReport {
        target: diff.target.clone(),
        older_timestamp: diff.older_timestamp,
        newer_timestamp: diff.newer_timestamp,
        findings,
        summary,
    }
}

fn classify_new_subdomain(subdomain: &str) -> DriftFinding {
    let lowered = subdomain.to_lowercase();

    if lowered.starts_with("admin.") || lowered.contains(".admin.") {
        DriftFinding {
            severity: Severity::High,
            category: "new_admin_subdomain".to_string(),
            title: "Nuevo subdominio administrativo".to_string(),
            resource: subdomain.to_string(),
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
            category: "new_nonprod_subdomain".to_string(),
            title: "Nuevo subdominio no productivo".to_string(),
            resource: subdomain.to_string(),
            description: format!(
                "Se detectó el subdominio {} asociado a entornos de desarrollo, prueba o staging.",
                subdomain
            ),
        }
    } else {
        DriftFinding {
            severity: Severity::Low,
            category: "new_subdomain".to_string(),
            title: "Nuevo subdominio detectado".to_string(),
            resource: subdomain.to_string(),
            description: format!(
                "Se detectó un nuevo subdominio {} que no existía en el snapshot anterior.",
                subdomain
            ),
        }
    }
}

fn classify_new_service(url: &str, scheme: &str) -> DriftFinding {
    match scheme {
        "http" => DriftFinding {
            severity: Severity::High,
            category: "new_http_service".to_string(),
            title: "Nuevo servicio HTTP expuesto".to_string(),
            resource: url.to_string(),
            description: format!(
                "Se detectó un nuevo servicio accesible por HTTP sin cifrado en {}.",
                url
            ),
        },
        "https" => DriftFinding {
            severity: Severity::Medium,
            category: "new_https_service".to_string(),
            title: "Nuevo servicio HTTPS expuesto".to_string(),
            resource: url.to_string(),
            description: format!("Se detectó un nuevo servicio HTTPS accesible en {}.", url),
        },
        _ => DriftFinding {
            severity: Severity::Low,
            category: "new_service".to_string(),
            title: "Nuevo servicio detectado".to_string(),
            resource: url.to_string(),
            description: format!("Se detectó un nuevo servicio expuesto en {}.", url),
        },
    }
}

fn classify_service_change(change: &ServiceChange) -> Option<DriftFinding> {
    let became_available =
        !is_success_status(change.before_status) && is_success_status(change.after_status);
    let changed_server = change.before_server != change.after_server;

    if became_available {
        return Some(DriftFinding {
            severity: Severity::Medium,
            category: "service_became_available".to_string(),
            title: "Servicio ahora accesible".to_string(),
            resource: change.url.clone(),
            description: format!(
                "El servicio {} cambió de estado {} a {}, lo que indica que ahora está accesible.",
                change.url, change.before_status, change.after_status
            ),
        });
    }

    if changed_server {
        return Some(DriftFinding {
            severity: Severity::Low,
            category: "service_backend_changed".to_string(),
            title: "Cambio de servidor o backend".to_string(),
            resource: change.url.clone(),
            description: format!(
                "El servicio {} cambió el encabezado Server de {:?} a {:?}.",
                change.url, change.before_server, change.after_server
            ),
        });
    }

    None
}

fn is_success_status(status: u16) -> bool {
    (200..300).contains(&status)
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
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::HttpService;
    use atlas_diff::DiffReport;
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
}
