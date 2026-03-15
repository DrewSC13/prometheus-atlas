use atlas_core::{HttpService, SecurityHeaders};
use atlas_snapshot::Snapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceKey {
    host: String,
    url: String,
    scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChange {
    pub host: String,
    pub url: String,
    pub scheme: String,
    pub before_status: u16,
    pub after_status: u16,
    pub before_server: Option<String>,
    pub after_server: Option<String>,
    pub before_provider: Option<String>,
    pub after_provider: Option<String>,
    pub before_technologies: Vec<String>,
    pub after_technologies: Vec<String>,
    pub before_security_headers: SecurityHeaders,
    pub after_security_headers: SecurityHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub target: String,
    pub older_timestamp: DateTime<Utc>,
    pub newer_timestamp: DateTime<Utc>,
    pub new_ips: Vec<String>,
    pub removed_ips: Vec<String>,
    pub new_subdomains: Vec<String>,
    pub removed_subdomains: Vec<String>,
    pub new_services: Vec<HttpService>,
    pub removed_services: Vec<HttpService>,
    pub changed_services: Vec<ServiceChange>,
}

impl DiffReport {
    pub fn has_changes(&self) -> bool {
        !(self.new_ips.is_empty()
            && self.removed_ips.is_empty()
            && self.new_subdomains.is_empty()
            && self.removed_subdomains.is_empty()
            && self.new_services.is_empty()
            && self.removed_services.is_empty()
            && self.changed_services.is_empty())
    }
}

pub fn diff_snapshots(older: &Snapshot, newer: &Snapshot) -> DiffReport {
    let old_ips: BTreeSet<_> = older.scan.resolved_ips.iter().cloned().collect();
    let new_ips: BTreeSet<_> = newer.scan.resolved_ips.iter().cloned().collect();

    let old_subdomains: BTreeSet<_> = older.scan.subdomains.iter().cloned().collect();
    let new_subdomains: BTreeSet<_> = newer.scan.subdomains.iter().cloned().collect();

    let old_services = service_map(&older.scan.services);
    let new_services = service_map(&newer.scan.services);

    let added_ips = difference(&new_ips, &old_ips);
    let removed_ips = difference(&old_ips, &new_ips);

    let added_subdomains = difference(&new_subdomains, &old_subdomains);
    let removed_subdomains = difference(&old_subdomains, &new_subdomains);

    let mut added_services = Vec::new();
    let mut removed_services = Vec::new();
    let mut changed_services = Vec::new();

    for (key, new_service) in &new_services {
        match old_services.get(key) {
            None => added_services.push(new_service.clone()),
            Some(old_service) => {
                if service_changed(old_service, new_service) {
                    changed_services.push(ServiceChange {
                        host: new_service.host.clone(),
                        url: new_service.url.clone(),
                        scheme: new_service.scheme.clone(),
                        before_status: old_service.status,
                        after_status: new_service.status,
                        before_server: old_service.server.clone(),
                        after_server: new_service.server.clone(),
                        before_provider: old_service.provider.clone(),
                        after_provider: new_service.provider.clone(),
                        before_technologies: old_service.technologies.clone(),
                        after_technologies: new_service.technologies.clone(),
                        before_security_headers: old_service.security_headers.clone(),
                        after_security_headers: new_service.security_headers.clone(),
                    });
                }
            }
        }
    }

    for (key, old_service) in &old_services {
        if !new_services.contains_key(key) {
            removed_services.push(old_service.clone());
        }
    }

    added_services.sort_by(|a, b| a.url.cmp(&b.url));
    removed_services.sort_by(|a, b| a.url.cmp(&b.url));
    changed_services.sort_by(|a, b| a.url.cmp(&b.url));

    DiffReport {
        target: newer.scan.target.clone(),
        older_timestamp: older.timestamp,
        newer_timestamp: newer.timestamp,
        new_ips: added_ips,
        removed_ips,
        new_subdomains: added_subdomains,
        removed_subdomains,
        new_services: added_services,
        removed_services,
        changed_services,
    }
}

fn service_changed(old_service: &HttpService, new_service: &HttpService) -> bool {
    old_service.status != new_service.status
        || old_service.server != new_service.server
        || old_service.provider != new_service.provider
        || old_service.technologies != new_service.technologies
        || old_service.security_headers.strict_transport_security
            != new_service.security_headers.strict_transport_security
        || old_service.security_headers.content_security_policy
            != new_service.security_headers.content_security_policy
        || old_service.security_headers.x_frame_options
            != new_service.security_headers.x_frame_options
        || old_service.security_headers.x_content_type_options
            != new_service.security_headers.x_content_type_options
        || old_service.security_headers.referrer_policy
            != new_service.security_headers.referrer_policy
}

fn service_map(services: &[HttpService]) -> BTreeMap<ServiceKey, HttpService> {
    services
        .iter()
        .cloned()
        .map(|service| {
            let key = ServiceKey {
                host: service.host.clone(),
                url: service.url.clone(),
                scheme: service.scheme.clone(),
            };

            (key, service)
        })
        .collect()
}

fn difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::{HttpService, ScanResult};
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

    fn service(
        host: &str,
        url: &str,
        scheme: &str,
        status: u16,
        server: Option<&str>,
    ) -> HttpService {
        HttpService {
            host: host.to_string(),
            url: url.to_string(),
            scheme: scheme.to_string(),
            status,
            server: server.map(ToString::to_string),
            title: None,
            content_type: None,
            technologies: Vec::new(),
            provider: None,
            tls_enabled: scheme == "https",
            security_headers: headers(),
        }
    }

    fn snapshot(
        target: &str,
        ips: Vec<&str>,
        subdomains: Vec<&str>,
        services: Vec<HttpService>,
    ) -> Snapshot {
        Snapshot {
            timestamp: Utc::now(),
            target: target.to_string(),
            scan: ScanResult {
                target: target.to_string(),
                resolved_ips: ips.into_iter().map(ToString::to_string).collect(),
                subdomains: subdomains.into_iter().map(ToString::to_string).collect(),
                services,
            },
        }
    }

    #[test]
    fn detects_new_and_removed_items() {
        let old = snapshot(
            "example.com",
            vec!["1.1.1.1"],
            vec!["www.example.com"],
            vec![service(
                "example.com",
                "http://example.com",
                "http",
                200,
                Some("nginx"),
            )],
        );

        let new = snapshot(
            "example.com",
            vec!["2.2.2.2"],
            vec!["api.example.com"],
            vec![service(
                "api.example.com",
                "https://api.example.com",
                "https",
                200,
                Some("cloudflare"),
            )],
        );

        let report = diff_snapshots(&old, &new);

        assert_eq!(report.new_ips, vec!["2.2.2.2"]);
        assert_eq!(report.removed_ips, vec!["1.1.1.1"]);
        assert_eq!(report.new_subdomains, vec!["api.example.com"]);
        assert_eq!(report.removed_subdomains, vec!["www.example.com"]);
        assert_eq!(report.new_services.len(), 1);
        assert_eq!(report.removed_services.len(), 1);
    }

    #[test]
    fn detects_changed_services() {
        let old = snapshot(
            "example.com",
            vec![],
            vec![],
            vec![service(
                "example.com",
                "https://example.com",
                "https",
                200,
                Some("nginx"),
            )],
        );

        let mut changed = service(
            "example.com",
            "https://example.com",
            "https",
            503,
            Some("cloudflare"),
        );
        changed.provider = Some("Cloudflare".to_string());
        changed.technologies = vec!["cloudflare".to_string()];

        let new = snapshot("example.com", vec![], vec![], vec![changed]);

        let report = diff_snapshots(&old, &new);

        assert!(report.new_services.is_empty());
        assert!(report.removed_services.is_empty());
        assert_eq!(report.changed_services.len(), 1);
        assert_eq!(report.changed_services[0].before_status, 200);
        assert_eq!(report.changed_services[0].after_status, 503);
    }
}
