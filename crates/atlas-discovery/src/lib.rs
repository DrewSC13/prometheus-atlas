use anyhow::Result;
use atlas_core::ScanResult;
use std::collections::BTreeSet;

pub async fn scan_target(target: &str) -> Result<ScanResult> {
    let normalized = normalize_target(target);

    let root_ips = atlas_dns::resolve_ips(&normalized)
        .await
        .unwrap_or_default();
    let subdomains = atlas_dns::enumerate_common_subdomains(&normalized).await;

    let mut hosts = BTreeSet::new();
    hosts.insert(normalized.clone());

    for sub in &subdomains {
        hosts.insert(sub.clone());
    }

    let host_list: Vec<String> = hosts.into_iter().collect();
    let services = atlas_http::probe_hosts(&host_list).await;

    Ok(ScanResult {
        target: normalized,
        resolved_ips: root_ips,
        subdomains,
        services,
    })
}

fn normalize_target(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalize_target;

    #[test]
    fn normalizes_http_target() {
        assert_eq!(normalize_target("https://Example.com/"), "example.com");
    }
}
