use anyhow::Result;
use futures::future::join_all;
use std::collections::BTreeSet;
use tokio::net::lookup_host;

const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "api", "dev", "staging", "admin", "app", "test", "portal", "auth", "beta",
];

pub async fn resolve_ips(host: &str) -> Result<Vec<String>> {
    let addrs = lookup_host((host, 0)).await?;
    let mut ips = BTreeSet::new();

    for addr in addrs {
        ips.insert(addr.ip().to_string());
    }

    Ok(ips.into_iter().collect())
}

pub async fn enumerate_common_subdomains(domain: &str) -> Vec<String> {
    let tasks = COMMON_SUBDOMAINS.iter().map(|sub| {
        let fqdn = format!("{sub}.{domain}");

        async move {
            let exists = match lookup_host((fqdn.as_str(), 0)).await {
                Ok(mut resolved) => resolved.next().is_some(),
                Err(_) => false,
            };

            if exists { Some(fqdn) } else { None }
        }
    });

    let results = join_all(tasks).await;

    let mut discovered = BTreeSet::new();
    for item in results.into_iter().flatten() {
        discovered.insert(item);
    }

    discovered.into_iter().collect()
}
