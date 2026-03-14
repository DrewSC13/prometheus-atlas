use atlas_core::HttpService;
use futures::future::join_all;
use reqwest::Client;
use reqwest::header::SERVER;
use std::time::Duration;

pub async fn probe_hosts(hosts: &[String]) -> Vec<HttpService> {
    let client = match Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return Vec::new(),
    };

    let tasks = hosts.iter().flat_map(|host| {
        let client_http = client.clone();
        let client_https = client.clone();

        let host_http = host.clone();
        let host_https = host.clone();

        [
            tokio::spawn(async move { probe_one(&client_http, &host_http, "http").await }),
            tokio::spawn(async move { probe_one(&client_https, &host_https, "https").await }),
        ]
    });

    let results = join_all(tasks).await;

    let mut services = Vec::new();

    for result in results {
        if let Ok(Some(service)) = result {
            services.push(service);
        }
    }

    services.sort_by(|a, b| a.url.cmp(&b.url));
    services.dedup_by(|a, b| a.url == b.url);

    services
}

async fn probe_one(client: &Client, host: &str, scheme: &str) -> Option<HttpService> {
    let url = format!("{scheme}://{host}");

    let response = client.get(&url).send().await.ok()?;
    let status = response.status().as_u16();
    let server = response
        .headers()
        .get(SERVER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Some(HttpService {
        host: host.to_string(),
        url,
        scheme: scheme.to_string(),
        status,
        server,
    })
}
