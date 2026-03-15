use atlas_core::{HttpService, SecurityHeaders};
use futures::future::join_all;
use reqwest::header::{
    HeaderMap, CONTENT_SECURITY_POLICY, CONTENT_TYPE, SERVER, STRICT_TRANSPORT_SECURITY, VIA,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use reqwest::Client;
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
    let headers = response.headers().clone();

    let server = header_to_string(&headers, SERVER);
    let content_type = header_to_string(&headers, CONTENT_TYPE);
    let title = extract_title(response.text().await.ok().as_deref());

    let technologies = detect_technologies(
        &headers,
        server.as_deref(),
        content_type.as_deref(),
        title.as_deref(),
    );
    let provider = detect_provider(&headers, server.as_deref());
    let tls_enabled = scheme == "https";
    let security_headers = detect_security_headers(&headers);

    Some(HttpService {
        host: host.to_string(),
        url,
        scheme: scheme.to_string(),
        status,
        server,
        title,
        content_type,
        technologies,
        provider,
        tls_enabled,
        security_headers,
    })
}

fn header_to_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn detect_security_headers(headers: &HeaderMap) -> SecurityHeaders {
    SecurityHeaders {
        strict_transport_security: headers.contains_key(STRICT_TRANSPORT_SECURITY),
        content_security_policy: headers.contains_key(CONTENT_SECURITY_POLICY),
        x_frame_options: headers.contains_key(X_FRAME_OPTIONS),
        x_content_type_options: headers.contains_key(X_CONTENT_TYPE_OPTIONS),
        referrer_policy: headers.contains_key("referrer-policy"),
    }
}

fn detect_technologies(
    headers: &HeaderMap,
    server: Option<&str>,
    content_type: Option<&str>,
    title: Option<&str>,
) -> Vec<String> {
    let mut tech = Vec::new();

    if let Some(server) = server {
        let s = server.to_lowercase();

        if s.contains("cloudflare") {
            tech.push("cloudflare".to_string());
        }
        if s.contains("nginx") {
            tech.push("nginx".to_string());
        }
        if s.contains("apache") {
            tech.push("apache".to_string());
        }
        if s.contains("openresty") {
            tech.push("openresty".to_string());
        }
        if s.contains("envoy") {
            tech.push("envoy".to_string());
        }
        if s.contains("iis") {
            tech.push("iis".to_string());
        }
        if s.contains("gws") {
            tech.push("google-web-server".to_string());
        }
    }

    if let Some(x_powered_by) = header_to_string(
        headers,
        reqwest::header::HeaderName::from_static("x-powered-by"),
    ) {
        let x = x_powered_by.to_lowercase();

        if x.contains("php") {
            tech.push("php".to_string());
        }
        if x.contains("express") {
            tech.push("nodejs-express".to_string());
        }
        if x.contains("asp.net") {
            tech.push("aspnet".to_string());
        }
    }

    if let Some(via) = header_to_string(headers, VIA) {
        let v = via.to_lowercase();

        if v.contains("varnish") {
            tech.push("varnish".to_string());
        }
        if v.contains("envoy") {
            tech.push("envoy".to_string());
        }
    }

    if headers.contains_key("cf-cache-status") {
        tech.push("cloudflare-cache".to_string());
    }

    if let Some(content_type) = content_type {
        let ct = content_type.to_lowercase();

        if ct.contains("application/json") {
            tech.push("json-api".to_string());
        }
        if ct.contains("text/html") {
            tech.push("html-app".to_string());
        }
    }

    if let Some(title) = title {
        let t = title.to_lowercase();

        if t.contains("admin") {
            tech.push("admin-ui".to_string());
        }
        if t.contains("login") {
            tech.push("login-portal".to_string());
        }
        if t.contains("dashboard") {
            tech.push("dashboard".to_string());
        }
    }

    tech.sort();
    tech.dedup();
    tech
}

fn detect_provider(headers: &HeaderMap, server: Option<&str>) -> Option<String> {
    if headers.contains_key("cf-cache-status")
        || server
            .map(|s| s.to_lowercase().contains("cloudflare"))
            .unwrap_or(false)
    {
        return Some("Cloudflare".to_string());
    }

    if server
        .map(|s| s.eq_ignore_ascii_case("gws"))
        .unwrap_or(false)
    {
        return Some("Google".to_string());
    }

    None
}

fn extract_title(body: Option<&str>) -> Option<String> {
    let body = body?;
    let lower = body.to_lowercase();

    let start = lower.find("<title>")?;
    let end = lower.find("</title>")?;

    if end <= start + 7 {
        return None;
    }

    let raw = &body[start + 7..end];
    let title = raw.trim();

    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn detects_security_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'"),
        );

        let detected = detect_security_headers(&headers);

        assert!(detected.strict_transport_security);
        assert!(detected.content_security_policy);
        assert!(!detected.x_frame_options);
    }

    #[test]
    fn extracts_title() {
        let body = "<html><head><title>Admin Portal</title></head></html>";
        let title = extract_title(Some(body));

        assert_eq!(title.as_deref(), Some("Admin Portal"));
    }

    #[test]
    fn detects_technologies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("Express"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

        let tech = detect_technologies(
            &headers,
            Some("nginx"),
            Some("text/html"),
            Some("Admin Dashboard"),
        );

        assert!(tech.iter().any(|t| t == "nginx"));
        assert!(tech.iter().any(|t| t == "nodejs-express"));
        assert!(tech.iter().any(|t| t == "html-app"));
        assert!(tech.iter().any(|t| t == "admin-ui"));
    }
}
