use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub strict_transport_security: bool,
    pub content_security_policy: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub referrer_policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpService {
    pub host: String,
    pub url: String,
    pub scheme: String,
    pub status: u16,
    pub server: Option<String>,

    pub title: Option<String>,
    pub content_type: Option<String>,
    pub technologies: Vec<String>,
    pub provider: Option<String>,
    pub tls_enabled: bool,
    pub security_headers: SecurityHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub resolved_ips: Vec<String>,
    pub subdomains: Vec<String>,
    pub services: Vec<HttpService>,
}
