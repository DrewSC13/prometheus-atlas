use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpService {
    pub host: String,
    pub url: String,
    pub scheme: String,
    pub status: u16,
    pub server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub resolved_ips: Vec<String>,
    pub subdomains: Vec<String>,
    pub services: Vec<HttpService>,
}
