use anyhow::Result;
use atlas_drift::analyze_diff;
use atlas_snapshot::{load_snapshot, save_snapshot, Snapshot};
use atlas_store::{AtlasStore, ExportFormat};
use atlas_core::{ScanResult, HttpService, SecurityHeaders};
use chrono::Utc;
use tempfile::tempdir;

fn headers() -> SecurityHeaders {
    SecurityHeaders {
        strict_transport_security: false,
        content_security_policy: false,
        x_frame_options: false,
        x_content_type_options: false,
        referrer_policy: false,
    }
}

fn service(host: &str, url: &str, scheme: &str, status: u16) -> HttpService {
    HttpService {
        host: host.to_string(),
        url: url.to_string(),
        scheme: scheme.to_string(),
        status,
        server: Some("nginx".to_string()),
        title: None,
        content_type: Some("text/html".to_string()),
        technologies: vec!["nginx".to_string()],
        provider: None,
        tls_enabled: scheme == "https",
        security_headers: headers(),
    }
}

#[test]
fn phase10_storage_workflow() -> Result<()> {
    let tmp = tempdir()?;
    let snapshots_dir = tmp.path().join(".snapshots");
    let db_path = tmp.path().join(".atlas").join("atlas.db");

    let store = AtlasStore::open(&db_path)?;
    store.initialize()?;

    let scan_old = ScanResult {
        target: "example.com".to_string(),
        resolved_ips: vec!["1.1.1.1".to_string()],
        subdomains: vec!["www.example.com".to_string()],
        services: vec![service("example.com", "https://example.com", "https", 404)],
    };

    let scan_new = ScanResult {
        target: "example.com".to_string(),
        resolved_ips: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
        subdomains: vec!["www.example.com".to_string(), "admin.example.com".to_string()],
        services: vec![
            service("example.com", "https://example.com", "https", 200),
            service("admin.example.com", "http://admin.example.com", "http", 200),
        ],
    };

    let mut old_snapshot = Snapshot::new(scan_old);
    old_snapshot.timestamp = Utc::now();

    let mut new_snapshot = Snapshot::new(scan_new);
    new_snapshot.timestamp = old_snapshot.timestamp + chrono::Duration::minutes(5);

    let old_path = save_snapshot(&old_snapshot, &snapshots_dir)?;
    let new_path = save_snapshot(&new_snapshot, &snapshots_dir)?;

    store.register_snapshot(&old_path, &old_snapshot)?;
    store.register_snapshot(&new_path, &new_snapshot)?;

    let old_loaded = load_snapshot(&old_path)?;
    let new_loaded = load_snapshot(&new_path)?;
    let diff = atlas_diff::diff_snapshots(&old_loaded, &new_loaded);
    let report = analyze_diff(&diff);

    store.register_drift_report(
        "example.com",
        &old_path,
        &new_path,
        None,
        &report,
    )?;

    let snapshots = store.list_snapshots("example.com")?;
    assert_eq!(snapshots.len(), 2);

    let history = store.list_history("example.com")?;
    assert_eq!(history.len(), 1);

    let findings = store.list_findings("example.com", None, None)?;
    assert!(!findings.is_empty());

    let export_path = tmp.path().join("findings.json");
    store.export_findings(
        "example.com",
        None,
        None,
        ExportFormat::Json,
        &export_path,
    )?;

    assert!(export_path.exists());
    Ok(())
}