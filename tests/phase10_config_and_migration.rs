use anyhow::Result;
use atlas_config::AppConfig;
use atlas_snapshot::{load_snapshot, migrate_snapshots_in_dir, CURRENT_SNAPSHOT_VERSION};
use std::fs;
use tempfile::tempdir;

#[test]
fn phase10_config_and_migration() -> Result<()> {
    let tmp = tempdir()?;

    let cfg_path = tmp.path().join("atlas.toml");
    AppConfig::write_default_to_path(&cfg_path)?;
    let cfg = AppConfig::load_from_path(&cfg_path)?;
    cfg.validate()?;

    let snapshots_dir = tmp.path().join(".snapshots").join("example.com");
    fs::create_dir_all(&snapshots_dir)?;

    let old_snapshot_path = snapshots_dir.join("legacy.json");
    let legacy = r#"
{
  "timestamp": "2026-03-14T20:00:00Z",
  "target": "example.com",
  "scan": {
    "target": "example.com",
    "resolved_ips": ["1.1.1.1"],
    "subdomains": ["www.example.com"],
    "services": [
      {
        "host": "example.com",
        "url": "https://example.com",
        "scheme": "https",
        "status": 200,
        "server": "nginx"
      }
    ]
  }
}
"#;

    fs::write(&old_snapshot_path, legacy)?;
    let report = migrate_snapshots_in_dir(tmp.path().join(".snapshots").as_path())?;

    assert_eq!(report.scanned_files, 1);
    assert_eq!(report.migrated_files, 1);

    let migrated = load_snapshot(&old_snapshot_path)?;
    assert_eq!(migrated.snapshot_version, CURRENT_SNAPSHOT_VERSION);
    assert_eq!(migrated.scan.services.len(), 1);
    assert!(migrated.scan.services[0].technologies.is_empty());

    Ok(())
}