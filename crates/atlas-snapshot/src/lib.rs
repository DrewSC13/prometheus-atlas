use anyhow::{Context, Result};
use atlas_core::ScanResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const CURRENT_SNAPSHOT_VERSION: u32 = 2;

fn default_snapshot_version() -> u32 {
    CURRENT_SNAPSHOT_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub snapshot_version: u32,
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub scan: ScanResult,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            snapshot_version: CURRENT_SNAPSHOT_VERSION,
            timestamp: Utc::now(),
            target: String::new(),
            scan: ScanResult::default(),
        }
    }
}

impl Snapshot {
    pub fn new(scan: ScanResult) -> Self {
        Self {
            snapshot_version: CURRENT_SNAPSHOT_VERSION,
            timestamp: Utc::now(),
            target: scan.target.clone(),
            scan,
        }
    }

    pub fn filename(&self) -> String {
        self.timestamp.format("%Y-%m-%dT%H-%M-%SZ").to_string()
    }
}

#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub scanned_files: usize,
    pub migrated_files: usize,
}

pub fn save_snapshot(snapshot: &Snapshot, base_dir: &Path) -> Result<PathBuf> {
    let target_dir = base_dir.join(&snapshot.target);
    fs::create_dir_all(&target_dir).with_context(|| {
        format!(
            "no se pudo crear el directorio de snapshots: {}",
            target_dir.display()
        )
    })?;

    let path = target_dir.join(format!("{}.json", snapshot.filename()));
    let json = serde_json::to_string_pretty(snapshot)?;
    fs::write(&path, json)
        .with_context(|| format!("no se pudo escribir el snapshot en {}", path.display()))?;

    Ok(path)
}

pub fn load_snapshot(path: &Path) -> Result<Snapshot> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("no se pudo leer el snapshot {}", path.display()))?;

    let mut snapshot = serde_json::from_str::<Snapshot>(&data)
        .with_context(|| format!("no se pudo parsear el snapshot {}", path.display()))?;

    if snapshot.snapshot_version == 0 {
        snapshot.snapshot_version = default_snapshot_version();
    }

    Ok(snapshot)
}

pub fn list_snapshots_for_target(base_dir: &Path, target: &str) -> Result<Vec<PathBuf>> {
    let target_dir = base_dir.join(target);

    if !target_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for entry in fs::read_dir(&target_dir)
        .with_context(|| format!("no se pudo leer el directorio {}", target_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            entries.push(path);
        }
    }

    entries.sort();
    Ok(entries)
}

pub fn load_all_snapshots_for_target(base_dir: &Path, target: &str) -> Result<Vec<Snapshot>> {
    let paths = list_snapshots_for_target(base_dir, target)?;
    let mut snapshots = Vec::new();

    for path in paths {
        snapshots.push(load_snapshot(&path)?);
    }

    snapshots.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(snapshots)
}

pub fn snapshot_file_hash(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .with_context(|| format!("no se pudo leer el archivo para hash {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

pub fn migrate_snapshots_in_dir(base_dir: &Path) -> Result<MigrationReport> {
    let mut scanned_files = 0usize;
    let mut migrated_files = 0usize;

    if !base_dir.exists() {
        return Ok(MigrationReport {
            scanned_files,
            migrated_files,
        });
    }

    for entry in WalkDir::new(base_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        scanned_files += 1;
        let snapshot = load_snapshot(path)?;
        let serialized = serde_json::to_string_pretty(&snapshot)?;

        fs::write(path, serialized)
            .with_context(|| format!("no se pudo reescribir {}", path.display()))?;

        migrated_files += 1;
    }

    Ok(MigrationReport {
        scanned_files,
        migrated_files,
    })
}
