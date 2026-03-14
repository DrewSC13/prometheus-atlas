use anyhow::{Context, Result};
use atlas_core::ScanResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub scan: ScanResult,
}

impl Snapshot {
    pub fn new(scan: ScanResult) -> Self {
        Self {
            timestamp: Utc::now(),
            target: scan.target.clone(),
            scan,
        }
    }

    pub fn filename(&self) -> String {
        self.timestamp.format("%Y-%m-%dT%H-%M-%SZ").to_string()
    }
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

    let snapshot = serde_json::from_str::<Snapshot>(&data)
        .with_context(|| format!("no se pudo parsear el snapshot {}", path.display()))?;

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
