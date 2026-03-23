use std::{collections::BTreeMap, path::Path, sync::Arc};

use axum::{
    extract::{Path as AxumPath, State},
    Json,
};
use serde_json::json;

use crate::{
    auth::{scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{
        ApiEnvelope, EnrichedTargetReport, EnrichedTargetReportResponse, OwnerOperationalSummary,
    },
    state::AppState,
};

pub async fn get_report(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    AxumPath(target): AxumPath<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let snapshots = store.list_snapshots_scoped(&scope, &target)?;
    let graph = store
        .load_latest_graph_scoped(&scope, &target)?
        .ok_or_else(|| ApiError::not_found("grafo no encontrado para target"))?;

    let episodes = store.list_episodes_scoped(&scope, &target)?;
    let current_findings =
        store.list_current_findings_operational_scoped(&scope, &target, None, None, None, None)?;
    let owners = store.list_asset_owners_scoped(&scope, None)?;
    let incidents = store.list_incidents_scoped(&scope, None, None, 200)?;

    let snapshot_models = snapshots
        .iter()
        .filter_map(|item| atlas_snapshot::load_snapshot(Path::new(&item.path)).ok())
        .collect::<Vec<_>>();

    let timeline = build_timeline_from_store(&store, &scope, &target)?;
    let episode_collection = if episodes.is_empty() {
        None
    } else {
        Some(atlas_episodes::EpisodeCollection {
            target: target.clone(),
            episode_count: episodes.len(),
            episodes: episodes
                .iter()
                .filter_map(map_stored_episode_to_risk_episode)
                .collect(),
        })
    };

    let summary = atlas_risk::build_summary_report(
        &target,
        &snapshot_models,
        timeline.as_ref(),
        episode_collection.as_ref(),
        &graph,
    );

    let risk = atlas_risk::build_risk_report(
        &target,
        timeline.as_ref(),
        episode_collection.as_ref(),
        &graph,
    );

    let ownership = atlas_risk::build_ownership_intelligence(
        &target,
        &current_findings,
        incidents.len(),
        &owners,
    );

    let incident_operations = atlas_risk::build_incident_operations_intelligence(
        &target,
        &current_findings,
        &episodes,
        &owners,
        Some(&graph),
    );

    let response = json!({
        "target": target,
        "summary": summary,
        "risk": risk,
        "ownership": ownership,
        "incident_operations": incident_operations,
        "current_incidents": incidents
            .into_iter()
            .filter(|item| item.target == target)
            .collect::<Vec<_>>()
    });

    Ok(Json(ApiEnvelope { data: response }))
}

pub async fn get_enriched_report(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    AxumPath(target): AxumPath<String>,
) -> ApiResult<Json<EnrichedTargetReportResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;

    let snapshots = store.list_snapshots_scoped(&scope, &target)?;
    let graph = store
        .load_latest_graph_scoped(&scope, &target)?
        .ok_or_else(|| ApiError::not_found("grafo no encontrado para target"))?;

    let episodes = store.list_episodes_scoped(&scope, &target)?;
    let current_findings =
        store.list_current_findings_operational_scoped(&scope, &target, None, None, None, None)?;
    let owners = store.list_asset_owners_scoped(&scope, None)?;
    let incidents = store
        .list_incidents_scoped(&scope, None, None, 500)?
        .into_iter()
        .filter(|item| item.target == target)
        .collect::<Vec<_>>();

    let snapshot_models = snapshots
        .iter()
        .filter_map(|item| atlas_snapshot::load_snapshot(Path::new(&item.path)).ok())
        .collect::<Vec<_>>();

    let timeline = build_timeline_from_store(&store, &scope, &target)?;
    let episode_collection = if episodes.is_empty() {
        None
    } else {
        Some(atlas_episodes::EpisodeCollection {
            target: target.clone(),
            episode_count: episodes.len(),
            episodes: episodes
                .iter()
                .filter_map(map_stored_episode_to_risk_episode)
                .collect(),
        })
    };

    let summary = atlas_risk::build_summary_report(
        &target,
        &snapshot_models,
        timeline.as_ref(),
        episode_collection.as_ref(),
        &graph,
    );

    let risk = atlas_risk::build_risk_report(
        &target,
        timeline.as_ref(),
        episode_collection.as_ref(),
        &graph,
    );

    let ownership = atlas_risk::build_ownership_intelligence(
        &target,
        &current_findings,
        incidents.len(),
        &owners,
    );

    let incident_operations = atlas_risk::build_incident_operations_intelligence(
        &target,
        &current_findings,
        &episodes,
        &owners,
        Some(&graph),
    );

    let owner_summaries = build_owner_operational_summaries(&current_findings, &incidents, &owners);

    Ok(Json(ApiEnvelope {
        data: EnrichedTargetReport {
            target,
            summary,
            risk,
            ownership,
            incident_operations,
            current_incidents: incidents,
            owner_summaries,
        },
    }))
}

fn build_owner_operational_summaries(
    findings: &[atlas_store::StoredCurrentFinding],
    incidents: &[atlas_store::StoredIncident],
    owners: &[atlas_store::StoredAssetOwner],
) -> Vec<OwnerOperationalSummary> {
    let owner_meta = owners
        .iter()
        .map(|item| (item.owner.clone(), item.team.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut by_owner: BTreeMap<String, OwnerOperationalSummary> = BTreeMap::new();

    for finding in findings {
        let Some(owner) = finding.owner.clone() else {
            continue;
        };

        let entry = by_owner
            .entry(owner.clone())
            .or_insert_with(|| OwnerOperationalSummary {
                owner: owner.clone(),
                team: owner_meta.get(&owner).cloned().unwrap_or(None),
                open_findings: 0,
                open_incidents: 0,
                total_risk_score: 0,
                resources: Vec::new(),
            });

        if !finding.operational_state.eq_ignore_ascii_case("resolved") {
            entry.open_findings += 1;
            entry.total_risk_score = entry.total_risk_score.saturating_add(finding.score);
        }

        if !entry
            .resources
            .iter()
            .any(|value| value == &finding.resource)
        {
            entry.resources.push(finding.resource.clone());
        }
    }

    for incident in incidents {
        let Some(owner) = incident.owner.clone() else {
            continue;
        };

        let entry = by_owner
            .entry(owner.clone())
            .or_insert_with(|| OwnerOperationalSummary {
                owner: owner.clone(),
                team: owner_meta.get(&owner).cloned().unwrap_or(None),
                open_findings: 0,
                open_incidents: 0,
                total_risk_score: 0,
                resources: Vec::new(),
            });

        if !incident.state.eq_ignore_ascii_case("resolved") {
            entry.open_incidents += 1;
            entry.total_risk_score = entry.total_risk_score.saturating_add(incident.score);
        }

        if !entry
            .resources
            .iter()
            .any(|value| value == &incident.resource)
        {
            entry.resources.push(incident.resource.clone());
        }
    }

    let mut items = by_owner.into_values().collect::<Vec<_>>();
    items.sort_by(|a, b| {
        b.total_risk_score
            .cmp(&a.total_risk_score)
            .then_with(|| b.open_incidents.cmp(&a.open_incidents))
            .then_with(|| b.open_findings.cmp(&a.open_findings))
            .then_with(|| a.owner.cmp(&b.owner))
    });
    items
}

fn build_timeline_from_store(
    store: &atlas_store::AtlasStore,
    scope: &atlas_store::StorageScope,
    target: &str,
) -> Result<Option<atlas_drift::TimelineReport>, ApiError> {
    let snapshots = store.list_snapshots_scoped(scope, target)?;
    if snapshots.len() < 2 {
        return Ok(None);
    }

    let snapshot_models = snapshots
        .iter()
        .filter_map(|item| atlas_snapshot::load_snapshot(Path::new(&item.path)).ok())
        .collect::<Vec<_>>();

    if snapshot_models.len() < 2 {
        return Ok(None);
    }

    Ok(Some(
        atlas_drift::build_timeline_report(target, &snapshot_models, None)
            .map_err(|err| ApiError::internal(err.to_string()))?,
    ))
}

fn map_stored_episode_to_risk_episode(
    item: &atlas_store::StoredEpisode,
) -> Option<atlas_episodes::RiskEpisode> {
    let resources = serde_json::from_str::<Vec<String>>(&item.resources_json).ok()?;
    let cluster_ids = serde_json::from_str::<Vec<String>>(&item.cluster_ids_json).ok()?;
    let explanation = serde_json::from_str::<Vec<String>>(&item.explanation_json).ok()?;

    Some(atlas_episodes::RiskEpisode {
        episode_id: item.episode_id.clone(),
        target: item.target.clone(),
        title: item.title.clone(),
        kind: CorrelationKindExt::from_str(&item.kind).ok()?,
        severity: SeverityExt::from_str(&item.severity).ok()?,
        criticality: CriticalityExt::from_str(&item.criticality).ok()?,
        score: item.score,
        state: EpisodeStateExt::from_str(&item.state).ok()?,
        resource_count: item.resource_count,
        resources,
        cluster_ids,
        started_at: chrono::DateTime::parse_from_rfc3339(&item.started_at)
            .ok()?
            .with_timezone(&chrono::Utc),
        ended_at: chrono::DateTime::parse_from_rfc3339(&item.ended_at)
            .ok()?
            .with_timezone(&chrono::Utc),
        summary: item.summary.clone(),
        explanation,
    })
}

trait SeverityExt: Sized {
    fn from_str(value: &str) -> Result<Self, ()>;
}

impl SeverityExt for atlas_drift::Severity {
    fn from_str(value: &str) -> Result<Self, ()> {
        match value.to_ascii_uppercase().as_str() {
            "INFO" => Ok(Self::Info),
            "LOW" => Ok(Self::Low),
            "MEDIUM" => Ok(Self::Medium),
            "HIGH" => Ok(Self::High),
            _ => Err(()),
        }
    }
}

trait CriticalityExt: Sized {
    fn from_str(value: &str) -> Result<Self, ()>;
}

impl CriticalityExt for atlas_drift::Criticality {
    fn from_str(value: &str) -> Result<Self, ()> {
        match value.to_ascii_uppercase().as_str() {
            "LOW" => Ok(Self::Low),
            "MEDIUM" => Ok(Self::Medium),
            "HIGH" => Ok(Self::High),
            "CRITICAL" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

trait EpisodeStateExt: Sized {
    fn from_str(value: &str) -> Result<Self, ()>;
}

impl EpisodeStateExt for atlas_episodes::EpisodeState {
    fn from_str(value: &str) -> Result<Self, ()> {
        match value.to_ascii_lowercase().as_str() {
            "new" => Ok(Self::New),
            "open" => Ok(Self::New),
            "active" => Ok(Self::New),
            "persistent" => Ok(Self::Persistent),
            "resolved" => Ok(Self::Resolved),
            _ => Err(()),
        }
    }
}

trait CorrelationKindExt: Sized {
    fn from_str(value: &str) -> Result<Self, ()>;
}

impl CorrelationKindExt for atlas_correlation::CorrelationKind {
    fn from_str(value: &str) -> Result<Self, ()> {
        match value {
            "AdministrativeExposure" => Ok(Self::AdministrativeExposure),
            "ServiceExpansion" => Ok(Self::ServiceExpansion),
            "InfrastructureShift" => Ok(Self::InfrastructureShift),
            "RiskyDeployment" => Ok(Self::RiskyDeployment),
            "NonProductionLeak" => Ok(Self::NonProductionLeak),
            "RecurringSurfaceChange" => Ok(Self::RecurringSurfaceChange),
            "UnknownComposite" => Ok(Self::UnknownComposite),
            _ => Err(()),
        }
    }
}
