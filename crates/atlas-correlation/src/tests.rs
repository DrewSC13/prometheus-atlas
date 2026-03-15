use crate::{build_episodes, build_resource_lineage, build_timeline_episodes, explain_finding};
use atlas_drift::{
    AssetType, AssetTypeSummary, Criticality, DriftFinding, DriftReport, DriftSummary, Environment,
    FindingState, Severity, TimelineExecutiveSummary, TimelineReport, TimelineTransition,
};
use chrono::Utc;

fn sample_finding(
    resource: &str,
    category: &str,
    score: u32,
    severity: Severity,
    tags: Vec<&str>,
) -> DriftFinding {
    DriftFinding {
        finding_id: format!("id-{resource}-{category}"),
        severity,
        score,
        category: category.to_string(),
        title: category.to_string(),
        resource: resource.to_string(),
        asset_type: if resource.starts_with("http://") || resource.starts_with("https://") {
            AssetType::Service
        } else {
            AssetType::Subdomain
        },
        environment: if resource.contains("admin") {
            Environment::Admin
        } else {
            Environment::Unknown
        },
        criticality: if resource.contains("admin") {
            Criticality::Critical
        } else {
            Criticality::Low
        },
        state: FindingState::New,
        tags: tags.into_iter().map(ToString::to_string).collect(),
        description: "test finding".to_string(),
    }
}

fn sample_report() -> DriftReport {
    DriftReport {
        target: "example.com".to_string(),
        older_timestamp: Utc::now(),
        newer_timestamp: Utc::now(),
        findings: vec![
            sample_finding(
                "admin.example.com",
                "new_admin_subdomain",
                95,
                Severity::High,
                vec!["admin", "new-exposure"],
            ),
            sample_finding(
                "http://admin.example.com",
                "new_http_service",
                90,
                Severity::High,
                vec!["admin", "plaintext", "service"],
            ),
        ],
        suppressed_findings: vec![],
        groups: vec![],
        summary: DriftSummary::default(),
    }
}

#[test]
fn builds_episodes_from_report() {
    let report = sample_report();
    let episodes = build_episodes(&report);

    assert!(!episodes.is_empty());
    assert!(episodes.iter().any(|e| e.resource.contains("admin")));
}

#[test]
fn builds_lineage_from_services() {
    let report = sample_report();
    let lineage = build_resource_lineage(&report);

    assert!(!lineage.is_empty());
    assert!(lineage
        .iter()
        .any(|l| l.child == "http://admin.example.com"));
}

#[test]
fn explains_finding_with_reasons() {
    let finding = sample_finding(
        "http://admin.example.com",
        "new_http_service",
        90,
        Severity::High,
        vec!["admin", "plaintext"],
    );

    let explanation = explain_finding(&finding);

    assert_eq!(explanation.finding_id, finding.finding_id);
    assert!(explanation.final_score > 0);
    assert!(!explanation.reasons.is_empty());
}

#[test]
fn builds_timeline_episodes() {
    let report = sample_report();

    let timeline = TimelineReport {
        target: "example.com".to_string(),
        snapshot_count: 2,
        transition_count: 1,
        transitions: vec![TimelineTransition {
            older_timestamp: report.older_timestamp,
            newer_timestamp: report.newer_timestamp,
            report,
        }],
        executive: TimelineExecutiveSummary {
            total_score: 185,
            overall_severity: Severity::High,
            total_findings: 2,
            unique_resources: 2,
            critical_findings: 2,
            recurring_findings: 0,
            persistent_findings: 0,
            asset_types: AssetTypeSummary {
                ips: 0,
                subdomains: 1,
                services: 1,
                unknown: 0,
            },
            top_resources: vec![],
            top_categories: vec![],
        },
    };

    let episodes = build_timeline_episodes(&timeline);
    assert!(!episodes.is_empty());
}
