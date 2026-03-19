use atlas_graph::{EdgeKind, ExposureGraph, GraphEdge, GraphNode, NodeKind};
use atlas_query::{execute_query, parse_query};
use chrono::{Duration, Utc};
use std::collections::BTreeMap;

fn sample_graph() -> ExposureGraph {
    let now = Utc::now();
    let earlier = now - Duration::days(7);

    let mut graph = ExposureGraph::empty("example.com");

    let svc_admin = "svc_admin".to_string();
    let svc_api = "svc_api".to_string();
    let tech_cf = "tech_cf".to_string();
    let tech_nginx = "tech_nginx".to_string();
    let episode = "ep1".to_string();
    let sub_admin = "sub_admin".to_string();

    graph.nodes.push(GraphNode {
        node_id: svc_admin.clone(),
        kind: NodeKind::Service,
        label: "https://admin.example.com".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::from([
            ("severity".to_string(), "HIGH".to_string()),
            ("state".to_string(), "Persistent".to_string()),
            ("provider".to_string(), "cloudflare".to_string()),
            ("title".to_string(), "Admin Panel".to_string()),
            ("status".to_string(), "200".to_string()),
            ("scheme".to_string(), "https".to_string()),
            ("tls_enabled".to_string(), "true".to_string()),
        ]),
    });

    graph.nodes.push(GraphNode {
        node_id: svc_api.clone(),
        kind: NodeKind::Service,
        label: "http://api.example.com".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now - Duration::days(2)),
        attributes: BTreeMap::from([
            ("severity".to_string(), "MEDIUM".to_string()),
            ("state".to_string(), "New".to_string()),
            ("provider".to_string(), "internal".to_string()),
            ("title".to_string(), "API".to_string()),
            ("status".to_string(), "200".to_string()),
            ("scheme".to_string(), "http".to_string()),
            ("tls_enabled".to_string(), "false".to_string()),
        ]),
    });

    graph.nodes.push(GraphNode {
        node_id: tech_cf.clone(),
        kind: NodeKind::Technology,
        label: "cloudflare".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.nodes.push(GraphNode {
        node_id: tech_nginx.clone(),
        kind: NodeKind::Technology,
        label: "nginx".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.nodes.push(GraphNode {
        node_id: episode.clone(),
        kind: NodeKind::Episode,
        label: "Unsafe deployment".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::from([
            ("kind".to_string(), "InfrastructureShift".to_string()),
            ("criticality".to_string(), "CRITICAL".to_string()),
            ("severity".to_string(), "HIGH".to_string()),
            ("score".to_string(), "180".to_string()),
            ("resource_count".to_string(), "3".to_string()),
            ("state".to_string(), "New".to_string()),
        ]),
    });

    graph.nodes.push(GraphNode {
        node_id: sub_admin.clone(),
        kind: NodeKind::Subdomain,
        label: "admin.example.com".to_string(),
        target: "example.com".to_string(),
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.edges.push(GraphEdge {
        edge_id: "e1".to_string(),
        from: svc_admin.clone(),
        to: tech_cf,
        kind: EdgeKind::FingerprintsAs,
        target: "example.com".to_string(),
        weight: 1,
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.edges.push(GraphEdge {
        edge_id: "e2".to_string(),
        from: svc_api.clone(),
        to: tech_nginx,
        kind: EdgeKind::FingerprintsAs,
        target: "example.com".to_string(),
        weight: 1,
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.edges.push(GraphEdge {
        edge_id: "e3".to_string(),
        from: svc_admin.clone(),
        to: episode.clone(),
        kind: EdgeKind::ParticipatesIn,
        target: "example.com".to_string(),
        weight: 1,
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.edges.push(GraphEdge {
        edge_id: "e4".to_string(),
        from: sub_admin,
        to: svc_admin,
        kind: EdgeKind::Exposes,
        target: "example.com".to_string(),
        weight: 1,
        first_seen: Some(earlier),
        last_seen: Some(now),
        attributes: BTreeMap::new(),
    });

    graph.recompute_metadata();
    graph
}

#[test]
fn full_phase14_query_dsl_works() {
    let graph = sample_graph();

    let request = parse_query(
        r#"EXPLAIN services (technology=cloudflare OR title~"admin panel") AND in_episode=true ORDER BY degree DESC LIMIT 10 OFFSET 0"#,
        25,
    )
    .unwrap();

    let result = execute_query(&graph, &request).unwrap();

    assert_eq!(result.summary.total_matches, 1);
    assert_eq!(result.summary.returned_matches, 1);
    assert_eq!(result.matched_nodes[0].label, "https://admin.example.com");
    assert!(result.explain);
    assert!(!result.matched_nodes[0].explanations.is_empty());
}

#[test]
fn phase14_episode_numeric_and_rank_filters_work() {
    let graph = sample_graph();

    let request = parse_query(
        r#"episodes criticality>=high AND score>=100 AND resource_count>=2"#,
        25,
    )
    .unwrap();

    let result = execute_query(&graph, &request).unwrap();
    assert_eq!(result.summary.total_matches, 1);
    assert_eq!(result.matched_nodes[0].kind, NodeKind::Episode);
}

#[test]
fn phase14_not_and_sort_work() {
    let graph = sample_graph();

    let request = parse_query(
        r#"services NOT tls_enabled=true ORDER BY label ASC LIMIT 5"#,
        25,
    )
    .unwrap();

    let result = execute_query(&graph, &request).unwrap();
    assert_eq!(result.summary.total_matches, 1);
    assert_eq!(result.matched_nodes[0].label, "http://api.example.com");
}
