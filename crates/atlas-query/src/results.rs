use atlas_graph::NodeKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::query::SortSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMatch {
    pub node_id: String,
    pub label: String,
    pub kind: NodeKind,
    pub degree: usize,
    pub attributes: BTreeMap<String, String>,
    pub explanations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuerySummary {
    pub total_matches: usize,
    pub returned_matches: usize,
    pub max_degree: usize,
    pub kind_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub target: String,
    pub raw_query: String,
    pub matched_nodes: Vec<QueryMatch>,
    pub summary: QuerySummary,
    pub limit: usize,
    pub offset: usize,
    pub sort: Option<SortSpec>,
    pub explain: bool,
}