use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryPreset {
    Services,
    Technologies,
    Episodes,
    HighDegree,
    Subdomains,
    Targets,
    Ips,
}

impl std::fmt::Display for QueryPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryPreset::Services => write!(f, "services"),
            QueryPreset::Technologies => write!(f, "technologies"),
            QueryPreset::Episodes => write!(f, "episodes"),
            QueryPreset::HighDegree => write!(f, "high-degree"),
            QueryPreset::Subdomains => write!(f, "subdomains"),
            QueryPreset::Targets => write!(f, "targets"),
            QueryPreset::Ips => write!(f, "ips"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Comparator {
    Eq,
    Contains,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl std::fmt::Display for Comparator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Comparator::Eq => write!(f, "="),
            Comparator::Contains => write!(f, "~"),
            Comparator::Gt => write!(f, ">"),
            Comparator::Gte => write!(f, ">="),
            Comparator::Lt => write!(f, "<"),
            Comparator::Lte => write!(f, "<="),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryField {
    Kind,
    Label,
    Technology,
    Degree,
    EpisodeKind,
    Severity,
    Criticality,
    State,
}

impl std::fmt::Display for QueryField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryField::Kind => write!(f, "kind"),
            QueryField::Label => write!(f, "label"),
            QueryField::Technology => write!(f, "technology"),
            QueryField::Degree => write!(f, "degree"),
            QueryField::EpisodeKind => write!(f, "episode_kind"),
            QueryField::Severity => write!(f, "severity"),
            QueryField::Criticality => write!(f, "criticality"),
            QueryField::State => write!(f, "state"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryClause {
    pub field: QueryField,
    pub comparator: Comparator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryRequest {
    pub raw: String,
    pub preset: Option<QueryPreset>,
    pub clauses: Vec<QueryClause>,
    pub limit: usize,
}
