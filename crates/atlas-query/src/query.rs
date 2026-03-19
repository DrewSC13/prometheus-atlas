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
    FirstSeen,
    LastSeen,
    Source,
    Target,
    Title,
    Provider,
    Status,
    Scheme,
    TlsEnabled,
    Score,
    ResourceCount,
    NeighborKind,
    EdgeKind,
    ConnectedTo,
    InEpisode,
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
            QueryField::FirstSeen => write!(f, "first_seen"),
            QueryField::LastSeen => write!(f, "last_seen"),
            QueryField::Source => write!(f, "source"),
            QueryField::Target => write!(f, "target"),
            QueryField::Title => write!(f, "title"),
            QueryField::Provider => write!(f, "provider"),
            QueryField::Status => write!(f, "status"),
            QueryField::Scheme => write!(f, "scheme"),
            QueryField::TlsEnabled => write!(f, "tls_enabled"),
            QueryField::Score => write!(f, "score"),
            QueryField::ResourceCount => write!(f, "resource_count"),
            QueryField::NeighborKind => write!(f, "neighbor_kind"),
            QueryField::EdgeKind => write!(f, "edge_kind"),
            QueryField::ConnectedTo => write!(f, "connected_to"),
            QueryField::InEpisode => write!(f, "in_episode"),
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
pub enum QueryExpr {
    Clause(QueryClause),
    And(Vec<QueryExpr>),
    Or(Vec<QueryExpr>),
    Not(Box<QueryExpr>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortField {
    Degree,
    Label,
    Kind,
    FirstSeen,
    LastSeen,
    Score,
    Severity,
    Criticality,
}

impl std::fmt::Display for SortField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortField::Degree => write!(f, "degree"),
            SortField::Label => write!(f, "label"),
            SortField::Kind => write!(f, "kind"),
            SortField::FirstSeen => write!(f, "first_seen"),
            SortField::LastSeen => write!(f, "last_seen"),
            SortField::Score => write!(f, "score"),
            SortField::Severity => write!(f, "severity"),
            SortField::Criticality => write!(f, "criticality"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

impl std::fmt::Display for SortDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortDirection::Asc => write!(f, "asc"),
            SortDirection::Desc => write!(f, "desc"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SortSpec {
    pub field: SortField,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryRequest {
    pub raw: String,
    pub preset: Option<QueryPreset>,
    pub expr: Option<QueryExpr>,
    pub limit: usize,
    pub offset: usize,
    pub sort: Option<SortSpec>,
    pub explain: bool,
}
