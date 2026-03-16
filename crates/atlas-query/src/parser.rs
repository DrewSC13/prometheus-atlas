use anyhow::{anyhow, bail, Result};

use crate::query::{Comparator, QueryClause, QueryField, QueryPreset, QueryRequest};

pub fn parse_query(input: &str, limit: usize) -> Result<QueryRequest> {
    let raw = input.trim().to_string();
    if raw.is_empty() {
        bail!("la query no puede estar vacía");
    }

    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let mut preset = None;
    let mut clauses = Vec::new();

    for token in tokens {
        if let Some(found) = parse_preset(token) {
            if preset.is_none() {
                preset = Some(found);
                continue;
            }
        }

        clauses.push(parse_clause(token)?);
    }

    Ok(QueryRequest {
        raw,
        preset,
        clauses,
        limit,
    })
}

fn parse_preset(token: &str) -> Option<QueryPreset> {
    match token.to_ascii_lowercase().as_str() {
        "services" | "service" => Some(QueryPreset::Services),
        "technologies" | "technology" | "tech" => Some(QueryPreset::Technologies),
        "episodes" | "episode" => Some(QueryPreset::Episodes),
        "high-degree" | "high_degree" | "hubs" | "hub" => Some(QueryPreset::HighDegree),
        "subdomains" | "subdomain" => Some(QueryPreset::Subdomains),
        "targets" | "target" => Some(QueryPreset::Targets),
        "ips" | "ip" => Some(QueryPreset::Ips),
        _ => None,
    }
}

fn parse_clause(token: &str) -> Result<QueryClause> {
    let operators = ["<=", ">=", "~", "=", ">", "<"];

    for operator in operators {
        if let Some(index) = token.find(operator) {
            let field_raw = token[..index].trim();
            let value_raw = token[index + operator.len()..].trim();

            if field_raw.is_empty() || value_raw.is_empty() {
                bail!("cláusula inválida: {token}");
            }

            return Ok(QueryClause {
                field: parse_field(field_raw)?,
                comparator: parse_comparator(operator)?,
                value: value_raw.to_string(),
            });
        }
    }

    Err(anyhow!("token no reconocido en query: {token}"))
}

fn parse_field(input: &str) -> Result<QueryField> {
    match input.to_ascii_lowercase().as_str() {
        "kind" => Ok(QueryField::Kind),
        "label" => Ok(QueryField::Label),
        "technology" | "tech" => Ok(QueryField::Technology),
        "degree" => Ok(QueryField::Degree),
        "episode_kind" | "episode-kind" => Ok(QueryField::EpisodeKind),
        "severity" => Ok(QueryField::Severity),
        "criticality" => Ok(QueryField::Criticality),
        "state" => Ok(QueryField::State),
        other => Err(anyhow!("campo no soportado en query: {other}")),
    }
}

fn parse_comparator(input: &str) -> Result<Comparator> {
    match input {
        "=" => Ok(Comparator::Eq),
        "~" => Ok(Comparator::Contains),
        ">" => Ok(Comparator::Gt),
        ">=" => Ok(Comparator::Gte),
        "<" => Ok(Comparator::Lt),
        "<=" => Ok(Comparator::Lte),
        other => Err(anyhow!("operador no soportado: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{Comparator, QueryField, QueryPreset};

    #[test]
    fn parses_preset_only() {
        let query = parse_query("services", 25).unwrap();
        assert_eq!(query.preset, Some(QueryPreset::Services));
        assert!(query.clauses.is_empty());
    }

    #[test]
    fn parses_mixed_query() {
        let query = parse_query("services technology=cloudflare degree>=3", 25).unwrap();
        assert_eq!(query.preset, Some(QueryPreset::Services));
        assert_eq!(query.clauses.len(), 2);

        assert_eq!(query.clauses[0].field, QueryField::Technology);
        assert_eq!(query.clauses[0].comparator, Comparator::Eq);
        assert_eq!(query.clauses[0].value, "cloudflare");

        assert_eq!(query.clauses[1].field, QueryField::Degree);
        assert_eq!(query.clauses[1].comparator, Comparator::Gte);
        assert_eq!(query.clauses[1].value, "3");
    }

    #[test]
    fn parses_label_contains() {
        let query = parse_query("label~admin", 10).unwrap();
        assert!(query.preset.is_none());
        assert_eq!(query.clauses.len(), 1);
        assert_eq!(query.clauses[0].field, QueryField::Label);
        assert_eq!(query.clauses[0].comparator, Comparator::Contains);
    }
}
