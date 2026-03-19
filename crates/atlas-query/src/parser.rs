use anyhow::{anyhow, bail, Result};

use crate::query::{
    Comparator, QueryClause, QueryExpr, QueryField, QueryMode, QueryPreset, QueryRequest,
    SortDirection, SortField, SortSpec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    String(String),
    LParen,
    RParen,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn peek_word_ci(&self, value: &str) -> bool {
        matches!(
            self.peek(),
            Some(Token::Word(word)) if word.eq_ignore_ascii_case(value)
        )
    }

    fn next_word_value(&mut self) -> Result<String> {
        match self.next() {
            Some(Token::Word(word)) => Ok(word),
            Some(Token::String(value)) => Ok(value),
            Some(Token::LParen) => bail!("se esperaba palabra y se encontró '('"),
            Some(Token::RParen) => bail!("se esperaba palabra y se encontró ')'"),
            None => bail!("fin inesperado de query"),
        }
    }

    fn next_stringish(&mut self) -> Result<String> {
        match self.next() {
            Some(Token::Word(word)) => Ok(word),
            Some(Token::String(value)) => Ok(value),
            Some(Token::LParen) => bail!("se esperaba valor y se encontró '('"),
            Some(Token::RParen) => bail!("se esperaba valor y se encontró ')'"),
            None => bail!("fin inesperado de query"),
        }
    }

    fn expect_word_ci(&mut self, expected: &str) -> Result<()> {
        let found = self.next_word_value()?;
        if !found.eq_ignore_ascii_case(expected) {
            bail!("se esperaba '{expected}' y se encontró '{found}'");
        }
        Ok(())
    }
}

pub fn parse_query(input: &str, default_limit: usize) -> Result<QueryRequest> {
    let raw = input.trim().to_string();
    if raw.is_empty() {
        bail!("la query no puede estar vacía");
    }

    let tokens = tokenize(&raw)?;
    let mut parser = Parser::new(tokens);

    let mut explain = false;
    if parser.peek_word_ci("EXPLAIN") {
        parser.next();
        explain = true;
    }

    if parser.peek_word_ci("PATH") {
        parser.next();
        let path_from = parser.next_stringish()?;
        let arrow = parser.next_word_value()?;
        if arrow != "->" {
            bail!("PATH requiere sintaxis: PATH <from> -> <to>");
        }
        let path_to = parser.next_stringish()?;

        return Ok(QueryRequest {
            raw,
            mode: QueryMode::Path,
            preset: None,
            expr: None,
            limit: default_limit,
            offset: 0,
            sort: None,
            explain,
            expand_depth: 0,
            neighbors_depth: 0,
            path_from: Some(path_from),
            path_to: Some(path_to),
        });
    }

    let mut mode = QueryMode::Filter;
    if parser.peek_word_ci("NEIGHBORS") {
        parser.next();
        mode = QueryMode::Neighbors;
    }

    let mut preset = None;
    if let Some(Token::Word(word)) = parser.peek() {
        if let Some(found) = parse_preset(word) {
            preset = Some(found);
            parser.next();
        }
    }

    let expr = if parser.is_eof() || is_directive_token(parser.peek()) {
        None
    } else {
        Some(parse_or_expr(&mut parser)?)
    };

    let mut sort = None;
    let mut limit = default_limit;
    let mut offset = 0usize;
    let mut expand_depth = 0usize;
    let mut neighbors_depth = 1usize;

    while !parser.is_eof() {
        if parser.peek_word_ci("ORDER") {
            parser.next();
            parser.expect_word_ci("BY")?;
            let field = parse_sort_field(&parser.next_word_value()?)?;
            let direction = if parser.peek_word_ci("ASC") {
                parser.next();
                SortDirection::Asc
            } else if parser.peek_word_ci("DESC") {
                parser.next();
                SortDirection::Desc
            } else {
                SortDirection::Desc
            };
            sort = Some(SortSpec { field, direction });
            continue;
        }

        if parser.peek_word_ci("LIMIT") {
            parser.next();
            let value = parser.next_word_value()?;
            limit = value
                .parse::<usize>()
                .map_err(|_| anyhow!("LIMIT debe ser numérico"))?;
            continue;
        }

        if parser.peek_word_ci("OFFSET") {
            parser.next();
            let value = parser.next_word_value()?;
            offset = value
                .parse::<usize>()
                .map_err(|_| anyhow!("OFFSET debe ser numérico"))?;
            continue;
        }

        if parser.peek_word_ci("EXPAND") {
            parser.next();
            let value = parser.next_word_value()?;
            expand_depth = value
                .parse::<usize>()
                .map_err(|_| anyhow!("EXPAND debe ser numérico"))?;
            continue;
        }

        if parser.peek_word_ci("DEPTH") {
            parser.next();
            let value = parser.next_word_value()?;
            neighbors_depth = value
                .parse::<usize>()
                .map_err(|_| anyhow!("DEPTH debe ser numérico"))?;
            continue;
        }

        if parser.peek_word_ci("EXPLAIN") {
            parser.next();
            explain = true;
            continue;
        }

        bail!(
            "token no esperado al final de la query: {}",
            display_token(parser.peek())
        );
    }

    Ok(QueryRequest {
        raw,
        mode,
        preset,
        expr,
        limit,
        offset,
        sort,
        explain,
        expand_depth,
        neighbors_depth,
        path_from: None,
        path_to: None,
    })
}

fn parse_or_expr(parser: &mut Parser) -> Result<QueryExpr> {
    let mut items = vec![parse_and_expr(parser)?];

    while parser.peek_word_ci("OR") {
        parser.next();
        items.push(parse_and_expr(parser)?);
    }

    if items.len() == 1 {
        Ok(items.remove(0))
    } else {
        Ok(QueryExpr::Or(items))
    }
}

fn parse_and_expr(parser: &mut Parser) -> Result<QueryExpr> {
    let mut items = vec![parse_not_expr(parser)?];

    loop {
        if parser.peek_word_ci("AND") {
            parser.next();
            items.push(parse_not_expr(parser)?);
            continue;
        }

        if should_end_expression(parser.peek()) || parser.peek_word_ci("OR") {
            break;
        }

        if parser.peek().is_some() {
            items.push(parse_not_expr(parser)?);
            continue;
        }

        break;
    }

    if items.len() == 1 {
        Ok(items.remove(0))
    } else {
        Ok(QueryExpr::And(items))
    }
}

fn parse_not_expr(parser: &mut Parser) -> Result<QueryExpr> {
    if parser.peek_word_ci("NOT") {
        parser.next();
        return Ok(QueryExpr::Not(Box::new(parse_not_expr(parser)?)));
    }

    parse_primary_expr(parser)
}

fn parse_primary_expr(parser: &mut Parser) -> Result<QueryExpr> {
    match parser.peek() {
        Some(Token::LParen) => {
            parser.next();
            let expr = parse_or_expr(parser)?;
            match parser.next() {
                Some(Token::RParen) => Ok(expr),
                other => Err(anyhow!(
                    "se esperaba ')' y se encontró {}",
                    display_owned_token(other)
                )),
            }
        }
        Some(Token::Word(_)) | Some(Token::String(_)) => {
            Ok(QueryExpr::Clause(parse_clause(parser)?))
        }
        Some(Token::RParen) => bail!("paréntesis de cierre inesperado"),
        None => bail!("fin inesperado de query"),
    }
}

fn parse_clause(parser: &mut Parser) -> Result<QueryClause> {
    let first = parser.next_stringish()?;

    if let Some((field_raw, operator_raw, value_raw)) = split_inline_clause(&first) {
        return Ok(QueryClause {
            field: parse_field(field_raw)?,
            comparator: parse_comparator(operator_raw)?,
            value: normalize_boolean_literal(value_raw),
        });
    }

    if let Some((field_raw, operator_raw)) = split_inline_clause_without_rhs(&first) {
        let value_raw = parser.next_stringish()?;
        return Ok(QueryClause {
            field: parse_field(field_raw)?,
            comparator: parse_comparator(operator_raw)?,
            value: normalize_boolean_literal(&value_raw),
        });
    }

    let field = parse_field(&first)?;
    let operator_raw = parser.next_word_value()?;
    let value_raw = parser.next_stringish()?;

    Ok(QueryClause {
        field,
        comparator: parse_comparator(&operator_raw)?,
        value: normalize_boolean_literal(&value_raw),
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

fn parse_field(input: &str) -> Result<QueryField> {
    match input.to_ascii_lowercase().as_str() {
        "kind" => Ok(QueryField::Kind),
        "label" => Ok(QueryField::Label),
        "technology" | "tech" | "has_technology" | "has-technology" => Ok(QueryField::Technology),
        "degree" => Ok(QueryField::Degree),
        "episode_kind" | "episode-kind" => Ok(QueryField::EpisodeKind),
        "severity" => Ok(QueryField::Severity),
        "criticality" => Ok(QueryField::Criticality),
        "state" => Ok(QueryField::State),
        "first_seen" | "first-seen" => Ok(QueryField::FirstSeen),
        "last_seen" | "last-seen" => Ok(QueryField::LastSeen),
        "source" => Ok(QueryField::Source),
        "target" => Ok(QueryField::Target),
        "title" => Ok(QueryField::Title),
        "provider" => Ok(QueryField::Provider),
        "status" => Ok(QueryField::Status),
        "scheme" => Ok(QueryField::Scheme),
        "tls_enabled" | "tls-enabled" | "tls" => Ok(QueryField::TlsEnabled),
        "score" => Ok(QueryField::Score),
        "resource_count" | "resource-count" => Ok(QueryField::ResourceCount),
        "neighbor_kind" | "neighbor-kind" => Ok(QueryField::NeighborKind),
        "edge_kind" | "edge-kind" => Ok(QueryField::EdgeKind),
        "connected_to" | "connected-to" | "neighbor" => Ok(QueryField::ConnectedTo),
        "in_episode" | "in-episode" => Ok(QueryField::InEpisode),
        other => Err(anyhow!("campo no soportado en query: {other}")),
    }
}

fn parse_sort_field(input: &str) -> Result<SortField> {
    match input.to_ascii_lowercase().as_str() {
        "degree" => Ok(SortField::Degree),
        "label" => Ok(SortField::Label),
        "kind" => Ok(SortField::Kind),
        "first_seen" | "first-seen" => Ok(SortField::FirstSeen),
        "last_seen" | "last-seen" => Ok(SortField::LastSeen),
        "score" => Ok(SortField::Score),
        "severity" => Ok(SortField::Severity),
        "criticality" => Ok(SortField::Criticality),
        other => Err(anyhow!("campo no soportado para ORDER BY: {other}")),
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

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let ch = chars[i];

        if ch.is_whitespace() {
            i += 1;
            continue;
        }

        if ch == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }

        if ch == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }

        if ch == '"' || ch == '\'' {
            let quote = ch;
            i += 1;
            let mut value = String::new();
            let mut closed = false;

            while i < chars.len() {
                let current = chars[i];
                if current == '\\' && i + 1 < chars.len() {
                    value.push(chars[i + 1]);
                    i += 2;
                    continue;
                }

                if current == quote {
                    i += 1;
                    closed = true;
                    break;
                }

                value.push(current);
                i += 1;
            }

            if !closed {
                bail!("string sin cierre");
            }

            tokens.push(Token::String(value));
            continue;
        }

        let start = i;
        while i < chars.len() {
            let current = chars[i];
            if current.is_whitespace()
                || current == '('
                || current == ')'
                || current == '"'
                || current == '\''
            {
                break;
            }
            i += 1;
        }

        let value: String = chars[start..i].iter().collect();
        tokens.push(Token::Word(value));
    }

    Ok(tokens)
}

fn split_inline_clause(input: &str) -> Option<(&str, &str, &str)> {
    for operator in ["<=", ">=", "~", "=", ">", "<"] {
        if let Some(index) = input.find(operator) {
            let field = input[..index].trim();
            let rhs = input[index + operator.len()..].trim();
            if !field.is_empty() && !rhs.is_empty() {
                return Some((field, operator, rhs));
            }
        }
    }
    None
}

fn split_inline_clause_without_rhs(input: &str) -> Option<(&str, &str)> {
    for operator in ["<=", ">=", "~", "=", ">", "<"] {
        if let Some(index) = input.find(operator) {
            let field = input[..index].trim();
            let rhs = input[index + operator.len()..].trim();
            if !field.is_empty() && rhs.is_empty() {
                return Some((field, operator));
            }
        }
    }
    None
}

fn normalize_boolean_literal(input: &str) -> String {
    match input.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => "true".to_string(),
        "false" | "no" | "0" => "false".to_string(),
        _ => input.to_string(),
    }
}

fn is_directive_token(token: Option<&Token>) -> bool {
    matches!(
        token,
        Some(Token::Word(word))
            if word.eq_ignore_ascii_case("ORDER")
                || word.eq_ignore_ascii_case("LIMIT")
                || word.eq_ignore_ascii_case("OFFSET")
                || word.eq_ignore_ascii_case("EXPLAIN")
                || word.eq_ignore_ascii_case("EXPAND")
                || word.eq_ignore_ascii_case("DEPTH")
    )
}

fn should_end_expression(token: Option<&Token>) -> bool {
    matches!(token, None | Some(Token::RParen)) || is_directive_token(token)
}

fn display_token(token: Option<&Token>) -> String {
    match token {
        Some(Token::Word(word)) => word.clone(),
        Some(Token::String(value)) => format!("\"{value}\""),
        Some(Token::LParen) => "(".to_string(),
        Some(Token::RParen) => ")".to_string(),
        None => "<eof>".to_string(),
    }
}

fn display_owned_token(token: Option<Token>) -> String {
    match token {
        Some(Token::Word(word)) => word,
        Some(Token::String(value)) => format!("\"{value}\""),
        Some(Token::LParen) => "(".to_string(),
        Some(Token::RParen) => ")".to_string(),
        None => "<eof>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{
        Comparator, QueryExpr, QueryField, QueryMode, QueryPreset, SortDirection, SortField,
    };

    #[test]
    fn parses_preset_only() {
        let query = parse_query("services", 25).unwrap();
        assert_eq!(query.mode, QueryMode::Filter);
        assert_eq!(query.preset, Some(QueryPreset::Services));
        assert!(query.expr.is_none());
        assert_eq!(query.limit, 25);
        assert_eq!(query.offset, 0);
        assert!(!query.explain);
    }

    #[test]
    fn parses_boolean_expression_with_parentheses() {
        let query = parse_query(
            r#"services technology=cloudflare AND (severity=high OR criticality=critical)"#,
            25,
        )
        .unwrap();

        assert_eq!(query.preset, Some(QueryPreset::Services));
        match query.expr {
            Some(QueryExpr::And(items)) => assert_eq!(items.len(), 2),
            other => panic!("expr inesperada: {other:?}"),
        }
    }

    #[test]
    fn parses_quoted_values() {
        let query = parse_query(r#"label~"admin panel""#, 10).unwrap();

        match query.expr {
            Some(QueryExpr::Clause(clause)) => {
                assert_eq!(clause.field, QueryField::Label);
                assert_eq!(clause.comparator, Comparator::Contains);
                assert_eq!(clause.value, "admin panel");
            }
            other => panic!("expr inesperada: {other:?}"),
        }
    }

    #[test]
    fn parses_order_limit_offset_explain() {
        let query = parse_query(
            r#"EXPLAIN services technology=cloudflare ORDER BY degree DESC LIMIT 5 OFFSET 2"#,
            25,
        )
        .unwrap();

        assert!(query.explain);
        assert_eq!(query.limit, 5);
        assert_eq!(query.offset, 2);

        let sort = query.sort.expect("sort requerida");
        assert_eq!(sort.field, SortField::Degree);
        assert_eq!(sort.direction, SortDirection::Desc);
    }

    #[test]
    fn parses_not_expression() {
        let query = parse_query(r#"services NOT state=resolved"#, 20).unwrap();

        match query.expr {
            Some(QueryExpr::Not(inner)) => {
                assert!(matches!(*inner, QueryExpr::Clause(_)));
            }
            other => panic!("expr inesperada: {other:?}"),
        }
    }

    #[test]
    fn parses_expand_directive() {
        let query = parse_query(r#"services technology=cloudflare EXPAND 2"#, 20).unwrap();
        assert_eq!(query.expand_depth, 2);
        assert_eq!(query.mode, QueryMode::Filter);
    }

    #[test]
    fn parses_neighbors_mode() {
        let query = parse_query(r#"NEIGHBORS label=example.com DEPTH 3"#, 20).unwrap();
        assert_eq!(query.mode, QueryMode::Neighbors);
        assert_eq!(query.neighbors_depth, 3);
    }

    #[test]
    fn parses_path_mode() {
        let query = parse_query(r#"PATH example.com -> cloudflare"#, 20).unwrap();
        assert_eq!(query.mode, QueryMode::Path);
        assert_eq!(query.path_from.as_deref(), Some("example.com"));
        assert_eq!(query.path_to.as_deref(), Some("cloudflare"));
    }
}
