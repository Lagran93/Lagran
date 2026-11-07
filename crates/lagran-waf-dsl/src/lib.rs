//! Safe, dependency-free WAF custom-rule DSL.
//!
//! Grammar (case-insensitive keywords):
//!
//! ```text
//! expr    := or
//! or      := and ("OR" and)*
//! and     := unary ("AND" unary)*
//! unary   := "NOT" unary | "(" expr ")" | condition
//! condition := field operator "string"
//! field   := path | query | user_agent | ua | referer | method | ip | header:name
//! op      := contains | equals | eq | prefix | suffix
//! ```
//!
//! No regex, no code execution, bounded length/depth/nodes.

use std::fmt;

pub const MAX_EXPR_LEN: usize = 2048;
pub const MAX_DEPTH: usize = 16;
pub const MAX_NODES: usize = 64;
pub const MAX_VALUE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Path,
    Query,
    UserAgent,
    Referer,
    Method,
    Ip,
    Header(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Contains,
    Equals,
    Prefix,
    Suffix,
    /// CIDR membership. Only valid for the `ip` field.
    In,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Condition { field: Field, op: Op, value: String },
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DslError {
    pub message: String,
    pub position: usize,
}

impl DslError {
    fn new(message: impl Into<String>, position: usize) -> Self {
        Self { message: message.into(), position }
    }
}

impl fmt::Display for DslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for DslError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    End,
}

struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, bytes: input.as_bytes(), pos: 0 }
    }

    fn tokens(mut self) -> Result<Vec<(Token, usize)>, DslError> {
        let mut out = Vec::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_whitespace() {
                self.pos += 1;
                continue;
            }
            let start = self.pos;
            match b {
                b'(' => {
                    self.pos += 1;
                    out.push((Token::LParen, start));
                }
                b')' => {
                    self.pos += 1;
                    out.push((Token::RParen, start));
                }
                b'"' | b'\'' => {
                    let quote = b;
                    self.pos += 1;
                    let mut value = String::new();
                    let mut closed = false;
                    while self.pos < self.bytes.len() {
                        let c = self.bytes[self.pos];
                        if c == quote {
                            self.pos += 1;
                            closed = true;
                            break;
                        }
                        if c == b'\\' {
                            self.pos += 1;
                            if self.pos >= self.bytes.len() {
                                break;
                            }
                            let escaped = self.bytes[self.pos];
                            value.push(match escaped {
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                other => other as char,
                            });
                            self.pos += 1;
                            continue;
                        }
                        if c.is_ascii_control() {
                            return Err(DslError::new(
                                "control character is not allowed in a string",
                                self.pos,
                            ));
                        }
                        value.push(c as char);
                        self.pos += 1;
                    }
                    if !closed {
                        return Err(DslError::new("unterminated string", start));
                    }
                    if value.len() > MAX_VALUE_LEN {
                        return Err(DslError::new("string is too long", start));
                    }
                    out.push((Token::Str(value), start));
                }
                c if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b':' | b'.') => {
                    while self.pos < self.bytes.len() {
                        let c = self.bytes[self.pos];
                        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b':' | b'.') {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let text = &self.input[start..self.pos];
                    out.push((Token::Ident(text.to_string()), start));
                }
                other => {
                    return Err(DslError::new(
                        format!("unexpected character {:?}", other as char),
                        start,
                    ));
                }
            }
        }
        out.push((Token::End, self.input.len()));
        Ok(out)
    }
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
    depth: usize,
    nodes: usize,
}

impl Parser {
    fn new(tokens: Vec<(Token, usize)>) -> Self {
        Self { tokens, pos: 0, depth: 0, nodes: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos].0
    }

    fn position(&self) -> usize {
        self.tokens[self.pos].1
    }

    fn bump(&mut self) -> Token {
        let token = self.tokens[self.pos].0.clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        token
    }

    fn keyword(&self, expected: &str) -> bool {
        matches!(self.peek(), Token::Ident(s) if s.eq_ignore_ascii_case(expected))
    }

    fn node(&mut self, position: usize) -> Result<(), DslError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(DslError::new("expression has too many nodes", position));
        }
        Ok(())
    }

    fn parse_expr(&mut self) -> Result<Expr, DslError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(DslError::new("expression is nested too deeply", self.position()));
        }
        let result = self.parse_or();
        self.depth -= 1;
        result
    }

    fn parse_or(&mut self) -> Result<Expr, DslError> {
        let position = self.position();
        let mut parts = vec![self.parse_and()?];
        while self.keyword("OR") {
            self.bump();
            parts.push(self.parse_and()?);
        }
        if parts.len() == 1 {
            Ok(parts.remove(0))
        } else {
            self.node(position)?;
            Ok(Expr::Or(parts))
        }
    }

    fn parse_and(&mut self) -> Result<Expr, DslError> {
        let position = self.position();
        let mut parts = vec![self.parse_unary()?];
        while self.keyword("AND") {
            self.bump();
            parts.push(self.parse_unary()?);
        }
        if parts.len() == 1 {
            Ok(parts.remove(0))
        } else {
            self.node(position)?;
            Ok(Expr::And(parts))
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, DslError> {
        let position = self.position();
        if self.keyword("NOT") {
            self.bump();
            self.node(position)?;
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        if matches!(self.peek(), Token::LParen) {
            self.bump();
            let expr = self.parse_expr()?;
            match self.bump() {
                Token::RParen => Ok(expr),
                _ => Err(DslError::new("missing closing parenthesis", self.position())),
            }
        } else {
            self.parse_condition()
        }
    }

    fn parse_condition(&mut self) -> Result<Expr, DslError> {
        let position = self.position();
        let field = match self.bump() {
            Token::Ident(name) => parse_field(&name)
                .ok_or_else(|| DslError::new(format!("unknown field {name:?}"), position))?,
            _ => return Err(DslError::new("expected a field name", position)),
        };
        let op_position = self.position();
        let op = match self.bump() {
            Token::Ident(name) => parse_op(&name)
                .ok_or_else(|| DslError::new(format!("unknown operator {name:?}"), op_position))?,
            _ => return Err(DslError::new("expected an operator", op_position)),
        };
        let value_position = self.position();
        let value = match self.bump() {
            Token::Str(value) => value.to_ascii_lowercase(),
            _ => return Err(DslError::new("expected a quoted value", value_position)),
        };
        if op == Op::In {
            if field != Field::Ip {
                return Err(DslError::new(
                    "operator \"in\" is only valid for the ip field",
                    op_position,
                ));
            }
            if !is_cidr_list(&value) {
                return Err(DslError::new(
                    "ip in requires one or more valid CIDR / IP values",
                    value_position,
                ));
            }
        }
        self.node(position)?;
        Ok(Expr::Condition { field, op, value })
    }
}

fn parse_field(input: &str) -> Option<Field> {
    let lower = input.trim().to_ascii_lowercase();
    if let Some(name) = lower.strip_prefix("header:") {
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        return Some(Field::Header(name.to_string()));
    }
    match lower.as_str() {
        "path" | "uri" => Some(Field::Path),
        "query" | "args" => Some(Field::Query),
        "user_agent" | "user-agent" | "ua" => Some(Field::UserAgent),
        "referer" | "referrer" => Some(Field::Referer),
        "method" => Some(Field::Method),
        "ip" => Some(Field::Ip),
        _ => None,
    }
}

fn parse_op(input: &str) -> Option<Op> {
    match input.trim().to_ascii_lowercase().as_str() {
        "contains" => Some(Op::Contains),
        "equals" | "eq" => Some(Op::Equals),
        "prefix" | "starts_with" => Some(Op::Prefix),
        "suffix" | "ends_with" => Some(Op::Suffix),
        "in" => Some(Op::In),
        _ => None,
    }
}

/// One CIDR or bare IP, separated by commas. Used by `ip in`.
pub fn is_cidr_list(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    value.split(',').all(|part| {
        let part = part.trim();
        if part.is_empty() {
            return false;
        }
        let (addr, prefix) = match part.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (part, None),
        };
        let Ok(addr) = addr.parse::<std::net::IpAddr>() else {
            return false;
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        match prefix {
            Some(prefix) => prefix
                .trim()
                .parse::<u8>()
                .map(|p| p <= max)
                .unwrap_or(false),
            None => true,
        }
    })
}

pub fn parse(input: &str) -> Result<Expr, DslError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DslError::new("expression is empty", 0));
    }
    if input.len() > MAX_EXPR_LEN {
        return Err(DslError::new("expression is too long", 0));
    }
    let tokens = Lexer::new(input).tokens()?;
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    if !matches!(parser.peek(), Token::End) {
        return Err(DslError::new("unexpected token after expression", parser.position()));
    }
    Ok(expr)
}

pub fn validate(input: &str) -> Result<(), DslError> {
    parse(input).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boolean_precedence() {
        let expr = parse(r#"path prefix "/admin" AND (method equals "POST" OR query contains "debug")"#).unwrap();
        match expr {
            Expr::And(parts) => assert_eq!(parts.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_headers_and_not() {
        let expr = parse(r#"NOT header:x-api-key equals "secret""#).unwrap();
        assert!(matches!(expr, Expr::Not(_)));
        let expr = parse(r#"header:X-Api-Key prefix "ak_""#).unwrap();
        assert!(matches!(expr, Expr::Condition { field: Field::Header(_), .. }));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("path contains").is_err());
        assert!(parse("path regex \".*\"").is_err());
        assert!(parse("path contains \"unterminated").is_err());
        assert!(parse(&"(".repeat(MAX_DEPTH + 2)).is_err());
    }

    #[test]
    fn parses_ip_cidr_in() {
        let expr = parse(r#"ip in "10.0.0.0/8,2001:db8::/32""#).unwrap();
        assert!(matches!(
            expr,
            Expr::Condition { field: Field::Ip, op: Op::In, .. }
        ));
        assert!(parse(r#"path in "10.0.0.0/8""#).is_err());
        assert!(parse(r#"ip in "10.0.0.0/33""#).is_err());
        assert!(parse(r#"ip in "not-an-ip""#).is_err());
    }

    #[test]
    fn lowercases_values() {
        let expr = parse(r#"method equals "POST""#).unwrap();
        match expr {
            Expr::Condition { value, .. } => assert_eq!(value, "post"),
            _ => panic!(),
        }
    }
}
