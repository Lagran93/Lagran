//! Cache key and TTL policy helpers

use axum::http::Request;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct CacheRule {
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
}

#[derive(Clone, Default)]
pub struct RuleSet {
    inner: Arc<RwLock<Vec<CacheRule>>>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn replace(&self, mut rules: Vec<CacheRule>) {
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        *self.inner.write().await = rules;
    }

    /// Match path against rules (priority desc). Supports trailing * wildcard.
    pub async fn match_ttl(&self, path: &str) -> Option<u64> {
        let rules = self.inner.read().await;
        for r in rules.iter() {
            if path_matches(&r.path_pattern, path) {
                return Some(r.ttl_seconds);
            }
        }
        None
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/")) || path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

/// Build a cache key from method + host + path + query
pub fn cache_key<B>(req: &Request<B>) -> String {
    let method = req.method().as_str();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    format!("{method}:{host}:{path}")
}

/// Whether this request is cacheable (simple rules)
pub fn is_cacheable<B>(req: &Request<B>) -> bool {
    req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD
}


/// Cache key; when ignore_query is true, strip ?query
pub fn cache_key_opts<B>(req: &Request<B>, ignore_query: bool) -> String {
    let method = req.method().as_str();
    let path = if ignore_query {
        req.uri().path().to_string()
    } else {
        req.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let host = host.split(':').next().unwrap_or(host);
    format!("{method}:{host}:{path}")
}
