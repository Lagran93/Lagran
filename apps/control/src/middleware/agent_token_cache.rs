//! Cached edge-node token authentication.
//!
//! Every edge management request used to execute
//! `SELECT name FROM edge_nodes WHERE auth_token = $1`. With heartbeats, logs,
//! metrics and health reports that is ~1-2 queries/second per node, which is
//! enough to queue the control-plane pool during a database backup.
//!
//! This cache has two levels:
//! * a short-lived process-local `DashMap` for the common case;
//! * the optional shared Redis cache so a token resolved by one control replica
//!   does not immediately hit PostgreSQL on every other replica.
//!
//! Tokens are hashed before they become cache keys, so a raw node credential is
//! never stored in Redis or used as a map key.

use crate::repository;
use crate::service::redis::RedisService;
use dashmap::DashMap;
use ring::digest::{digest, SHA256};
use sqlx::PgPool;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Positive lookups live this long. Revocation is bounded by this TTL on other
/// control replicas (the local replica invalidates immediately).
pub const AGENT_TOKEN_CACHE_SECS: u64 = 30;
const AGENT_TOKEN_CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct CachedAgent {
    node_name: String,
    expires_at: Instant,
}

pub struct AgentTokenCache {
    local: DashMap<String, CachedAgent>,
}

impl AgentTokenCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
        }
    }

    /// Resolve a per-node token to its node name.
    ///
    /// Invalid tokens are deliberately not negatively cached: a newly created
    /// node's token is used immediately by the install command and must not be
    /// rejected for a TTL.
    pub async fn resolve(
        &self,
        pool: &PgPool,
        redis: Option<&RedisService>,
        token: &str,
    ) -> sqlx::Result<Option<String>> {
        let key = token_cache_key(token);
        if let Some(node_name) = self.lookup_local(&key) {
            return Ok(Some(node_name));
        }

        if let Some(redis) = redis {
            if let Some(node_name) = redis.get(&key).await {
                if !node_name.is_empty() {
                    self.insert_local(key, node_name.clone());
                    return Ok(Some(node_name));
                }
            }
        }

        let node_name = repository::node_name_for_token(pool, token).await?;
        if let Some(node_name) = node_name.as_ref() {
            self.insert_local(key.clone(), node_name.clone());
            if let Some(redis) = redis {
                let _ = redis.set_ex(&key, node_name, AGENT_TOKEN_CACHE_SECS).await;
            }
        } else if let Some(redis) = redis {
            // A previous positive entry could otherwise survive a token change
            // on another replica for the remainder of its TTL.
            redis.del(&key).await;
        }
        Ok(node_name)
    }

    /// Drop a token from this process and, when configured, from Redis.
    ///
    /// Other control replicas may still have their process-local entry until
    /// [`AGENT_TOKEN_CACHE_SECS`] expires; Redis invalidation covers replicas
    /// whose local entry has already expired.
    pub async fn invalidate(&self, redis: Option<&RedisService>, token: &str) {
        if token.is_empty() {
            return;
        }
        let key = token_cache_key(token);
        self.local.remove(&key);
        if let Some(redis) = redis {
            redis.del(&key).await;
        }
    }

    fn lookup_local(&self, key: &str) -> Option<String> {
        let now = Instant::now();
        let entry = self.local.get(key)?;
        if entry.expires_at > now {
            return Some(entry.node_name.clone());
        }
        drop(entry);
        self.local
            .remove_if(key, |_, entry| entry.expires_at <= now);
        None
    }

    fn insert_local(&self, key: String, node_name: String) {
        let now = Instant::now();
        if self.local.len() >= AGENT_TOKEN_CACHE_MAX_ENTRIES {
            self.local.retain(|_, entry| entry.expires_at > now);
            if self.local.len() >= AGENT_TOKEN_CACHE_MAX_ENTRIES {
                return;
            }
        }
        self.local.insert(
            key,
            CachedAgent {
                node_name,
                expires_at: now + Duration::from_secs(AGENT_TOKEN_CACHE_SECS),
            },
        );
    }
}

impl Default for AgentTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 of the token, hex encoded and namespaced for Redis.
fn token_cache_key(token: &str) -> String {
    let digest = digest(&SHA256, token.as_bytes());
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("lagran:agent-token:{hex}")
}

/// Shared handle stored in [`crate::state::AppState`].
pub type SharedAgentTokenCache = Arc<AgentTokenCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_hashed_and_deterministic() {
        let token = "super-secret-node-token";
        let key = token_cache_key(token);
        assert!(key.starts_with("lagran:agent-token:"));
        assert_eq!(key, token_cache_key(token));
        assert_eq!(key.len(), "lagran:agent-token:".len() + 64);
        assert!(!key.contains(token));
    }

    #[test]
    fn local_hits_are_bounded_and_expiry_is_enforced() {
        let cache = AgentTokenCache::new();
        for i in 0..(AGENT_TOKEN_CACHE_MAX_ENTRIES + 32) {
            cache.insert_local(format!("key-{i}"), format!("node-{i}"));
        }
        assert!(cache.local.len() <= AGENT_TOKEN_CACHE_MAX_ENTRIES);

        let key = token_cache_key("expired-token");
        cache.local.insert(
            key.clone(),
            CachedAgent {
                node_name: "expired-node".into(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(cache.lookup_local(&key).is_none());
        assert!(!cache.local.contains_key(&key));
    }

    #[tokio::test]
    async fn invalidation_drops_the_local_entry() {
        let cache = AgentTokenCache::new();
        let token = "node-token-to-revoke";
        let key = token_cache_key(token);
        cache.insert_local(key.clone(), "node-1".into());
        assert!(cache.lookup_local(&key).is_some());

        cache.invalidate(None, token).await;
        assert!(cache.lookup_local(&key).is_none());
    }
}
