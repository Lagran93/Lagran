//! Cached edge-node token authentication.
//!
//! Every edge management request used to execute
//! `SELECT name FROM edge_nodes WHERE auth_token = $1`. With heartbeats, logs,
//! metrics and health reports that is ~1-2 queries/second per node, which is
//! enough to queue the control-plane pool during a database backup.
//!
//! This cache has three levels:
//! * a short-lived process-local `DashMap` for the common case (both hits and
//!   misses);
//! * the optional shared Redis cache so a token resolved by one control replica
//!   does not immediately hit PostgreSQL on every other replica;
//! * a fail-closed **negative** entry for unknown tokens, see below.
//!
//! Tokens are hashed before they become cache keys, so a raw node credential is
//! never stored in Redis or used as a map key.
//!
//! # Why misses are cached
//!
//! The agent routes (`/nodes/heartbeat`, `/access-logs/report`,
//! `/metrics/report`, `/edge/config`, …) are reachable without a session, so
//! anyone can send `X-Lagran-Agent-Token: <random>`. A miss used to fall straight
//! through to PostgreSQL, which meant N requests with N unique random tokens cost
//! N queries against a 20-connection pool: a trivial way to queue every
//! legitimate request behind an attacker's traffic.
//!
//! Caching the miss fixes that, but a *per-token* negative entry alone is not
//! enough: it bounds queries per token, not queries in total, so an attacker can
//! still force one query per random token they invent. Two limits close that:
//!
//! * [`NEGATIVE_FLOOD_PER_SEC`] caps how many misses any one client IP may take to
//!   the database per second. Beyond it the lookup is rejected without querying.
//! * [`NEGATIVE_ENTRY_MAX_ENTRIES`] bounds the memory the negative table itself can
//!   consume, independently of the positive table.
//!
//! # Why the negative TTL is short, and why creation clears it
//!
//! A newly registered node's token must work immediately: `POST /nodes` returns
//! the token and the install command uses it seconds later. A negative entry could
//! otherwise reject it. [`NEGATIVE_TTL`] is therefore short, and
//! [`AgentTokenCache::forget_miss`] lets the node-creation path clear the entry so
//! the very first heartbeat cannot be refused even inside that window.

use crate::repository;
use crate::service::redis::RedisService;
use dashmap::DashMap;
use ring::digest::{digest, SHA256};
use sqlx::PgPool;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Positive lookups live this long. Revocation is bounded by this TTL on other
/// control replicas (the local replica invalidates immediately).
pub const AGENT_TOKEN_CACHE_SECS: u64 = 30;
const AGENT_TOKEN_CACHE_MAX_ENTRIES: usize = 10_000;

/// How long a token that resolved to nothing is remembered as invalid.
///
/// Kept short on purpose: it is the upper bound on how long a *valid* token could
/// be refused if it was ever observed missing (a node created, deleted, and
/// recreated with the same token within the window). The creation path clears the
/// entry explicitly, so the normal flow never relies on this bound.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Hard cap on the per-IP flood table, so a widely distributed source set cannot
/// grow it without bound.
const FLOOD_TABLE_MAX_ENTRIES: usize = 4_096;

/// Hard cap on the number of negative entries held in this process.
///
/// Separate from the positive table so a flood of random tokens cannot evict
/// legitimate cached node names by filling the map.
const NEGATIVE_ENTRY_MAX_ENTRIES: usize = 10_000;

/// How many database lookups one client IP may trigger per second while its
/// tokens keep missing.
///
/// This is the bound that makes the attack in the finding (thousands of unique
/// random tokens per second from one source) actually cheap to reject: past the
/// budget, the request is refused by the cache without touching PostgreSQL.
pub const NEGATIVE_FLOOD_PER_SEC: u32 = 50;

#[derive(Debug, Clone)]
struct CachedAgent {
    node_name: String,
    expires_at: Instant,
}

/// A remembered miss. `expires_at` is when the token may be re-checked.
#[derive(Debug, Clone, Copy)]
struct Negative {
    expires_at: Instant,
}

/// Per-client-IP miss budget for the current second.
#[derive(Debug, Default)]
struct FloodWindow {
    /// `u32::MAX` sentinel-free: `second` identifies the window.
    second: u64,
    count: u32,
}

pub struct AgentTokenCache {
    local: DashMap<String, CachedAgent>,
    negative: DashMap<String, Negative>,
    /// Sliding one-second counters keyed by client IP (a hashed, truncated form).
    flood: DashMap<u32, FloodWindow>,
    /// Rejection counter, surfaced for tests and operators.
    suppressed: AtomicU32,
}

impl AgentTokenCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
            negative: DashMap::new(),
            flood: DashMap::new(),
            suppressed: AtomicU32::new(0),
        }
    }

    /// Resolve a per-node token to its node name.
    ///
    /// Returns `Ok(None)` for an unknown token without consulting PostgreSQL when
    /// the miss is already cached or the caller has exhausted its miss budget.
    /// `client_ip` identifies the source so one noisy client cannot spend the
    /// whole process's query budget; pass `None` when there is no peer (the
    /// per-token negative cache still applies).
    pub async fn resolve(
        &self,
        pool: &PgPool,
        redis: Option<&RedisService>,
        token: &str,
        client_ip: Option<IpAddr>,
    ) -> sqlx::Result<Option<String>> {
        let key = token_cache_key(token);
        if let Some(node_name) = self.lookup_local(&key) {
            return Ok(Some(node_name));
        }
        if self.is_known_miss(&key) {
            return Ok(None);
        }

        if let Some(redis) = redis {
            if let Some(node_name) = redis.get(&key).await {
                if !node_name.is_empty() {
                    self.insert_local(key, node_name.clone());
                    return Ok(Some(node_name));
                }
            }
        }

        // Past this point the request would reach PostgreSQL. Charge the caller's
        // miss budget first: when one source is enumerating tokens, refusing here
        // is the difference between N queries and a constant number.
        if !self.charge_miss(client_ip) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let node_name = repository::node_name_for_token(pool, token).await?;
        match node_name.as_ref() {
            Some(node_name) => {
                self.insert_local(key.clone(), node_name.clone());
                // A stale miss must not shadow a token that now exists.
                self.negative.remove(&key);
                if let Some(redis) = redis {
                    let _ = redis.set_ex(&key, node_name, AGENT_TOKEN_CACHE_SECS).await;
                }
            }
            None => {
                self.remember_miss(key.clone());
                if let Some(redis) = redis {
                    // A previous positive entry could otherwise survive a token
                    // change on another replica for the remainder of its TTL.
                    redis.del(&key).await;
                }
            }
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
        self.negative.remove(&key);
        if let Some(redis) = redis {
            redis.del(&key).await;
        }
    }

    /// Clear any remembered miss for `token`.
    ///
    /// Called after a node is created: the install command uses the freshly
    /// issued token within seconds, and a miss recorded for that same string
    /// before the row existed (a bare guess that happened to match, or a deleted
    /// and recreated token) must not reject it.
    pub fn forget_miss(&self, token: &str) {
        if token.is_empty() {
            return;
        }
        self.negative.remove(&token_cache_key(token));
    }

    /// Number of requests rejected by the flood budget since startup.
    pub fn suppressed(&self) -> u32 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Whether this token is already known to be invalid.
    fn is_known_miss(&self, key: &str) -> bool {
        let now = Instant::now();
        let Some(entry) = self.negative.get(key) else {
            return false;
        };
        if entry.expires_at > now {
            return true;
        }
        drop(entry);
        self.negative
            .remove_if(key, |_, entry| entry.expires_at <= now);
        false
    }

    fn remember_miss(&self, key: String) {
        let now = Instant::now();
        if self.negative.len() >= NEGATIVE_ENTRY_MAX_ENTRIES {
            self.negative.retain(|_, entry| entry.expires_at > now);
            if self.negative.len() >= NEGATIVE_ENTRY_MAX_ENTRIES {
                // The table is full of still-valid misses: refusing to grow is
                // the point, so this request simply repeats its query later
                // rather than pushing a legitimate entry out.
                return;
            }
        }
        self.negative.insert(
            key,
            Negative {
                expires_at: now + NEGATIVE_TTL,
            },
        );
    }

    /// Take one unit of `client_ip`'s per-second miss budget.
    ///
    /// Returns `false` when the budget for the current second is spent. The
    /// counter is per second rather than per window so a legitimate node that
    /// misses once (during a restart, say) is never meaningfully throttled.
    fn charge_miss(&self, client_ip: Option<IpAddr>) -> bool {
        let Some(ip) = client_ip else {
            // No peer (tests, or a caller that did not supply one): only the
            // per-token negative cache applies.
            return true;
        };
        let key = flood_key(ip);
        let second = now_second();
        let allowed = {
            let mut entry = self.flood.entry(key).or_default();
            if entry.second != second {
                entry.second = second;
                entry.count = 0;
            }
            if entry.count >= NEGATIVE_FLOOD_PER_SEC {
                false
            } else {
                entry.count += 1;
                true
            }
        };
        // Cleanup must happen *after* the shard guard is released: `len` and
        // `retain` touch every shard, and holding one shard's write lock while
        // asking for the others deadlocks the whole table. A flood from many
        // sources must not grow this map without bound either.
        if self.flood.len() > FLOOD_TABLE_MAX_ENTRIES {
            self.flood.retain(|_, w| w.second == second);
        }
        allowed
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

/// A compact key for the per-IP flood table.
///
/// The full address is kept only as a `u32` hash: collisions merge two clients'
/// budgets, which costs a little fairness and leaks nothing, whereas a
/// `String` key per source would let an attacker with a large address space grow
/// the map.
fn flood_key(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return u32::from(v4);
            }
            let bytes = v6.octets();
            let mut hasher = 0u32;
            for chunk in bytes.chunks(4) {
                hasher = hasher.rotate_left(7)
                    ^ u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            hasher
        }
    }
}

/// Seconds since the process's first cache use, used to bucket the flood window.
///
/// A monotonic counter rather than a wall clock: a clock step must not hand an
/// attacker a fresh budget, and the value only ever needs to change once a second.
fn now_second() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs()
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

    // --- negative caching ---

    #[test]
    fn a_miss_is_remembered_and_expires() {
        let cache = AgentTokenCache::new();
        let key = token_cache_key("bogus");
        assert!(!cache.is_known_miss(&key));

        cache.remember_miss(key.clone());
        assert!(cache.is_known_miss(&key), "the miss must be remembered");

        // Rewrite the entry as already expired and confirm it is re-checkable.
        cache.negative.insert(
            key.clone(),
            Negative {
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(!cache.is_known_miss(&key));
        assert!(
            !cache.negative.contains_key(&key),
            "an expired entry must be dropped"
        );
    }

    #[test]
    fn forgetting_a_miss_lets_a_new_token_through_immediately() {
        // The creation path calls this: the install command uses the freshly
        // issued token within seconds, so a stale miss must never reject it.
        let cache = AgentTokenCache::new();
        let token = "freshly-issued-node-token";
        let key = token_cache_key(token);
        cache.remember_miss(key.clone());
        assert!(cache.is_known_miss(&key));

        cache.forget_miss(token);
        assert!(!cache.is_known_miss(&key));
    }

    #[test]
    fn invalidation_also_clears_a_negative_entry() {
        let cache = AgentTokenCache::new();
        let token = "tok";
        let key = token_cache_key(token);
        cache.remember_miss(key.clone());
        assert!(cache.is_known_miss(&key));

        // `invalidate` is async; drive it on a small runtime.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(cache.invalidate(None, token));
        assert!(!cache.is_known_miss(&key));
    }

    #[test]
    fn the_negative_table_is_bounded_separately_from_the_positive_one() {
        let cache = AgentTokenCache::new();
        // Fill the positive table so eviction pressure exists.
        for i in 0..AGENT_TOKEN_CACHE_MAX_ENTRIES {
            cache.insert_local(format!("pos-{i}"), format!("node-{i}"));
        }
        for i in 0..(NEGATIVE_ENTRY_MAX_ENTRIES + 64) {
            cache.remember_miss(format!("neg-{i}"));
        }
        assert!(
            cache.negative.len() <= NEGATIVE_ENTRY_MAX_ENTRIES,
            "negative table grew past its cap: {}",
            cache.negative.len()
        );
        assert!(
            cache.local.len() <= AGENT_TOKEN_CACHE_MAX_ENTRIES,
            "a token flood must not evict positive entries"
        );
    }

    #[test]
    fn one_source_cannot_spend_the_whole_miss_budget() {
        // The finding's attack: thousands of unique random tokens per second from
        // one source. However many distinct tokens arrive, the number that may
        // reach PostgreSQL per second is capped.
        let cache = AgentTokenCache::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let mut allowed = 0u32;
        for _ in 0..(NEGATIVE_FLOOD_PER_SEC * 10) {
            if cache.charge_miss(Some(ip)) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, NEGATIVE_FLOOD_PER_SEC,
            "the per-second budget must be enforced exactly"
        );
        assert!(
            cache.suppressed() == 0,
            "charging is not itself a rejection"
        );
    }

    #[test]
    fn the_miss_budget_is_per_source() {
        let cache = AgentTokenCache::new();
        let noisy: IpAddr = "203.0.113.9".parse().unwrap();
        let other: IpAddr = "198.51.100.7".parse().unwrap();
        for _ in 0..NEGATIVE_FLOOD_PER_SEC {
            assert!(cache.charge_miss(Some(noisy)));
        }
        assert!(!cache.charge_miss(Some(noisy)), "noisy source is spent");
        assert!(
            cache.charge_miss(Some(other)),
            "an unrelated source must keep its own budget"
        );
    }

    #[test]
    fn a_missing_peer_is_not_throttled() {
        // Callers without a socket peer (unit tests, internal calls) still get the
        // per-token negative cache, but must not be rejected for lacking an IP.
        let cache = AgentTokenCache::new();
        for _ in 0..(NEGATIVE_FLOOD_PER_SEC * 3) {
            assert!(cache.charge_miss(None));
        }
    }

    #[test]
    fn ipv4_mapped_addresses_share_their_v4_budget() {
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(flood_key(mapped), flood_key(v4));
    }

    #[test]
    fn the_flood_table_is_bounded() {
        let cache = AgentTokenCache::new();
        for i in 0..10_000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761)));
            let _ = cache.charge_miss(Some(ip));
        }
        assert!(
            cache.flood.len() <= 4_096,
            "flood table grew past its cap: {}",
            cache.flood.len()
        );
    }
}
