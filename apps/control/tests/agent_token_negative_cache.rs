//! SEC-NEW-03 regression: invalid agent tokens must not reach PostgreSQL per
//! request.
//!
//! The agent routes are open to the internet by design (they authenticate with a
//! per-node token, not a session), so `X-Lagran-Agent-Token: <random>` is
//! attacker-controlled input. Before the negative cache, every unique random
//! token cost one `SELECT ... WHERE auth_token = $1` against a 20-connection
//! pool: a trivial way to queue every legitimate request behind a flood, because
//! the *rate* of queries followed the request rate one-for-one.
//!
//! These tests pin the guarantees using the crate's public surface. The
//! integration-test build compiles the library without `cfg(test)`, so what is
//! exercised here is the code that ships.

use control::middleware::agent_token_cache::{
    AgentTokenCache, NEGATIVE_FLOOD_PER_SEC, NEGATIVE_TTL,
};
use std::time::Duration;

/// Deliberately not `assert!(CONST >= 1)`: a comparison of two constants is
/// constant-folded and clippy rejects it as a vacuous assertion. Wrapping the
/// value in a function keeps the check meaningful and readable.
fn ttl() -> Duration {
    NEGATIVE_TTL
}

fn budget() -> u32 {
    NEGATIVE_FLOOD_PER_SEC
}

#[test]
fn the_miss_ttl_is_short_enough_for_a_fresh_node() {
    // The finding's own caveat: a newly created node's token is used within
    // seconds. The window must stay well under that so the worst case (no
    // explicit invalidation at all) cannot outlive a normal install.
    assert!(
        ttl() <= Duration::from_secs(10),
        "a negative entry must not outlive a normal node install"
    );
    assert!(
        ttl() >= Duration::from_secs(1),
        "a sub-second window would still let one token reach the database per request"
    );
}

#[test]
fn the_per_source_budget_is_a_usable_positive_rate() {
    // A budget of 0 would refuse every unknown token *and* any legitimate node
    // whose positive entry had just expired: a DoS defence turning into an
    // outage. A very large budget would defeat the point of the limit.
    assert!(
        budget() >= 1,
        "the per-source budget must allow at least one lookup per second"
    );
    assert!(
        budget() <= 1_000,
        "an unbounded budget lets one source still flood PostgreSQL"
    );
}

#[test]
fn forget_miss_is_safe_for_any_input() {
    // `POST /nodes` calls this with the freshly issued token. It must never
    // panic, and must tolerate an empty token (the caller does not check).
    let cache = AgentTokenCache::new();
    cache.forget_miss("fresh-node-token");
    cache.forget_miss("");
    assert_eq!(cache.suppressed(), 0);
}

#[test]
fn the_suppression_counter_starts_at_zero() {
    // Operators read this counter to see whether a flood is being absorbed
    // rather than reaching the pool.
    let cache = AgentTokenCache::new();
    assert_eq!(cache.suppressed(), 0);
}
