//! Contract tests for cache TTL selection.
//!
//! Precedence under test:
//!   explicit rule TTL → origin `s-maxage` → origin `max-age` → `Expires` → default
//!
//! These call the same `decide_storage` the proxy uses on every origin response,
//! so a regression here is a real behaviour change (not a mock).

use edge::cache::policy::{decide_storage, ResolvedPolicy, RuleAction};

/// Far-future HTTP date (~2027-10-21), used wherever a long TTL is wanted.
const FAR_FUTURE: &str = "Tue, 01 Jan 2030 00:00:00 GMT";

fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn policy(ttl: Option<u64>, swr: u64) -> ResolvedPolicy {
    ResolvedPolicy {
        action: RuleAction::Cache,
        ttl_override: ttl,
        swr_secs: swr,
        browser_ttl_secs: None,
        ignore_query: None,
        ignore_cookie: false,
    }
}

#[test]
fn rule_ttl_wins_over_every_origin_signal() {
    let all = hdrs(&[
        ("Cache-Control", "public, s-maxage=100, max-age=50"),
        ("Expires", FAR_FUTURE),
    ]);
    let d = decide_storage(200, &all, policy(Some(7), 0), 60).unwrap();
    assert_eq!(d.ttl_secs, 7);
}

#[test]
fn s_maxage_wins_over_max_age_and_expires() {
    let all = hdrs(&[
        ("Cache-Control", "public, s-maxage=100, max-age=50"),
        ("Expires", FAR_FUTURE),
    ]);
    let d = decide_storage(200, &all, policy(None, 0), 60).unwrap();
    assert_eq!(d.ttl_secs, 100);
}

#[test]
fn max_age_wins_over_expires() {
    let both = hdrs(&[
        ("Cache-Control", "public, max-age=50"),
        ("Expires", FAR_FUTURE),
    ]);
    let d = decide_storage(200, &both, policy(None, 0), 60).unwrap();
    assert_eq!(d.ttl_secs, 50);
}

#[test]
fn expires_is_used_without_cache_control() {
    let only = hdrs(&[("Expires", FAR_FUTURE)]);
    let d = decide_storage(200, &only, policy(None, 0), 60).unwrap();
    // Roughly one year: definitely not the 60s default.
    assert!(d.ttl_secs > 1_000_000, "got {}", d.ttl_secs);
}

#[test]
fn default_ttl_is_the_last_resort() {
    let d = decide_storage(200, &[], policy(None, 0), 60).unwrap();
    assert_eq!(d.ttl_secs, 60);
}

#[test]
fn zero_ttl_means_do_not_store() {
    assert!(decide_storage(200, &[], policy(None, 0), 0).is_none());
    assert!(
        decide_storage(200, &[], policy(Some(0), 0), 60).is_none(),
        "an explicit zero TTL must not fall through to the default"
    );
}

#[test]
fn swr_rule_wins_over_origin_swr() {
    let cc = hdrs(&[(
        "Cache-Control",
        "public, max-age=30, stale-while-revalidate=5",
    )]);
    assert_eq!(
        decide_storage(200, &cc, policy(None, 20), 60)
            .unwrap()
            .swr_secs,
        20
    );
    assert_eq!(
        decide_storage(200, &cc, policy(None, 0), 60)
            .unwrap()
            .swr_secs,
        5
    );
}

#[test]
fn uncacheable_directives_beat_every_layer() {
    let blocked = hdrs(&[("Cache-Control", "private, max-age=60")]);
    assert!(decide_storage(200, &blocked, policy(Some(30), 10), 60).is_none());
    assert!(decide_storage(404, &[], policy(Some(30), 10), 60).is_none());
}
