//! SEC-NEW-01 regression: DNS-rebinding must not defeat the SSRF guard.
//!
//! The integration-test build compiles the library *without* `cfg(test)`, so the
//! loopback exemption that lets the library's own mock-server unit tests run is
//! absent here. That makes this the honest check of what ships.
//!
//! The property under test is that the policy is applied where the socket is
//! opened, not only in a caller's pre-flight check. A rebinding server wins
//! precisely when the transport re-resolves a name after the check; if the guard
//! can refuse an address even when no pre-flight check ran, the race has no room.

use control::service::agent_http;
use control::service::net_guard;
use serde_json::json;
use std::net::{IpAddr, TcpListener};

/// A hostname that always resolves to loopback. No external DNS involved.
const LOOPBACK_NAME: &str = "localhost";

#[test]
fn loopback_answer_is_rejected_by_the_shipping_policy() {
    // `permitted` adds the loopback exemption only under `cfg(test)`; this
    // library build has none, so the guard must refuse these outright.
    for raw in ["127.0.0.1", "::1"] {
        assert!(!net_guard::is_public_ip(raw.parse::<IpAddr>().unwrap()));
    }
}

#[test]
fn guarded_resolver_returns_only_approved_addresses() {
    // The resolver is what hyper and reqwest call at connect time. If it hands
    // back a private address for a DNS name, the guard is decorative.
    let msg = "alert destination";
    let err = futures_lite_block_on(net_guard::resolve_allowed(
        LOOPBACK_NAME,
        80,
        net_guard::is_public_ip,
        msg,
    ))
    .unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");

    // An approved literal comes back unchanged, which is what gets dialled.
    let ok = futures_lite_block_on(net_guard::resolve_allowed(
        "1.1.1.1",
        443,
        net_guard::is_public_ip,
        msg,
    ))
    .unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].ip().to_string(), "1.1.1.1");
    assert_eq!(ok[0].port(), 443);
}

#[tokio::test]
async fn transport_refuses_internal_targets_without_any_preflight() {
    // `post_json_with_headers` and `get_response` are public helpers that run the
    // guard themselves. Nothing calls `validate_http_url` first here: this is the
    // "attacker already got past the check" shape of a rebinding attempt.
    let metadata = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
    let err = agent_http::post_json_with_headers(metadata, &json!({"x": 1}), &[])
        .await
        .unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");

    let err = agent_http::get_response(metadata, &[]).await.unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");

    // Same for an IP literal the resolver never sees, and for a loopback name
    // that only the guarded resolver can refuse.
    let err = agent_http::get_response("http://127.0.0.1:1/", &[])
        .await
        .unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://{LOOPBACK_NAME}:{port}/hook");
    let err = agent_http::post_json_with_headers(&url, &json!({}), &[])
        .await
        .unwrap_err();
    assert!(
        err.contains("disallowed address"),
        "a loopback name must be refused at connect time, got: {err}"
    );
}

#[tokio::test]
async fn alerting_channels_refuse_loopback_destinations() {
    // End-to-end through the notification transports, which is the path a tenant
    // actually controls via `POST /alert-channels`.
    let config = json!({ "url": format!("http://{LOOPBACK_NAME}:9/hook") });
    let err = control::service::notify::send_channel("webhook", &config, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");

    let config = json!({
        "bot_token": "1:x",
        "chat_id": "1",
        "api_base": format!("http://{LOOPBACK_NAME}:9"),
    });
    let err = control::service::notify::send_channel("telegram", &config, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");

    let config = json!({
        "smtp_host": LOOPBACK_NAME,
        "from": "a@example.com",
        "to": ["b@example.com"],
    });
    let err = control::service::notify::send_channel("email", &config, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");
}

/// Minimal blocking runner so the non-async tests can await the resolver.
fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}
