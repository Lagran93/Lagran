//! Behavioural proof for SEC-NEW-01, beyond unit assertions on helpers.
//!
//! These tests stand up real sockets and check what the control plane actually
//! connects to. The integration-test build compiles the library without
//! `cfg(test)`, so the shipping policy has no loopback exemption: anything that
//! reaches a 127.0.0.1 listener here would have to travel through a guard that
//! already approved that address — exactly the property the rebinding fix adds.

use control::service::{agent_http, net_guard};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};

const LOOPBACK_NAME: &str = "localhost";

#[test]
fn shipping_policy_rejects_every_internal_range() {
    for raw in [
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        let ip: IpAddr = raw.parse().unwrap();
        assert!(
            !net_guard::is_public_ip(ip),
            "{raw} must not pass the shipping policy"
        );
    }
}

#[test]
fn resolver_refuses_a_name_that_answers_with_loopback() {
    // The rebinding shape with a stand-in name: whatever a hostile DNS server
    // returns, the answer is filtered at the point of use. `localhost` always
    // resolves internally, so no network access is needed to prove the filter.
    let err = tokio_block_on(net_guard::resolve_allowed(
        LOOPBACK_NAME,
        8080,
        net_guard::is_public_ip,
        "alert destination",
    ))
    .unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");
    assert!(err.contains("127.0.0.1") || err.contains("::1"), "{err}");
}

#[tokio::test]
async fn transport_refuses_loopback_without_a_preflight_check() {
    // A live listener proves the refusal is not just "nothing was listening".
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    for url in [
        format!("http://127.0.0.1:{port}/hook"),
        format!("http://{LOOPBACK_NAME}:{port}/hook"),
        format!("http://[::1]:{port}/hook"),
        "http://169.254.169.254/latest/meta-data/".to_string(),
    ] {
        let err = agent_http::post_json_with_headers(&url, &json!({}), &[])
            .await
            .unwrap_err();
        assert!(
            err.contains("disallowed address"),
            "{url} was not refused by the address guard: {err}"
        );
    }
}

#[tokio::test]
async fn alert_transports_refuse_loopback_in_every_channel() {
    let webhook = json!({ "url": format!("http://{LOOPBACK_NAME}:9/hook") });
    let err = control::service::notify::send_channel("webhook", &webhook, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");

    let telegram = json!({
        "bot_token": "1:x",
        "chat_id": "1",
        "api_base": format!("http://{LOOPBACK_NAME}:9"),
    });
    let err = control::service::notify::send_channel("telegram", &telegram, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");

    let email = json!({
        "smtp_host": LOOPBACK_NAME,
        "from": "a@example.com",
        "to": ["b@example.com"],
    });
    let err = control::service::notify::send_channel("email", &email, "s", "m", "info")
        .await
        .unwrap_err();
    assert!(err.contains("rejected"), "{err}");
}

#[tokio::test]
async fn the_guard_rejects_before_the_transport_does_any_work() {
    // A live listener makes the distinction visible: if the guard failed to run,
    // the request would reach the socket and produce a real HTTP answer instead
    // of a "disallowed address" error.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served_srv = served.clone();
    let server = std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0_u8; 2048];
            if stream.read(&mut buf).unwrap_or(0) > 0 {
                served_srv.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let err = agent_http::get_response(&format!("http://127.0.0.1:{port}/"), &[])
        .await
        .unwrap_err();
    assert!(err.contains("disallowed address"), "{err}");
    assert!(
        !served.load(std::sync::atomic::Ordering::SeqCst),
        "the request reached the listener, so the guard did not run before connect"
    );

    drop(server);
}

fn tokio_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}
