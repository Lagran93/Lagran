//! End-to-end PERF-NEW-02 measurement.
//!
//! Stands up N slow mock edges on loopback, pushes a certificate to all of them
//! two ways, and reports wall-clock time:
//!
//! * serial   — the old `for` loop over nodes (what the finding describes);
//! * parallel — `fan_out_edge`, as shipped.
//!
//! Each mock edge sleeps before answering, so the measurement is dominated by
//! per-node latency, exactly the term that used to be additive.
//!
//! Run: cargo run --release -p control --example acme_fanout_probe

use control::service::agent_http::{fan_out_edge, OwnedNode};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

const NODES: usize = 8;
const DELAY_MS: u64 = 400;

/// One mock edge that answers after `delay`.
fn spawn_slow_edge(delay: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock edge");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                thread::sleep(delay);
                let body = r#"{"success":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    port
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let delay = Duration::from_millis(DELAY_MS);
    let ports: Vec<u16> = (0..NODES).map(|_| spawn_slow_edge(delay)).collect();

    let nodes: Vec<OwnedNode> = ports
        .iter()
        .enumerate()
        .map(|(i, port)| OwnedNode {
            name: format!("edge-{i}"),
            agent_url: format!("http://127.0.0.1:{port}"),
            token: "probe-token".into(),
        })
        .collect();

    let body = serde_json::json!({
        "names": ["probe.test"],
        "cert_pem": "cert",
        "key_pem": "key",
    });

    // --- serial: the pre-fix shape -----------------------------------------
    let serial_start = Instant::now();
    let mut serial_ok = 0usize;
    for node in &nodes {
        let url = node.endpoint("/__lagran/certs/load");
        if control::service::agent_http::post_json_ok(&url, &body, &node.token)
            .await
            .is_ok()
        {
            serial_ok += 1;
        }
    }
    let serial = serial_start.elapsed();

    // --- parallel: shipped behaviour ---------------------------------------
    let parallel_start = Instant::now();
    let (parallel_ok, failures) = fan_out_edge(&nodes, move |node| {
        let url = node.endpoint("/__lagran/certs/load");
        let body = body.clone();
        async move { control::service::agent_http::post_json_ok(&url, &body, &node.token).await }
    })
    .await;
    let parallel = parallel_start.elapsed();

    println!("nodes={NODES} per_node_delay={delay:?}");
    println!("serial:   {serial:?} ok={serial_ok}");
    println!(
        "parallel: {parallel:?} ok={parallel_ok} failures={}",
        failures.len()
    );

    let speedup = serial.as_secs_f64() / parallel.as_secs_f64();
    println!(
        "speedup={speedup:.2}x serial_ideal={:?}",
        delay * NODES as u32
    );

    assert_eq!(
        parallel_ok as usize, NODES,
        "every mock edge must be reached"
    );
    if parallel * 2 < serial {
        println!("PASS: bounded fan-out removes the additive cost");
    } else {
        println!("FAIL: fan-out did not beat the serial loop");
        std::process::exit(1);
    }
}
