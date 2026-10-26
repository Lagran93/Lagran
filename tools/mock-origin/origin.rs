//! Minimal HTTP origin for the integration smoke test (std only, no crates).
//!
//! Build: rustc -O tools/mock-origin/origin.rs -o target/mock-origin
//! Run:   target/mock-origin 9090

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

static ETAG_COUNTER: AtomicU64 = AtomicU64::new(0);

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9090);
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind mock origin");
    eprintln!("mock origin listening on 127.0.0.1:{port}");
    for stream in listener.incoming().flatten() {
        thread::spawn(move || {
            if let Err(e) = handle(stream, port) {
                eprintln!("mock origin connection error: {e}");
            }
        });
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn handle(mut stream: TcpStream, port: u16) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    let head_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    let mut custom_header = String::new();
    let mut cookie = String::new();
    let mut accept_language = String::new();
    let mut cache_control = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("x-custom") {
                custom_header = value.to_string();
            } else if name.eq_ignore_ascii_case("cookie") {
                cookie = value.to_string();
            } else if name.eq_ignore_ascii_case("accept-language") {
                accept_language = value.to_string();
            } else if name.eq_ignore_ascii_case("cache-control") {
                cache_control = value.to_string();
            }
        }
    }

    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let (status, payload, extra): (u16, Vec<u8>, Vec<(&str, String)>) = match method.as_str() {
        "POST" => {
            let json = format!(
                "{{\"method\":\"POST\",\"path\":\"{}\",\"x_custom\":\"{}\",\"cookie\":\"{}\",\"cache_control\":\"{}\",\"bytes\":{},\"echo\":\"{}\"}}",
                json_escape(&target),
                json_escape(&custom_header),
                json_escape(&cookie),
                json_escape(&cache_control),
                body.len(),
                json_escape(&String::from_utf8_lossy(&body))
            );
            (
                200,
                json.into_bytes(),
                vec![("Content-Type", "application/json".into())],
            )
        }
        _ => match path.as_str() {
            "/etag" => {
                let n = ETAG_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
                (
                    200,
                    format!("version-{n}").into_bytes(),
                    vec![("Cache-Control", "public, max-age=60".into())],
                )
            }
            "/vary" => (
                200,
                format!("lang={}", accept_language).into_bytes(),
                vec![
                    ("Vary", "Accept-Language".into()),
                    ("Cache-Control", "public, max-age=60".into()),
                ],
            ),
            "/cached" => (
                200,
                b"hello from origin".to_vec(),
                vec![(
                    "Cache-Control",
                    "public, max-age=120, stale-while-revalidate=30".into(),
                )],
            ),
            "/nostore" => (
                200,
                b"hello from origin".to_vec(),
                vec![("Cache-Control", "no-store".into())],
            ),
            "/private" => (
                200,
                b"hello from origin".to_vec(),
                vec![("Cache-Control", "private, max-age=60".into())],
            ),
            "/api/data" => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                (
                    200,
                    format!("{{\"ok\":true,\"ts\":{ts}}}").into_bytes(),
                    vec![("Content-Type", "application/json".into())],
                )
            }
            "/expires" => (
                200,
                b"hello from origin".to_vec(),
                vec![("Expires", "Tue, 01 Jan 2030 00:00:00 GMT".into())],
            ),
            // --- TTL precedence fixtures (used by tests/integration/ttl.sh) ---
            // Origin says max-age=60; the domain rule overrides it to 1s.
            "/ttl/rule" => (
                200,
                b"ttl rule".to_vec(),
                vec![("Cache-Control", "public, max-age=60".into())],
            ),
            // s-maxage=1 must win over max-age=60.
            "/ttl/smax" => (
                200,
                b"ttl smax".to_vec(),
                vec![("Cache-Control", "public, s-maxage=1, max-age=60".into())],
            ),
            // max-age=1 must win over the far-future Expires.
            "/ttl/maxage" => (
                200,
                b"ttl maxage".to_vec(),
                vec![
                    ("Cache-Control", "public, max-age=1".into()),
                    ("Expires", "Tue, 01 Jan 2030 00:00:00 GMT".into()),
                ],
            ),
            // Only Expires: must be used instead of the 2s default.
            "/ttl/expires" => (
                200,
                b"ttl expires".to_vec(),
                vec![("Expires", "Tue, 01 Jan 2030 00:00:00 GMT".into())],
            ),
            // No cache headers at all: the domain default (CACHE_TTL) applies.
            "/ttl/default" => (200, b"ttl default".to_vec(), vec![]),
            "/big" => (200, vec![b'x'; 512 * 1024], vec![]),
            _ => (
                200,
                b"hello from origin".to_vec(),
                vec![("Content-Type", "text/plain".into())],
            ),
        },
    };

    let mut response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n",
        payload.len()
    );
    response.push_str(&format!("X-Origin-Port: {port}\r\n"));
    for (name, value) in extra {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("Connection: close\r\n\r\n");

    stream.write_all(response.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(&payload)?;
    }
    stream.flush()?;
    Ok(())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
