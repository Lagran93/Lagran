//! Shared Control → Edge agent HTTP client.
//!
//! One pooled client for purge/reload/cert/challenge callbacks, with a bounded
//! per-attempt timeout and one retry for transport/5xx failures.
//!
//! Two connectors exist here, and the difference matters:
//!
//! * [`client`] is used for edge agent callbacks. Its destinations come from the
//!   node table, filled in by an administrator, and routinely sit on private or
//!   loopback addresses (a node on the same host as the control plane). It is
//!   therefore unguarded by design.
//! * [`public_client`] is used for anything a *tenant* chooses: alert webhooks and
//!   cache-probe fallbacks. Its connector resolves through
//!   [`net_guard::GuardedResolver`], so the address that passes the SSRF policy is
//!   the address that is dialled. See [`crate::service::net_guard`] for why that
//!   check has to live at connect time rather than in a pre-flight call.

use crate::service::net_guard;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::HeaderMap;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{de::DeserializeOwned, Serialize};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

type EdgeClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;
type GuardedConnector = hyper_rustls::HttpsConnector<HttpConnector<net_guard::GuardedResolver>>;
type PublicClient = Client<GuardedConnector, Full<Bytes>>;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPTS: usize = 2;

/// Trust anchors for `https://` edge agent callbacks.
///
/// WebPKI roots cover the normal case; `AGENT_TLS_CA_FILE` lets an operator pin
/// a private CA for an edge management listener that uses a self-signed or
/// internally issued certificate (M6).
fn agent_tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(path) = std::env::var("AGENT_TLS_CA_FILE") {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::read(path) {
                Ok(data) => {
                    let mut reader = std::io::BufReader::new(&data[..]);
                    let mut added = 0;
                    for cert in rustls_pemfile::certs(&mut reader).flatten() {
                        if roots.add(cert).is_ok() {
                            added += 1;
                        }
                    }
                    tracing::info!(ca = %path, certs = added, "trusting private CA for edge agent callbacks");
                }
                Err(e) => tracing::error!(
                    ca = %path,
                    error = %e,
                    "cannot read AGENT_TLS_CA_FILE; https edge callbacks may fail"
                ),
            }
        }
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

pub fn client() -> &'static EdgeClient {
    static CLIENT: OnceLock<EdgeClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.set_connect_timeout(Some(Duration::from_secs(3)));
        // Same reason as the guarded client: the outer connector owns scheme
        // selection, so `enforce_http` would reject every `https://` agent URL.
        http.enforce_http(false);
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(agent_tls_config())
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            // One shared client serves every edge. At 16 idle sockets, a fleet of
            // hundreds of nodes rebuilt connections constantly; 64 keeps the steady
            // state warm without holding an unbounded number open.
            .pool_max_idle_per_host(64)
            .build(https)
    })
}

/// Build a client whose connections are restricted to `policy`-approved addresses.
fn build_public_client(policy: fn(IpAddr) -> bool, label: &'static str) -> PublicClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = HttpConnector::new_with_resolver(net_guard::GuardedResolver::new(policy, label));
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(3)));
    // The HttpsConnector picks plaintext vs TLS from the URI scheme; leaving
    // `enforce_http` at its default (`true`) rejects every `https://` URL.
    http.enforce_http(false);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(16)
        .build(https)
}

/// Whether the failure was the attempt deadline rather than a transport fault.
///
/// `send_once_timeout` tags its own timeout; anything else (connection refused,
/// reset, DNS) may still succeed on a fresh attempt.
fn is_timeout(err: &str) -> bool {
    err.starts_with("callback timeout after")
}

async fn send_once(
    method: &str,
    url: &str,
    body: Bytes,
    token: &str,
) -> Result<(u16, Bytes), String> {
    send_once_timeout(method, url, body, token, ATTEMPT_TIMEOUT).await
}

async fn send_once_timeout(
    method: &str,
    url: &str,
    body: Bytes,
    token: &str,
    timeout: Duration,
) -> Result<(u16, Bytes), String> {
    let req = Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(body))
        .map_err(|e| format!("build callback request {url}: {e}"))?;
    let response = tokio::time::timeout(timeout, client().request(req))
        .await
        .map_err(|_| format!("callback timeout after {timeout:?}: {url}"))?
        .map_err(|e| format!("callback transport error {url}: {}", describe(&e)))?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("callback body error {url}: {e}"))?
        .to_bytes();
    Ok((status, bytes))
}

/// Send a JSON body with an explicit method; ignore the response body. Retries once.
pub async fn request_ok<B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
) -> Result<(), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        match send_once(method, url, bytes.clone(), token).await {
            Ok((status, _body)) if (200..300).contains(&status) => return Ok(()),
            Ok((status, body)) if status >= 500 && attempt + 1 < ATTEMPTS => {
                last = format!("HTTP {status}: {}", preview(&body));
            }
            Ok((status, body)) => return Err(format!("HTTP {status}: {}", preview(&body))),
            // A timeout already consumed the full attempt budget; spending it again
            // is not a retry, it is paying twice. This matters in `purge_retry`, which
            // walks rows serially: 5s + 0.1s + 5s per unreachable node turned a 15 s
            // cycle into minutes of continuous work.
            Err(e) if is_timeout(&e) => return Err(e),
            Err(e) if attempt + 1 < ATTEMPTS => last = e,
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(if last.is_empty() {
        "callback failed".into()
    } else {
        last
    })
}

pub async fn post_json_ok<B: Serialize>(url: &str, body: &B, token: &str) -> Result<(), String> {
    request_ok("POST", url, body, token).await
}

pub async fn put_json_ok<B: Serialize>(url: &str, body: &B, token: &str) -> Result<(), String> {
    request_ok("PUT", url, body, token).await
}

/// Send a JSON body and decode a JSON response. Retries once.
pub async fn request_json<T: DeserializeOwned, B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
) -> Result<T, String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        match send_once(method, url, bytes.clone(), token).await {
            Ok((status, body)) if (200..300).contains(&status) => {
                return serde_json::from_slice(&body)
                    .map_err(|e| format!("invalid callback JSON from {url}: {e}"));
            }
            Ok((status, body)) if status >= 500 && attempt + 1 < ATTEMPTS => {
                last = format!("HTTP {status}: {}", preview(&body));
            }
            Ok((status, body)) => return Err(format!("HTTP {status}: {}", preview(&body))),
            // A timeout already consumed the full attempt budget; spending it again
            // is not a retry, it is paying twice. This matters in `purge_retry`, which
            // walks rows serially: 5s + 0.1s + 5s per unreachable node turned a 15 s
            // cycle into minutes of continuous work.
            Err(e) if is_timeout(&e) => return Err(e),
            Err(e) if attempt + 1 < ATTEMPTS => last = e,
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(if last.is_empty() {
        "callback failed".into()
    } else {
        last
    })
}

/// Same as `request_json`, but with a caller-supplied deadline and no retry.
/// Cache diagnostics may legitimately wait for a slow origin/range probe.
pub async fn request_json_timeout<T: DeserializeOwned, B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
    timeout: Duration,
) -> Result<T, String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let (status, response) = send_once_timeout(method, url, bytes, token, timeout).await?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {}", preview(&response)));
    }
    serde_json::from_slice(&response).map_err(|e| format!("invalid callback JSON from {url}: {e}"))
}

/// Which address policy a tenant-supplied destination is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicDestination {
    /// Alert channels and cache-probe fallbacks: public addresses only.
    Internet,
    /// Origin diagnostics: private ranges are legitimate, loopback is not.
    OriginProbe,
}

impl PublicDestination {
    /// The guard predicate for this destination class.
    pub fn policy(self) -> fn(IpAddr) -> bool {
        match self {
            PublicDestination::Internet => net_guard::is_public_ip,
            PublicDestination::OriginProbe => net_guard::is_probeable_ip,
        }
    }

    /// How the guard names this destination in its rejection message.
    pub fn label(self) -> &'static str {
        match self {
            PublicDestination::Internet => "destination",
            PublicDestination::OriginProbe => "origin",
        }
    }
}

/// A guarded transport, one per address policy.
fn public_client(kind: PublicDestination) -> &'static PublicClient {
    static INTERNET: OnceLock<PublicClient> = OnceLock::new();
    static ORIGIN_PROBE: OnceLock<PublicClient> = OnceLock::new();
    match kind {
        PublicDestination::Internet => {
            INTERNET.get_or_init(|| build_public_client(kind.policy(), kind.label()))
        }
        PublicDestination::OriginProbe => {
            ORIGIN_PROBE.get_or_init(|| build_public_client(kind.policy(), kind.label()))
        }
    }
}

/// Public callback helper for alert notifications. The caller supplies all
/// headers; this does not attach an edge agent token.
pub async fn post_json_with_headers<B: Serialize>(
    url: &str,
    body: &B,
    headers: &[(&str, &str)],
) -> Result<(u16, Bytes), String> {
    let kind = PublicDestination::Internet;
    // Every HTTP client skips DNS when the URI host is already an IP literal, so
    // the guarded resolver alone would never see `http://169.254.169.254/`.
    net_guard::check_target(url, kind.policy(), kind.label())?;
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut builder = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(bytes))
        .map_err(|e| format!("build notification request {url}: {e}"))?;
    let response = tokio::time::timeout(Duration::from_secs(10), public_client(kind).request(req))
        .await
        .map_err(|_| format!("notification timeout: {url}"))?
        .map_err(|e| format!("notification transport error {url}: {}", describe(&e)))?;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("notification body error {url}: {e}"))?
        .to_bytes();
    Ok((status, body))
}

/// Maximum body bytes collected for diagnostic requests (64 KiB).
/// Prevents large streaming responses (e.g. video files) from exhausting memory.
pub const MAX_DIAGNOSTIC_BODY_BYTES: usize = 64 * 1024;

/// Diagnostic GET: returns status/headers/body for cache troubleshooting.
///
/// Body consumption is capped at [`MAX_DIAGNOSTIC_BODY_BYTES`] (64 KiB).  Large
/// responses (video streams, downloads, etc.) are truncated rather than buffered
/// whole, preventing OOM in the control plane.
pub async fn get_response(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, HeaderMap, Bytes), String> {
    get_response_limited(url, headers, MAX_DIAGNOSTIC_BODY_BYTES).await
}

/// Diagnostic GET with an explicit cap on how many body bytes are buffered.
pub async fn get_response_limited(
    url: &str,
    headers: &[(&str, &str)],
    max_bytes: usize,
) -> Result<(u16, HeaderMap, Bytes), String> {
    use http_body_util::BodyExt as _;

    let kind = PublicDestination::Internet;
    net_guard::check_target(url, kind.policy(), kind.label())?;
    let mut builder = Request::builder().method("GET").uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("build diagnostic request: {e}"))?;
    let response = tokio::time::timeout(Duration::from_secs(15), public_client(kind).request(req))
        .await
        .map_err(|_| "diagnostic request timed out".to_string())?
        .map_err(|e| format!("diagnostic request failed: {}", describe(&e)))?;
    let status = response.status().as_u16();
    let resp_headers = response.headers().clone();

    // Stream frames up to `max_bytes`; drop the rest to avoid OOM. The read
    // loop also has its own deadline: a malicious origin can send headers and
    // then stall forever, which the request timeout above does not cover.
    let mut body = response.into_body();
    let mut buf: Vec<u8> = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if buf.len() >= max_bytes {
                break;
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let take = data.len().min(max_bytes.saturating_sub(buf.len()));
                        buf.extend_from_slice(&data[..take]);
                    }
                }
                Some(Err(e)) => return Err(format!("diagnostic body error: {e}")),
                None => break,
            }
        }
        Ok::<(), String>(())
    })
    .await;
    match read {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("diagnostic body timed out".into()),
    }
    Ok((status, resp_headers, Bytes::from(buf)))
}

/// Render an error together with its `source` chain.
///
/// A guarded connector refuses a disallowed address by *failing the resolution*,
/// and hyper keeps that reason in `source()`. `Display` alone reduces it to
/// `client error (Connect)`, which hides why the request never left the host and
/// makes a security refusal indistinguishable from an unreachable server.
fn describe(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

/// Maximum concurrent Control → Edge fan-outs.
///
/// Cluster fan-outs used to run as a serial `for` loop, so wall-clock time was the
/// *sum* of every node's latency. With a 5 s attempt timeout and one retry, a few
/// weak or unreachable nodes blocked a certificate issuance for 10 s each while
/// holding the HTTP request open — which is how a 20-node cluster produced gateway
/// timeouts. Fanning out in parallel turns that sum into roughly the slowest
/// single node.
///
/// The bound exists for the opposite failure: an unbounded `join_all` would open
/// one socket per node at once, turning a certificate rollout into a connection
/// burst. 16 matches the purge path, so both fan-outs follow one documented
/// concurrency policy.
pub const EDGE_FANOUT_CONCURRENCY: usize = 16;

/// A node detached from its repository row so it can move into a task.
#[derive(Clone, Debug)]
pub struct OwnedNode {
    pub name: String,
    pub agent_url: String,
    /// Per-node token, already resolved to the global one when the node has none.
    pub token: String,
}

impl OwnedNode {
    /// `{agent_url}{path}`, with the trailing slash of `agent_url` normalised away.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.agent_url.trim_end_matches('/'), path)
    }
}

/// Detach repository node rows into fan-out targets.
///
/// Resolves each node's token once here — the per-node token, falling back to the
/// shared `AGENT_TOKEN` when the node has none — so the request builders below do
/// not repeat that decision in four places.
pub fn owned_nodes(nodes: &[crate::repository::NodeRow], global_token: &str) -> Vec<OwnedNode> {
    nodes
        .iter()
        .map(|node| OwnedNode {
            name: node.name.clone(),
            agent_url: node.agent_url.trim_end_matches('/').to_string(),
            token: if node.auth_token.is_empty() {
                global_token.to_string()
            } else {
                node.auth_token.clone()
            },
        })
        .collect()
}

/// Run `send` against every node with bounded concurrency.
///
/// Returns `(succeeded, failures)`, each failure carrying the node name and error
/// for the caller's log line. Every node is attempted even when an earlier one
/// fails: one unreachable edge must not stop the rest of the fleet from receiving
/// a certificate or a challenge. That property is what the serial loop got right
/// and the fix has to preserve.
pub async fn fan_out_edge<F, Fut>(nodes: &[OwnedNode], send: F) -> (u32, Vec<(String, String)>)
where
    F: Fn(OwnedNode) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    if nodes.is_empty() {
        return (0, Vec::new());
    }

    // `send` is shared across tasks rather than cloned per node: the callers pass
    // a closure, which is not `Clone`. Wrapping it in `Arc` keeps one copy.
    let send = Arc::new(send);
    let semaphore = Arc::new(Semaphore::new(EDGE_FANOUT_CONCURRENCY.min(nodes.len())));
    let mut set = JoinSet::new();

    for (index, node) in nodes.iter().enumerate() {
        let node = node.clone();
        let send = send.clone();
        let semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    return (
                        index,
                        node.name.clone(),
                        Err("fan-out gate closed".to_string()),
                    );
                }
            };
            let name = node.name.clone();
            (index, name, send(node).await)
        });
    }

    let mut results: Vec<(usize, String, Result<(), String>)> = Vec::with_capacity(nodes.len());
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(item) => results.push(item),
            // A panicking worker must not leave the caller waiting on a
            // `join_next` that will never yield again.
            Err(error) => tracing::error!(error = %error, "edge fan-out worker failed"),
        }
    }
    // Stable ordering keeps counts and logs deterministic across runs.
    results.sort_by_key(|(index, _, _)| *index);

    let mut ok = 0u32;
    let mut failures = Vec::new();
    for (_, name, result) in results {
        match result {
            Ok(()) => ok += 1,
            Err(e) => failures.push((name, e)),
        }
    }
    (ok, failures)
}

fn preview(bytes: &Bytes) -> String {
    String::from_utf8_lossy(bytes).chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    #[tokio::test]
    async fn caps_diagnostic_body_at_limit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    // Serve a 1 MiB body; the client must truncate it at 1024 bytes.
                    let large = vec![b'X'; 1024 * 1024];
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        large.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&large);
                });
            }
        });

        let url = format!("http://127.0.0.1:{port}/large");
        let (status, _hdrs, body) = get_response_limited(&url, &[], 1024).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.len(), 1024, "body must be capped at 1024 bytes");
    }

    #[tokio::test]
    async fn retries_a_transient_5xx_once() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = attempts.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let n = attempts_srv.fetch_add(1, Ordering::Relaxed) + 1;
                let mut stream = stream;
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let (status, body) = if n == 1 {
                        ("500 Internal Server Error", "temporary")
                    } else {
                        ("200 OK", "{}")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });

        let url = format!("http://127.0.0.1:{port}/__lagran/config/reload");
        post_json_ok(&url, &serde_json::json!({}), "token")
            .await
            .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    /// `HttpConnector` rejects non-`http` schemes unless told otherwise, and the
    /// outer `HttpsConnector` is the component that owns scheme selection. If this
    /// regresses, every `https://` agent callback fails with
    /// "invalid URL, scheme is not http" — a latent bug that only the plain-http
    /// integration fixtures hid.
    #[tokio::test]
    async fn https_agent_urls_reach_the_transport_not_a_scheme_check() {
        let err = post_json_ok(
            "https://127.0.0.1:1/__lagran/config/reload",
            &serde_json::json!({}),
            "t",
        )
        .await
        .unwrap_err();
        assert!(
            !err.contains("scheme is not http"),
            "the connector rejected https before dialling: {err}"
        );
        assert!(err.contains("transport error"), "{err}");
    }

    /// PERF-NEW-02: a cluster fan-out must cost roughly the slowest node, not the
    /// sum of every node.
    ///
    /// The serial loop this replaced made wall-clock time additive, so a handful of
    /// weak edges blocked certificate issuance for 10 s each (5 s attempt + retry)
    /// while the HTTP request stayed open. Here every node sleeps for the same
    /// fixed delay; a serial implementation needs N times that delay.
    #[tokio::test]
    async fn fan_out_does_not_serialise_across_nodes() {
        const NODES: usize = 8;
        const DELAY_MS: u64 = 150;

        let nodes: Vec<OwnedNode> = (0..NODES)
            .map(|i| OwnedNode {
                name: format!("edge-{i}"),
                agent_url: format!("http://127.0.0.1:{}", 20_000 + i),
                token: "t".into(),
            })
            .collect();

        let started = Instant::now();
        let (ok, failures) = fan_out_edge(&nodes, |_node| async move {
            tokio::time::sleep(Duration::from_millis(DELAY_MS)).await;
            Ok(())
        })
        .await;
        let elapsed = started.elapsed();

        assert_eq!(ok as usize, NODES);
        assert!(failures.is_empty());
        // Serially this would be N * 150 ms = 1200 ms. All eight fit within the
        // bound, so anything near the serial sum means the fan-out regressed to a
        // loop.
        let budget = Duration::from_millis(DELAY_MS * 4);
        assert!(
            elapsed < budget,
            "fan-out took {elapsed:?} for {NODES} nodes of {DELAY_MS}ms, budget {budget:?}"
        );
    }

    /// One unreachable node must not stop the rest of the fleet.
    ///
    /// The serial loop got this right, so the fix has to keep it: partial failure
    /// is counted, not fatal.
    #[tokio::test]
    async fn one_failing_node_does_not_block_the_others() {
        let nodes: Vec<OwnedNode> = (0..6)
            .map(|i| OwnedNode {
                name: format!("edge-{i}"),
                agent_url: "http://127.0.0.1:1".into(),
                token: "t".into(),
            })
            .collect();

        let (ok, failures) = fan_out_edge(&nodes, |node| async move {
            if node.name == "edge-2" {
                Err("simulated failure".to_string())
            } else {
                Ok(())
            }
        })
        .await;

        assert_eq!(ok, 5, "every healthy node must still be attempted");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "edge-2");
    }

    /// The concurrency bound must hold even when the fleet is far larger.
    ///
    /// An unbounded join would open one socket per node at once, turning a
    /// certificate rollout into a connection burst. This counts peak concurrency.
    #[tokio::test]
    async fn concurrency_is_bounded() {
        use std::sync::atomic::AtomicUsize;

        const NODES: usize = 64;
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let nodes: Vec<OwnedNode> = (0..NODES)
            .map(|i| OwnedNode {
                name: format!("edge-{i}"),
                agent_url: "http://127.0.0.1:1".into(),
                token: "t".into(),
            })
            .collect();

        let in_flight_task = in_flight.clone();
        let peak_task = peak.clone();
        let (ok, _) = fan_out_edge(&nodes, move |_node| {
            let in_flight = in_flight_task.clone();
            let peak = peak_task.clone();
            async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

        assert_eq!(ok as usize, NODES);
        let peak = peak.load(Ordering::SeqCst);
        assert!(
            peak <= EDGE_FANOUT_CONCURRENCY,
            "peak concurrency {peak} exceeded the bound {EDGE_FANOUT_CONCURRENCY}"
        );
        assert!(
            peak > 1,
            "concurrency was {peak}: the fan-out ran nothing in parallel"
        );
    }

    /// An empty fleet is not an error.
    #[tokio::test]
    async fn empty_fleet_is_a_no_op() {
        let (ok, failures) = fan_out_edge(&[], |_node| async move { Ok(()) }).await;
        assert_eq!(ok, 0);
        assert!(failures.is_empty());
    }

    /// SEC-NEW-01 regression: the metadata range is refused before a socket is
    /// opened, and the guard sits in the request path rather than in a
    /// pre-flight check a caller could forget to repeat.
    #[tokio::test]
    async fn tenant_urls_cannot_reach_internal_literals() {
        // Loopback stays exempt in `cfg(test)` so the mock-server tests above can
        // run; the metadata range is the real SSRF target and is never exempt.
        let url = "http://169.254.169.254/latest/meta-data";
        let err = post_json_with_headers(url, &serde_json::json!({}), &[])
            .await
            .unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");

        let err = get_response(url, &[]).await.unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");
    }
}
