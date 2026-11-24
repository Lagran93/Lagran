//! Outbound-connection guard for tenant-controlled URLs and hosts.
//!
//! Alert channels and domain diagnostics let a tenant choose the destination of
//! a control-plane connection. Without a guard that turns the control plane into
//! an SSRF proxy: an authenticated user can point a webhook at the cloud metadata
//! service or scan the control host's loopback ports.
//!
//! # Why the policy lives in the resolver
//!
//! Resolving a name and *then* handing that name to an HTTP client is a
//! time-of-check-to-time-of-use bug. Hyper/Reqwest/lettre resolve the name
//! themselves when they open the socket, so an attacker running their own
//! authoritative DNS server (TTL=0, alternating answers) can return a public
//! address for the pre-flight check and `127.0.0.1` or `169.254.169.254` a few
//! milliseconds later for the connection.
//!
//! The fix is to make the check and the connect share one answer. Every
//! transport therefore resolves *once*, filters that exact address list, and
//! dials only the addresses that came back:
//!
//! * [`GuardedResolver`] and [`GuardedDns`] plug into `hyper_util` and `reqwest`,
//!   so the address that is checked is the address that is connected.
//! * [`resolve_smtp_host`], [`resolve_origin_probe`] and [`connect_any`] hand
//!   validated `SocketAddr`s to callers that open sockets themselves (SMTP, TCP
//!   probes, TLS diagnostics).
//! * [`check_target`] covers the remaining hole: both clients skip DNS entirely
//!   when the URI host is already an IP literal, so the resolver never sees
//!   `http://169.254.169.254/`. The literal *is* the connect target, so checking
//!   it cannot race DNS.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tower::Service;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether an address may be contacted by a tenant-supplied channel.
///
/// Alert destinations must be public: loopback, link-local (metadata services),
/// private, CGNAT, multicast, unspecified and documentation ranges are refused.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast())
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 100.64.0.0/10 carrier-grade NAT.
    let cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || cgnat)
}

/// Addresses rejected for origin diagnostics. Private ranges are allowed here:
/// a self-hosted origin behind the operator's network is a legitimate setup.
pub fn is_probeable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_probeable_ip(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || v6.is_multicast())
        }
    }
}

/// Whether `ip` may be contacted under `policy`.
///
/// Unit tests drive the transports against 127.0.0.1 mock servers, so a loopback
/// exemption is compiled in — but only for the `cfg(test)` build of this
/// library, never for the shipped binary or the integration-test build.
#[inline]
fn permitted(policy: fn(IpAddr) -> bool, ip: IpAddr) -> bool {
    policy(ip) || (cfg!(test) && ip.is_loopback())
}

/// The single DNS lookup used by this module.
async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("empty host".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let lookup = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "dns lookup timed out".to_string())?
        .map_err(|e| format!("dns lookup failed: {e}"))?;
    let addrs: Vec<SocketAddr> = lookup.collect();
    if addrs.is_empty() {
        return Err("host did not resolve".into());
    }
    Ok(addrs)
}

/// Apply `policy` to a resolved address list and return exactly the approved
/// addresses.
///
/// Returning the list instead of `()` is the point of this module: callers
/// connect to *these* addresses, so a second, different DNS answer from a
/// rebinding server is never consulted.
fn filter_allowed(
    addrs: Vec<SocketAddr>,
    policy: fn(IpAddr) -> bool,
    label: &str,
) -> Result<Vec<SocketAddr>, String> {
    if let Some(bad) = addrs.iter().find(|addr| !permitted(policy, addr.ip())) {
        return Err(format!(
            "{label} resolves to a disallowed address ({})",
            bad.ip()
        ));
    }
    Ok(addrs)
}

/// Resolve `host` once and return only addresses that pass `policy`.
///
/// Callers must connect to the returned `SocketAddr`s rather than re-resolving
/// `host`; that is what closes the DNS-rebinding window.
pub async fn resolve_allowed(
    host: &str,
    port: u16,
    policy: fn(IpAddr) -> bool,
    label: &str,
) -> Result<Vec<SocketAddr>, String> {
    filter_allowed(lookup(host, port).await?, policy, label)
}

/// Connect to the first reachable address in a pre-validated list.
///
/// Taking a `&[SocketAddr]` is deliberate: there is no name here to re-resolve,
/// so the socket goes to an address the guard already approved.
pub async fn connect_any(addrs: &[SocketAddr], timeout: Duration) -> Result<SocketAddr, String> {
    let mut last = String::from("no address to connect to");
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // Drop the probe connection: callers that need the stream build
                // their own; this exists to prove reachability of a checked IP.
                drop(stream);
                return Ok(*addr);
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "connect timed out".into(),
        }
    }
    Err(last)
}

/// Reject a URL whose host is an IP literal that fails `policy`.
///
/// Both HTTP clients short-circuit DNS for IP-literal hosts, which means the
/// guarded resolvers never run for `http://127.0.0.1:6379/` or
/// `http://169.254.169.254/`. The literal is the connect target, so validating
/// it here is exact and cannot be raced. Hostnames are left to the resolver,
/// which re-checks the answer at connect time.
pub fn check_target(url: &str, policy: fn(IpAddr) -> bool, label: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    let Some(host) = parsed.host_str() else {
        return Ok(());
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(ip) = host.parse::<IpAddr>() else {
        // A DNS name: the guarded resolver applies the policy when the socket
        // is opened, so there is nothing to check yet.
        return Ok(());
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    filter_allowed(vec![SocketAddr::new(ip, port)], policy, label).map(|_| ())
}

/// A `hyper_util` name resolver that enforces an address policy.
///
/// Install with [`hyper_util::client::legacy::connect::HttpConnector::new_with_resolver`].
/// The connector stamps the request's port onto the returned addresses, so this
/// resolves with port `0` just like the default resolver does.
#[derive(Clone, Copy, Debug)]
pub struct GuardedResolver {
    policy: fn(IpAddr) -> bool,
    label: &'static str,
}

impl GuardedResolver {
    pub const fn new(policy: fn(IpAddr) -> bool, label: &'static str) -> Self {
        Self { policy, label }
    }
}

impl Service<hyper_util::client::legacy::connect::dns::Name> for GuardedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = String;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, String>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        let host = name.as_str().to_string();
        let Self { policy, label } = *self;
        Box::pin(async move {
            let addrs = resolve_allowed(&host, 0, policy, label).await?;
            Ok(addrs.into_iter())
        })
    }
}

/// The same address policy as a `reqwest` resolver, for clients that need
/// features the shared hyper client does not expose (proxies, redirects).
#[derive(Clone, Copy, Debug)]
pub struct GuardedDns {
    policy: fn(IpAddr) -> bool,
    label: &'static str,
}

impl GuardedDns {
    pub const fn new(policy: fn(IpAddr) -> bool, label: &'static str) -> Self {
        Self { policy, label }
    }
}

impl reqwest::dns::Resolve for GuardedDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let Self { policy, label } = *self;
        Box::pin(async move {
            let addrs = resolve_allowed(&host, 0, policy, label)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Validate an HTTP(S) URL used by a tenant-supplied alert channel.
///
/// This is a fast, clear rejection for the console (`POST /alert-channels/:id/test`
/// surfaces the message). Enforcement itself happens in the transport, because
/// only the transport can guarantee that the checked address is the dialled one.
pub async fn validate_http_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("url scheme must be http or https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("credentials in the url are not allowed".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "url has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    resolve_allowed(host, port, is_public_ip, "alert destination")
        .await
        .map(|_| ())
}

/// Validate an optional proxy URL (http/https/socks5).
pub async fn validate_proxy_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid proxy url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https" | "socks5" | "socks5h") {
        return Err("proxy scheme must be http, https, socks5 or socks5h".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "proxy url has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(1080);
    resolve_allowed(host, port, is_public_ip, "proxy")
        .await
        .map(|_| ())
}

/// Resolve an SMTP host to the addresses the transport may connect to.
pub async fn resolve_smtp_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    resolve_allowed(host, port, is_public_ip, "smtp host").await
}

/// Validate a tenant-configured origin before the control plane probes it.
/// Private ranges are allowed; loopback/link-local/metadata are not.
pub async fn validate_origin_probe(host: &str, port: u16) -> Result<(), String> {
    resolve_origin_probe(host, port).await.map(|_| ())
}

/// Resolve a tenant-configured origin to the addresses that may be probed.
pub async fn resolve_origin_probe(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    resolve_allowed(host, port, is_probeable_ip, "origin").await
}

#[cfg(test)]
mod tests {
    use super::{
        check_target, filter_allowed, is_probeable_ip, is_public_ip, permitted, resolve_allowed,
    };
    use std::net::{IpAddr, SocketAddr};

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    fn addr(raw: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip(raw), port)
    }

    #[test]
    fn public_addresses_are_allowed() {
        for raw in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip(raw)), "{raw} should be public");
        }
    }

    #[test]
    fn private_metadata_and_loopback_are_rejected() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip(raw)), "{raw} must be rejected");
        }
    }

    #[test]
    fn origin_probe_allows_private_but_not_loopback_or_metadata() {
        assert!(is_probeable_ip(ip("10.1.2.3")));
        assert!(is_probeable_ip(ip("192.168.1.10")));
        assert!(!is_probeable_ip(ip("127.0.0.1")));
        assert!(!is_probeable_ip(ip("169.254.169.254")));
        assert!(!is_probeable_ip(ip("::1")));
    }

    #[test]
    fn checked_addresses_are_returned_unchanged() {
        // The whole point of the guard: the caller connects to the list that
        // was checked, not to a fresh lookup of the same name.
        let addrs = vec![addr("1.1.1.1", 443), addr("8.8.8.8", 443)];
        let checked = filter_allowed(addrs.clone(), is_public_ip, "alert destination").unwrap();
        assert_eq!(checked, addrs);
    }

    #[test]
    fn one_bad_address_rejects_the_whole_answer() {
        // A single private answer is enough for a rebinding server to win a
        // later connection attempt, so the name is refused outright.
        let addrs = vec![addr("1.1.1.1", 443), addr("169.254.169.254", 443)];
        let err = filter_allowed(addrs, is_public_ip, "alert destination").unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");
        assert!(err.contains("169.254.169.254"), "{err}");
    }

    #[test]
    fn private_and_link_local_answers_are_rejected() {
        for raw in ["10.1.2.3", "192.168.1.10", "169.254.169.254"] {
            let err = filter_allowed(vec![addr(raw, 80)], is_public_ip, "webhook").unwrap_err();
            assert!(err.contains(raw), "{err}");
        }
    }

    #[test]
    fn ip_literals_are_checked_before_any_request_is_built() {
        // The clients skip their resolver for these, so the literal check is the
        // only thing standing between a tenant and the metadata service.
        let err = check_target(
            "http://169.254.169.254/latest/meta-data",
            is_public_ip,
            "target",
        )
        .unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");
        // Link-local v6 is refused under both policies and in every build. (A
        // loopback literal is *not* a useful negative here: `permitted` exempts
        // loopback in `cfg(test)` so the mock-server tests can run.)
        assert!(check_target("http://[fe80::1]:8080/", is_public_ip, "target").is_err());
        assert!(check_target("http://[fe80::1]:8080/", is_probeable_ip, "target").is_err());

        // A DNS name is deferred to the resolver, which re-checks the answer.
        check_target("https://example.com/hook", is_public_ip, "target").unwrap();
        // A public literal is fine.
        check_target("https://1.1.1.1/hook", is_public_ip, "target").unwrap();
    }

    #[tokio::test]
    async fn resolving_a_literal_does_not_consult_dns() {
        let addrs = resolve_allowed("1.1.1.1", 8443, is_public_ip, "target")
            .await
            .unwrap();
        assert_eq!(addrs, vec![addr("1.1.1.1", 8443)]);
        // And the policy still applies to it.
        assert!(resolve_allowed("10.0.0.5", 80, is_public_ip, "target")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn connect_any_only_dials_pre_validated_addresses() {
        // A refused list never reaches the connector, so `connect_any` is only
        // ever handed addresses the policy already approved.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.is_ok() });
        let reached = super::connect_any(&[addr], std::time::Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(reached, addr);
        assert!(accepted.await.unwrap());
    }

    #[test]
    fn loopback_exemption_only_exists_in_test_builds() {
        // The exemption is what lets unit tests talk to 127.0.0.1 mock servers.
        // It must never be readable as a production policy, so assert the shape
        // here: `permitted` is the only place that grants it.
        assert_eq!(permitted(is_public_ip, ip("127.0.0.1")), cfg!(test));
        assert!(!permitted(is_public_ip, ip("169.254.169.254")));
    }
}
