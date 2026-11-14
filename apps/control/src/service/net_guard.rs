//! Outbound-connection guard for tenant-controlled URLs and hosts.
//!
//! Alert channels and domain diagnostics let a tenant choose the destination of
//! a control-plane connection. Without a guard that turns the control plane into
//! an SSRF proxy: an authenticated user can point a webhook at the cloud metadata
//! service or scan the control host's loopback ports.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

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

async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("empty host".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let lookup = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "dns lookup timed out".to_string())?
        .map_err(|e| format!("dns lookup failed: {e}"))?;
    let ips: Vec<IpAddr> = lookup.map(|addr| addr.ip()).collect();
    if ips.is_empty() {
        return Err("host did not resolve".into());
    }
    Ok(ips)
}

/// Resolve a host and require every address to pass `allowed`.
async fn resolve_checked(
    host: &str,
    port: u16,
    allowed: fn(IpAddr) -> bool,
    label: &str,
) -> Result<(), String> {
    let ips = resolve(host, port).await?;
    // Unit tests exercise the transports against 127.0.0.1 mock servers; that
    // bypass only exists in the `cfg(test)` build of this library, never in the
    // shipped binary or the integration-test build.
    let permitted = |ip: &std::net::IpAddr| allowed(*ip) || (cfg!(test) && ip.is_loopback());
    if let Some(bad) = ips.iter().find(|ip| !permitted(ip)) {
        return Err(format!("{label} resolves to a disallowed address ({bad})"));
    }
    Ok(())
}

/// Validate an HTTP(S) URL used by a tenant-supplied alert channel.
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
    resolve_checked(host, port, is_public_ip, "alert destination").await
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
    resolve_checked(host, port, is_public_ip, "proxy").await
}

/// Validate an SMTP host before a notification email is sent.
pub async fn validate_smtp_host(host: &str, port: u16) -> Result<(), String> {
    resolve_checked(host, port, is_public_ip, "smtp host").await
}

/// Validate a tenant-configured origin before the control plane probes it.
/// Private ranges are allowed; loopback/link-local/metadata are not.
pub async fn validate_origin_probe(host: &str, port: u16) -> Result<(), String> {
    resolve_checked(host, port, is_probeable_ip, "origin").await
}

#[cfg(test)]
mod tests {
    use super::{is_probeable_ip, is_public_ip};
    use std::net::IpAddr;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
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
}
