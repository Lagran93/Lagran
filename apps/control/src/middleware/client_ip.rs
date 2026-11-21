//! Resolve the real client IP from a trusted reverse-proxy chain.
//!
//! `X-Forwarded-For` is client-controlled on a direct connection and can be
//! spoofed on every request. Only headers received from a configured trusted
//! proxy may influence the key used by login/register rate limiting. The
//! rightmost untrusted hop wins, so a client cannot prepend a fake address to
//! the proxy-appended chain.

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let (ip_raw, prefix_raw) = match raw.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (raw, None),
        };
        let base = normalize(ip_raw.parse::<IpAddr>().ok()?);
        let max_prefix = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_raw {
            Some(prefix) => prefix.parse::<u8>().ok()?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return None;
        }
        Some(Self { base, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, normalize(ip)) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(base) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(base) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Cached set of proxy networks trusted for forwarded-IP headers.
pub struct ClientIpResolver {
    trusted: Vec<Cidr>,
}

impl ClientIpResolver {
    /// Parse `TRUSTED_PROXIES`. Invalid entries are ignored (fail closed): a
    /// typo must never make an unexpected peer trusted.
    pub fn from_config(entries: &[String]) -> Self {
        let mut trusted = Vec::with_capacity(entries.len());
        for entry in entries {
            match Cidr::parse(entry) {
                Some(cidr) => trusted.push(cidr),
                None => tracing::warn!(entry, "ignoring invalid TRUSTED_PROXIES entry"),
            }
        }
        Self { trusted }
    }

    /// Resolve using the socket peer. Headers are ignored unless the peer is a
    /// configured trusted proxy.
    pub fn resolve(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        self.resolve_ip(peer.ip(), headers)
    }

    /// Same as [`Self::resolve`] for callers that already have an [`IpAddr`].
    pub fn resolve_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = normalize(peer);
        // No socket peer (e.g. a router test without connect info): fail closed
        // rather than trusting an unauthenticated header.
        if peer.is_unspecified() || !self.is_trusted(peer) {
            return peer;
        }

        let mut forwarded = Vec::new();
        for value in headers.get_all("x-forwarded-for").iter() {
            let Ok(value) = value.to_str() else {
                continue;
            };
            for part in value.split(',') {
                if let Some(ip) = parse_ip(part) {
                    let ip = normalize(ip);
                    if !ip.is_unspecified() {
                        forwarded.push(ip);
                    }
                }
            }
        }

        // Walk from the nearest proxy towards the client. The first untrusted
        // address is the only one the trusted proxies actually appended.
        for ip in forwarded.iter().rev() {
            if !self.is_trusted(*ip) {
                return *ip;
            }
        }

        // `X-Real-IP` is a common Caddy/Nginx single-value form. It is only
        // consulted after the trusted peer check above.
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_ip)
        {
            let ip = normalize(ip);
            if !ip.is_unspecified() {
                return ip;
            }
        }

        // Every forwarded hop was trusted (or the header was absent). Falling
        // back to the leftmost value still gives a stable key; if there was no
        // header at all, use the peer.
        forwarded.first().copied().unwrap_or(peer)
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|cidr| cidr.contains(ip))
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn parse_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    // Bracketed IPv6 without a port.
    raw.trim_matches(['[', ']']).parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::Ipv4Addr;

    fn resolver() -> ClientIpResolver {
        ClientIpResolver::from_config(&["127.0.0.1".into(), "::1".into(), "10.0.0.0/8".into()])
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn headers(xff: Option<&str>, real: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = xff {
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("valid test header"),
            );
        }
        if let Some(value) = real {
            headers.insert(
                "x-real-ip",
                HeaderValue::from_str(value).expect("valid test header"),
            );
        }
        headers
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        let resolver = resolver();
        let peer = ip("198.51.100.7");
        let headers = headers(Some("203.0.113.9"), Some("203.0.113.10"));
        assert_eq!(resolver.resolve_ip(peer, &headers), peer);
    }

    #[test]
    fn trusted_peer_uses_the_rightmost_untrusted_hop() {
        let resolver = resolver();
        let headers = headers(Some("1.1.1.1, 198.51.100.7, 10.1.2.3"), None);
        assert_eq!(
            resolver.resolve_ip(ip("127.0.0.1"), &headers),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn trusted_chain_skips_every_trusted_proxy() {
        let resolver = resolver();
        let headers = headers(Some("203.0.113.9, 10.1.2.3"), None);
        assert_eq!(
            resolver.resolve_ip(ip("127.0.0.1"), &headers),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn x_real_ip_is_only_used_from_a_trusted_peer() {
        let resolver = resolver();
        let spoofed = headers(None, Some("203.0.113.9"));
        assert_eq!(
            resolver.resolve_ip(ip("198.51.100.7"), &spoofed),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolver.resolve_ip(ip("127.0.0.1"), &spoofed),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn missing_headers_fall_back_to_the_peer() {
        let resolver = resolver();
        let headers = HeaderMap::new();
        assert_eq!(
            resolver.resolve_ip(ip("127.0.0.1"), &headers),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn malformed_headers_fall_back_to_the_peer() {
        let resolver = resolver();
        let headers = headers(Some("not-an-ip"), None);
        assert_eq!(
            resolver.resolve_ip(ip("127.0.0.1"), &headers),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_loopback_is_recognized() {
        let resolver = resolver();
        let headers = headers(Some("203.0.113.9"), None);
        assert_eq!(
            resolver.resolve_ip(ip("::ffff:127.0.0.1"), &headers),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn unspecified_peer_never_trusts_headers() {
        let resolver = resolver();
        let headers = headers(Some("203.0.113.9"), None);
        assert_eq!(
            resolver.resolve_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &headers),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn cidr_matching_respects_the_prefix() {
        let resolver = resolver();
        let headers = headers(Some("203.0.113.9"), None);
        assert_eq!(
            resolver.resolve_ip(ip("10.9.8.7"), &headers),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolver.resolve_ip(ip("11.9.8.7"), &headers),
            ip("11.9.8.7")
        );
    }

    #[test]
    fn invalid_trusted_entries_are_ignored() {
        let resolver = ClientIpResolver::from_config(&[
            "not-an-ip".into(),
            "10.0.0.0/33".into(),
            "2001:db8::/129".into(),
        ]);
        let headers = headers(Some("203.0.113.9"), None);
        assert_eq!(
            resolver.resolve_ip(ip("10.0.0.1"), &headers),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv6_cidr_is_supported() {
        let resolver = ClientIpResolver::from_config(&["2001:db8::/32".into()]);
        let headers = headers(Some("203.0.113.9"), None);
        assert_eq!(
            resolver.resolve_ip(ip("2001:db8::1"), &headers),
            ip("203.0.113.9")
        );
    }
}
