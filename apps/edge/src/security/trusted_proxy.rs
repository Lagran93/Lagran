//! Trusted reverse-proxy handling for client IP and request scheme.
//!
//! `X-Forwarded-For` and `X-Forwarded-Proto` are attacker-controlled strings. A
//! client talking directly to the edge can set them freely, so trusting them
//! unconditionally let anyone spoof their source IP (bypassing WAF IP deny
//! lists and CC bans) and claim `https` on a plaintext connection (bypassing the
//! HTTPS redirect and getting `Secure` challenge cookies that never arrive).
//!
//! The rule implemented here is the standard one for a proxy chain:
//!
//! * Walk `X-Forwarded-For` from the **right**. The rightmost entry was appended
//!   by the hop closest to us, so it is the only one we can reason about.
//! * Skip entries that are themselves trusted proxies; the first untrusted one
//!   is the real client.
//! * If nothing is trusted (or the list is exhausted), fall back to the socket
//!   peer address.
//! * Only honour `X-Forwarded-Proto` when the immediate peer is a trusted proxy.
//!
//! Both data planes call this, so they cannot disagree about who the client is.

use std::net::{IpAddr, SocketAddr};

/// A set of trusted proxy addresses and networks.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    /// Parse a comma-separated list such as `10.0.0.0/8, 192.168.1.5, ::1`.
    ///
    /// Returns an error naming the offending entry so a typo in
    /// `TRUSTED_PROXIES` fails at startup instead of silently trusting nothing.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for raw in spec.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            match IpNet::parse(entry) {
                Some(net) => nets.push(net),
                None => {
                    return Err(format!(
                        "invalid TRUSTED_PROXIES entry {entry:?}: expected an IP or CIDR"
                    ))
                }
            }
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }
}

#[derive(Debug, Clone, Copy)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(value: &str) -> Option<Self> {
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let addr: IpAddr = addr.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => {
                let p: u8 = p.trim().parse().ok()?;
                if p > max {
                    return None;
                }
                p
            }
            None => max,
        };
        Some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let prefix = self.prefix as u32;
                if prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let prefix = self.prefix as u32;
                if prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            // Never treat a v4 address as matching a v6 network.
            _ => false,
        }
    }
}

/// Result of resolving the client identity for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Best-effort client address, or `None` when nothing could be parsed.
    pub ip: Option<IpAddr>,
    /// Whether this request arrived over TLS, after accounting for trusted hops.
    pub is_https: bool,
    /// True when `X-Forwarded-For` was accepted because the peer is trusted.
    pub trusted_chain: bool,
}

/// Resolve the client IP, chain and scheme for a request.
///
/// `peer` is the socket address the connection came from. `xff` is the raw
/// `X-Forwarded-For` header value. `xfp` is the raw `X-Forwarded-Proto` value.
/// `tls_terminated` records whether *we* terminated TLS on this connection.
pub fn resolve(
    trusted: &TrustedProxies,
    peer: Option<SocketAddr>,
    xff: Option<&str>,
    xfp: Option<&str>,
    tls_terminated: bool,
) -> ClientIdentity {
    let peer_ip = peer.map(|addr| addr.ip());
    // Without a trusted peer we cannot attribute any forwarded value.
    let peer_is_trusted = peer_ip.is_some_and(|ip| trusted.contains(ip));
    if !peer_is_trusted {
        return ClientIdentity {
            ip: peer_ip,
            is_https: tls_terminated,
            trusted_chain: false,
        };
    }

    let client_ip = xff
        .and_then(|value| client_from_chain(trusted, value))
        .or(peer_ip);

    // A trusted proxy terminating TLS tells us the original scheme. Anything
    // other than an explicit `https` is treated as plaintext.
    let is_https = match xfp.map(str::trim) {
        Some(proto) if !proto.is_empty() => proto.eq_ignore_ascii_case("https"),
        _ => tls_terminated,
    };

    ClientIdentity {
        ip: client_ip,
        is_https,
        trusted_chain: true,
    }
}

/// Pick the real client out of an `X-Forwarded-For` list.
///
/// Entries are separated by commas and ordered client-first. We walk from the
/// right, discarding our own trusted proxies, and take the first address that is
/// not trusted. If every entry is trusted (or the list is malformed) we return
/// the rightmost address we could parse: it is the closest hop we can see.
fn client_from_chain(trusted: &TrustedProxies, value: &str) -> Option<IpAddr> {
    let mut parsed: Vec<IpAddr> = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Tolerate `1.2.3.4:5678` and `[::1]:5678` by stripping a trailing port.
        let candidate = part
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty())
            .map(|(host, _)| host.trim_matches(|c| c == '[' || c == ']'))
            .unwrap_or(part);
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            parsed.push(ip);
        }
    }
    if parsed.is_empty() {
        return None;
    }
    // Rightmost non-trusted address is the client.
    for ip in parsed.iter().rev() {
        if !trusted.contains(*ip) {
            return Some(*ip);
        }
    }
    parsed.last().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_list() -> TrustedProxies {
        TrustedProxies::parse("10.0.0.0/8, 192.168.1.5, ::1").unwrap()
    }

    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:12345").parse().unwrap()
    }

    #[test]
    fn parses_cidrs_and_bare_ips() {
        let t = proxy_list();
        assert!(t.contains("10.1.2.3".parse().unwrap()));
        assert!(t.contains("192.168.1.5".parse().unwrap()));
        assert!(!t.contains("192.168.1.6".parse().unwrap()));
        assert!(t.contains("::1".parse().unwrap()));
        assert!(TrustedProxies::parse("").unwrap().is_empty());
        assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxies::parse("not-an-ip").is_err());
    }

    /// A client connecting directly must not be able to spoof its address.
    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_for() {
        let id = resolve(
            &proxy_list(),
            Some(peer("203.0.113.9")),
            Some("1.2.3.4"),
            Some("https"),
            false,
        );
        assert_eq!(id.ip, Some("203.0.113.9".parse().unwrap()));
        assert!(!id.is_https, "plaintext connection stays plaintext");
        assert!(!id.trusted_chain);
    }

    /// The leftmost entry is client-supplied; the rightmost is appended by the
    /// hop closest to us and is the only trustworthy one.
    #[test]
    fn takes_rightmost_untrusted_hop() {
        let id = resolve(
            &proxy_list(),
            Some(peer("10.0.0.7")),
            Some("1.2.3.4, 203.0.113.9, 10.0.0.7"),
            None,
            false,
        );
        assert_eq!(id.ip, Some("203.0.113.9".parse().unwrap()));
        assert!(id.trusted_chain);
    }

    #[test]
    fn spoofed_left_entry_is_ignored() {
        // Attacker sends `X-Forwarded-For: 1.2.3.4`; the trusted proxy appends
        // the real address on the right.
        let id = resolve(
            &proxy_list(),
            Some(peer("10.0.0.7")),
            Some("1.2.3.4, 198.51.100.20"),
            None,
            false,
        );
        assert_eq!(id.ip, Some("198.51.100.20".parse().unwrap()));
    }

    #[test]
    fn trusted_proto_is_honoured_only_from_trusted_peer() {
        let trusted = resolve(
            &proxy_list(),
            Some(peer("10.0.0.7")),
            None,
            Some("https"),
            false,
        );
        assert!(trusted.is_https);

        let untrusted = resolve(
            &proxy_list(),
            Some(peer("203.0.113.9")),
            None,
            Some("https"),
            false,
        );
        assert!(!untrusted.is_https);
    }

    #[test]
    fn direct_tls_is_https_without_forwarded_proto() {
        let id = resolve(&proxy_list(), Some(peer("203.0.113.9")), None, None, true);
        assert!(id.is_https);
    }

    #[test]
    fn empty_configuration_trusts_nobody() {
        let t = TrustedProxies::default();
        let id = resolve(&t, Some(peer("10.0.0.7")), Some("1.2.3.4"), Some("https"), false);
        assert_eq!(id.ip, Some("10.0.0.7".parse().unwrap()));
        assert!(!id.is_https);
        assert!(!id.trusted_chain);
    }

    #[test]
    fn tolerates_ports_and_ipv6_brackets() {
        let id = resolve(
            &proxy_list(),
            Some(peer("10.0.0.7")),
            Some("198.51.100.20:4433, [2001:db8::1]:80"),
            None,
            false,
        );
        assert_eq!(id.ip, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn mixed_family_never_matches() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert!(!t.contains("::ffff:10.0.0.1".parse().unwrap()));
    }
}
