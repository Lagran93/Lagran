//! CDN / Origin Shield loop detection.
//!
//! Every data-plane request is stamped with the node that forwarded it:
//!
//! ```text
//! CDN-Loop: lagran; id=edge-hk-01-3f9a1c22b71d4e50
//! X-Lagran-Shield-Hops: 1
//! ```
//!
//! The id carries a per-machine instance token (see
//! [`crate::config::identity`]) so two edges that share one `NODE_ID` can never
//! mistake each other for themselves.
//!
//! An edge rejects the request with 508 when it sees its own id, or when the
//! hop counter has already reached the limit. This catches misconfigured
//! Shield-to-Shield paths before they can spin between nodes.
//!
//! These headers are only meaningful between Lagran edges. A public client
//! could otherwise send `X-Lagran-Shield-Hops: 3` (or `CDN-Loop` naming a
//! guessable default node id) and have the edge, and then the Shield behind it,
//! answer 508 to the client's own traffic — a one-way denial of service, and
//! for cacheable URLs a way to keep the Shield from ever filling its cache.
//! [`guard`] therefore strips both headers from any peer that is not in
//! `TRUSTED_EDGES` before the guard runs; the counter a peer can influence is
//! then only the one this edge stamped itself.

use axum::http::{HeaderMap, HeaderValue};

pub const CDN_LOOP_HEADER: &str = "cdn-loop";
pub const SHIELD_HOPS_HEADER: &str = "x-lagran-shield-hops";
/// Maximum number of Lagran edges a request may traverse. The fourth edge that
/// receives an already-three-hop request answers 508.
pub const MAX_SHIELD_HOPS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopReason {
    /// The incoming `CDN-Loop` already names this node.
    SelfReference,
    /// The incoming hop counter is at or beyond [`MAX_SHIELD_HOPS`].
    TooManyHops,
}

impl LoopReason {
    /// Stable value for access logs / diagnostic headers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfReference => "loop-self",
            Self::TooManyHops => "loop-hops",
        }
    }
}

/// Check an incoming request. Headers are only trustworthy as a *loop hint*:
/// a client may add them to its own request, but it can only make that request
/// fail, not bypass routing.
pub fn detect(headers: &HeaderMap, node_id: &str) -> Option<LoopReason> {
    if !node_id.is_empty() && cdn_loop_contains_node(headers, node_id) {
        return Some(LoopReason::SelfReference);
    }
    if incoming_hops(headers) >= MAX_SHIELD_HOPS {
        return Some(LoopReason::TooManyHops);
    }
    None
}

/// Strip the internal loop headers from a request.
///
/// Both headers are removed, including repeated `CDN-Loop` lines: forwarding
/// only the first line was a previous bug in the origin path, and leaving a
/// second spoofed line here would re-open the same hole.
pub fn strip_internal(headers: &mut HeaderMap) {
    while headers.remove(CDN_LOOP_HEADER).is_some() {}
    while headers.remove(SHIELD_HOPS_HEADER).is_some() {}
}

/// Ingress guard for one request.
///
/// `trusted_peer` must be true only when the socket peer is a known
/// Edge/Shield interconnect (configured through `TRUSTED_EDGES`). For anything
/// else — a public client, a plain reverse proxy in front of the edge — the
/// loop headers are attacker-controlled input and are stripped before they can
/// influence either the 508 decision or the counter forwarded upstream.
pub fn guard(headers: &mut HeaderMap, node_id: &str, trusted_peer: bool) -> Option<LoopReason> {
    if !trusted_peer {
        strip_internal(headers);
    }
    detect(headers, node_id)
}

/// Pingora variant of [`strip_internal`].
pub fn strip_internal_pingora(request: &mut pingora::http::RequestHeader) {
    // `remove_header` drops every value under the name; the return value is
    // ignored because only the absence matters.
    let _ = request.remove_header(CDN_LOOP_HEADER);
    let _ = request.remove_header(SHIELD_HOPS_HEADER);
}

/// Pingora variant of [`guard`].
pub fn guard_pingora(
    request: &mut pingora::http::RequestHeader,
    node_id: &str,
    trusted_peer: bool,
) -> Option<LoopReason> {
    if !trusted_peer {
        strip_internal_pingora(request);
    }
    detect(&request.headers, node_id)
}

/// Add this node to the loop chain and advance the hop counter.
///
/// Called once, before the request can reach any origin path (native proxy,
/// legacy handler, revalidation, streaming, or cache diagnostics). Mutating the
/// downstream request means every existing origin builder already forwards the
/// headers without a second implementation.
pub fn stamp(headers: &mut HeaderMap, node_id: &str) {
    if !node_id.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&format!("lagran; id={node_id}")) {
            headers.append(CDN_LOOP_HEADER, value);
        }
    }
    let next = incoming_hops(headers).saturating_add(1);
    if let Ok(value) = HeaderValue::from_str(&next.to_string()) {
        headers.insert(SHIELD_HOPS_HEADER, value);
    }
}

/// Pingora's `RequestHeader` is not a `HeaderMap` and needs its own insert
/// methods. Kept next to [`stamp`] so both planes use the same values.
pub fn stamp_pingora(request: &mut pingora::http::RequestHeader, node_id: &str) {
    if !node_id.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&format!("lagran; id={node_id}")) {
            let _ = request.append_header(CDN_LOOP_HEADER, value);
        }
    }
    let next = incoming_hops(&request.headers).saturating_add(1);
    if let Ok(value) = HeaderValue::from_str(&next.to_string()) {
        let _ = request.insert_header(SHIELD_HOPS_HEADER, value);
    }
}

/// Idempotent variant used by Pingora's upstream filter. `request_filter`
/// already stamps the downstream request, but this makes forwarding robust even
/// if a proxy layer rebuilds the upstream header map.
pub fn ensure_stamped_pingora(request: &mut pingora::http::RequestHeader, node_id: &str) {
    if !node_id.is_empty() && !cdn_loop_contains_node(&request.headers, node_id) {
        stamp_pingora(request, node_id);
        return;
    }
    if request.headers.get(SHIELD_HOPS_HEADER).is_none() {
        let next = incoming_hops(&request.headers).saturating_add(1);
        if let Ok(value) = HeaderValue::from_str(&next.to_string()) {
            let _ = request.insert_header(SHIELD_HOPS_HEADER, value);
        }
    }
}

fn incoming_hops(headers: &HeaderMap) -> u32 {
    let mut saw_header = false;
    let mut parsed_any = false;
    let mut max = 0;
    for value in headers.get_all(SHIELD_HOPS_HEADER).iter() {
        saw_header = true;
        if let Ok(value) = value.to_str() {
            if let Ok(hops) = value.trim().parse::<u32>() {
                parsed_any = true;
                max = max.max(hops);
            }
        }
    }
    if saw_header && !parsed_any {
        // Fail closed on a malformed internal hop header instead of treating it
        // as zero and allowing an unbounded chain.
        return MAX_SHIELD_HOPS;
    }
    max
}

fn cdn_loop_contains_node(headers: &HeaderMap, node_id: &str) -> bool {
    headers
        .get_all(CDN_LOOP_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value.split(',').any(|entry| {
                let mut parts = entry.split(';');
                let scheme = parts.next().unwrap_or("").trim();
                if !scheme.eq_ignore_ascii_case("lagran") {
                    return false;
                }
                parts.any(|parameter| {
                    parameter
                        .split_once('=')
                        .map(|(name, value)| {
                            name.trim().eq_ignore_ascii_case("id")
                                && value.trim().trim_matches('"') == node_id
                        })
                        .unwrap_or(false)
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).expect("valid test header")
    }

    #[test]
    fn detects_own_id_in_a_loop_header() {
        let mut headers = HeaderMap::new();
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-1"));
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::SelfReference));
        assert_eq!(detect(&headers, "edge-2"), None);
    }

    #[test]
    fn detects_own_id_in_a_multi_hop_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            CDN_LOOP_HEADER,
            header("lagran; id=edge-a, lagran; id=edge-1"),
        );
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::SelfReference));
    }

    #[test]
    fn quoted_ids_and_multiple_header_lines_work() {
        let mut headers = HeaderMap::new();
        headers.append(CDN_LOOP_HEADER, header("lagran; id=\"edge-2\""));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-3"));
        assert_eq!(detect(&headers, "edge-3"), Some(LoopReason::SelfReference));
        assert_eq!(detect(&headers, "edge-2"), Some(LoopReason::SelfReference));
    }

    #[test]
    fn unrelated_loop_headers_do_not_match() {
        let mut headers = HeaderMap::new();
        headers.append(CDN_LOOP_HEADER, header("other; id=edge-1"));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-9"));
        assert_eq!(detect(&headers, "edge-1"), None);
    }

    #[test]
    fn malformed_hop_header_fails_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("not-a-number"));
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::TooManyHops));
        headers.insert(SHIELD_HOPS_HEADER, header("3, 4"));
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::TooManyHops));
    }

    #[test]
    fn hop_limit_is_enforced() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("2"));
        assert_eq!(detect(&headers, "edge-1"), None);
        headers.insert(SHIELD_HOPS_HEADER, header("3"));
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::TooManyHops));
        headers.insert(SHIELD_HOPS_HEADER, header("999"));
        assert_eq!(detect(&headers, "edge-1"), Some(LoopReason::TooManyHops));
    }

    #[test]
    fn stamp_appends_and_increments() {
        let mut headers = HeaderMap::new();
        stamp(&mut headers, "edge-b");
        assert_eq!(
            headers.get(CDN_LOOP_HEADER).and_then(|v| v.to_str().ok()),
            Some("lagran; id=edge-b")
        );
        assert_eq!(
            headers
                .get(SHIELD_HOPS_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        assert_eq!(detect(&headers, "edge-b"), Some(LoopReason::SelfReference));
    }

    #[test]
    fn stamp_preserves_existing_chain_and_replaces_spoofed_hops() {
        let mut headers = HeaderMap::new();
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-a"));
        headers.insert(SHIELD_HOPS_HEADER, header("99"));
        stamp(&mut headers, "edge-b");
        let chain = headers
            .get_all(CDN_LOOP_HEADER)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(chain.contains("lagran; id=edge-a"));
        assert!(chain.contains("lagran; id=edge-b"));
        assert_eq!(
            headers
                .get(SHIELD_HOPS_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("100")
        );
    }

    #[test]
    fn three_edge_chain_is_detected_on_the_fourth() {
        let mut headers = HeaderMap::new();
        stamp(&mut headers, "edge-a");
        assert_eq!(detect(&headers, "edge-b"), None);
        stamp(&mut headers, "edge-b");
        assert_eq!(detect(&headers, "edge-c"), None);
        stamp(&mut headers, "edge-c");
        assert_eq!(detect(&headers, "edge-d"), Some(LoopReason::TooManyHops));
    }

    #[test]
    fn empty_node_id_still_enforces_hop_budget() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("3"));
        assert_eq!(detect(&headers, ""), Some(LoopReason::TooManyHops));
        let mut fresh = HeaderMap::new();
        stamp(&mut fresh, "");
        assert_eq!(
            fresh.get(CDN_LOOP_HEADER).and_then(|v| v.to_str().ok()),
            None
        );
        assert_eq!(
            fresh.get(SHIELD_HOPS_HEADER).and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    /// The reported defect: a public client could send the hop limit (or a
    /// `CDN-Loop` naming a guessable default node id) and make the edge — and
    /// the Shield behind it — answer 508 to valid traffic. An untrusted peer's
    /// headers must be gone before the guard runs.
    #[test]
    fn untrusted_peer_cannot_trigger_a_loop_verdict() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("3"));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-001"));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-001"));
        headers.insert("user-agent", header("curl"));

        assert_eq!(guard(&mut headers, "edge-001", false), None);
        assert!(
            headers.get(SHIELD_HOPS_HEADER).is_none(),
            "spoofed hop counter must be stripped, not just ignored"
        );
        assert_eq!(headers.get_all(CDN_LOOP_HEADER).iter().count(), 0);
        // Unrelated headers survive.
        assert_eq!(
            headers.get("user-agent").and_then(|v| v.to_str().ok()),
            Some("curl")
        );
    }

    /// A trusted Edge/Shield hop still gets the full chain: self-reference and
    /// the hop budget both keep working.
    #[test]
    fn trusted_peer_chain_is_still_enforced() {
        let mut headers = HeaderMap::new();
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-a"));
        assert_eq!(
            guard(&mut headers, "edge-a", true),
            Some(LoopReason::SelfReference)
        );
        assert_eq!(
            headers.get_all(CDN_LOOP_HEADER).iter().count(),
            1,
            "a trusted chain is preserved for forwarding"
        );

        let mut hops = HeaderMap::new();
        hops.insert(SHIELD_HOPS_HEADER, header("3"));
        assert_eq!(
            guard(&mut hops, "edge-b", true),
            Some(LoopReason::TooManyHops)
        );
    }

    /// Stripping happens before `stamp`, so an external client can neither
    /// raise nor reset the counter that reaches the next hop: the chain starts
    /// at one edge hop again.
    #[test]
    fn untrusted_client_cannot_influence_the_forwarded_counter() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("99"));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-001"));

        assert_eq!(guard(&mut headers, "edge-001", false), None);
        stamp(&mut headers, "edge-001-abc123");
        let chain = headers
            .get_all(CDN_LOOP_HEADER)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(chain, "lagran; id=edge-001-abc123");
        assert_eq!(
            headers
                .get(SHIELD_HOPS_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    /// A public client that is NOT in `TRUSTED_EDGES` cannot force a 508.
    ///
    /// This is the end-to-end shape of the reported defect: the old code called
    /// `detect()` directly on the inbound headers, so the hop counter and the
    /// `CDN-Loop` line reached the verdict untrimmed. `guard` must strip first,
    /// then find nothing to reject.
    #[test]
    fn public_client_injecting_hop_limit_gets_no_508() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("3"));
        headers.append(CDN_LOOP_HEADER, header("lagran; id=edge-hk-01-deadbeef"));
        headers.insert("accept", header("*/*"));

        assert_eq!(guard(&mut headers, "edge-hk-01-deadbeef", false), None);
        assert_eq!(guard(&mut headers, "edge-hk-01", false), None);
        assert!(headers.get(SHIELD_HOPS_HEADER).is_none());
        assert_eq!(headers.get_all(CDN_LOOP_HEADER).iter().count(), 0);
        // The request itself survives: this is a proxy, not a filter.
        assert_eq!(
            headers.get("accept").and_then(|v| v.to_str().ok()),
            Some("*/*")
        );
    }

    /// The default node id must not be a fixed literal.
    ///
    /// Two hosts configured identically (no `NODE_ID`, or a copied env file) used
    /// to share `"edge-001"`, so the second tier saw "its own" id in the chain and
    /// answered 508. The loop identity now carries a per-machine instance token.
    #[test]
    fn shared_node_ids_do_not_self_reference_across_hosts() {
        let a = crate::config::identity::resolve(Some("edge-001"), "/tmp/lg-id-a");
        let b = crate::config::identity::resolve(Some("edge-001"), "/tmp/lg-id-b");

        // Host A stamps its chain; host B must not recognise it as its own.
        let mut headers = HeaderMap::new();
        stamp(&mut headers, &a.loop_id);
        assert_eq!(
            detect(&headers, &a.loop_id),
            Some(LoopReason::SelfReference)
        );
        assert_eq!(detect(&headers, &b.loop_id), None);

        let _ = std::fs::remove_dir_all("/tmp/lg-id-a");
        let _ = std::fs::remove_dir_all("/tmp/lg-id-b");
    }

    /// Malformed headers from a trusted hop still fail closed.
    #[test]
    fn trusted_peer_malformed_header_still_fails_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(SHIELD_HOPS_HEADER, header("not-a-number"));
        assert_eq!(
            guard(&mut headers, "edge-1", true),
            Some(LoopReason::TooManyHops)
        );
    }
}
