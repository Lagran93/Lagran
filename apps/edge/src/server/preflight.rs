//! Request preflight shared by both data planes: HTTPS redirect, bot challenge,
//! CC, rate limit, WAF and hotlink checks. Returns a response when the request
//! must not reach cache/origin.
//!
//! The body is a verbatim move out of `server::handler` (阶段 1); it does not
//! depend on any legacy cache/origin code, only on `AppState`.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::cache::policy::CacheStatus;
use crate::config::registry::DomainEntry;
use crate::server::cc::{CcDecision, CcMode};
use crate::server::handler::AppState;
use crate::server::shared::{
    challenge_accepts_html, hotlink_allowed, log_access, uuid_like_request_id,
};
use crate::server::{bot_guard, challenge, default_page};
use crate::waf::{evaluate as waf_evaluate, WafAction, WafMode, WafRequest};

fn url_query(path_and_query: &str) -> &str {
    path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("")
}

/// Preflight for the native Pingora cache path: HTTPS redirect, CC, rate-limit,
/// WAF and hotlink checks. Returns a response when the request must not reach
/// cache/origin. This mirrors the corresponding part of `proxy_handler`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn preflight_cacheable(
    state: &Arc<AppState>,
    domain: &DomainEntry,
    method: &Method,
    host: &str,
    path_only: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    client_ip: &str,
    is_https: bool,
    start: Instant,
) -> Option<Response> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let request_id = headers
        .get("x-request-id")
        .or_else(|| headers.get("x-correlation-id"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(uuid_like_request_id);
    let client_ip_addr: Option<IpAddr> = client_ip.parse().ok();

    if domain.ssl_enabled && !is_https {
        let status = if *method == Method::GET || *method == Method::HEAD {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::PERMANENT_REDIRECT
        };
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            status.as_u16(),
            start,
            client_ip,
            &user_agent,
            &referer,
            0,
            "HTTPS_REDIRECT",
            &request_id,
        )
        .await;
        return Some(https_redirect_response(
            host,
            path_and_query,
            status,
            state.https_redirect_port,
        ));
    }

    let cleared = challenge::has_clearance(
        headers,
        host,
        domain.waf.challenge_ttl_secs,
        &state.challenge_secret,
    );
    if bot_guard::enabled()
        && !cleared
        && challenge_accepts_html(method, headers)
        && matches!(
            crate::server::cc::classify_path(path_only),
            crate::server::cc::CcPathClass::Dynamic | crate::server::cc::CcPathClass::Auth
        )
    {
        let behavior = bot_guard::analyze(headers);
        if behavior.score >= bot_guard::threshold() {
            let rule_name = if behavior.reasons.is_empty() {
                "behavior-score".to_string()
            } else {
                format!("behavior-score:{}", behavior.reasons.join(","))
            };
            state
                .waf_log
                .push(
                    host,
                    client_ip,
                    method.as_str(),
                    path_and_query,
                    "challenge",
                    "bot",
                    &rule_name,
                    "block",
                )
                .await;
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                403,
                start,
                client_ip,
                &user_agent,
                &referer,
                0,
                "BOT-CHALLENGE",
                &request_id,
            )
            .await;
            let nonce = challenge::issue_nonce(host, &state.challenge_secret);
            return Some(challenge::page(
                host,
                &nonce,
                path_and_query,
                domain.waf.challenge_difficulty,
                is_https,
            ));
        }
    }

    if let Some(ip) = client_ip_addr {
        let decision = state
            .cc
            .check(host, path_only, ip, &domain.cc, cleared)
            .await;
        if decision != CcDecision::Allow {
            let banned = decision.is_banned();
            let challenge_needed = domain.cc.mode == CcMode::Block
                && matches!(decision, CcDecision::Limit { .. })
                && !cleared
                && challenge_accepts_html(method, headers);
            let action = if domain.cc.mode == CcMode::Monitor {
                "log"
            } else if banned {
                "cc-ban"
            } else if challenge_needed {
                "challenge"
            } else {
                "cc-limit"
            };
            state
                .waf_log
                .push(
                    host,
                    client_ip,
                    method.as_str(),
                    path_and_query,
                    action,
                    "cc",
                    if banned {
                        "cc-auto-ban"
                    } else if challenge_needed {
                        "cc-challenge"
                    } else {
                        "cc-rate-limit"
                    },
                    if domain.cc.mode == CcMode::Block {
                        "block"
                    } else {
                        "monitor"
                    },
                )
                .await;
            if challenge_needed {
                log_access(
                    &state.access_log,
                    method,
                    host,
                    path_only,
                    403,
                    start,
                    client_ip,
                    &user_agent,
                    &referer,
                    0,
                    "CC-CHALLENGE",
                    &request_id,
                )
                .await;
                let nonce = challenge::issue_nonce(host, &state.challenge_secret);
                return Some(challenge::page(
                    host,
                    &nonce,
                    path_and_query,
                    domain.waf.challenge_difficulty,
                    is_https,
                ));
            }
            if domain.cc.mode == CcMode::Block {
                if let CcDecision::Banned {
                    newly_banned: true, ..
                } = decision
                {
                    let control = state.control.clone();
                    let cc = state.cc.clone();
                    let report_host = host.to_string();
                    let report_ip = ip;
                    let seconds = domain.cc.ban_seconds;
                    tokio::spawn(async move {
                        let body = serde_json::json!({
                            "domain": report_host,
                            "ip": report_ip.to_string(),
                            "seconds": seconds,
                            "reason": "cc-auto-ban"
                        });
                        match control.post_json("/api/v1/cc/bans", &body).await {
                            Ok(()) => cc.mark_reported(&report_host, report_ip).await,
                            Err(e) => {
                                tracing::warn!(error = %e, "report shared CC ban failed")
                            }
                        }
                    });
                }
                log_access(
                    &state.access_log,
                    method,
                    host,
                    path_only,
                    429,
                    start,
                    client_ip,
                    &user_agent,
                    &referer,
                    0,
                    if banned { "CC-BAN" } else { "CC" },
                    &request_id,
                )
                .await;
                return Some(cc_too_many(host, path_only, decision.retry_after(), banned));
            }
        }
    }

    let skip_rate_limit =
        domain.cc.enabled && domain.cc.mode == CcMode::Block && domain.cc.global_rps > 0;
    if !skip_rate_limit {
        let rl_key = if host.is_empty() { "default" } else { host };
        if !state
            .rate_limiter
            .check(rl_key, domain.rate_limit_rps, domain.rate_limit_burst)
            .await
        {
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                429,
                start,
                client_ip,
                &user_agent,
                &referer,
                0,
                CacheStatus::None.as_str(),
                &request_id,
            )
            .await;
            return Some(default_page::rate_limited_page(host, path_only, 1, false));
        }
    }

    if domain.waf.enabled {
        // Only pay for a database lookup when this domain configured Geo/ASN
        // rules. The lookup uses the already-resolved trusted client IP.
        let geo = if domain.waf.needs_geo() {
            state.geo.lookup(client_ip_addr)
        } else {
            crate::waf::geo::GeoInfo::default()
        };
        let waf_request = WafRequest {
            method: method.as_str(),
            path: path_only,
            query: url_query(path_and_query),
            user_agent: &user_agent,
            referer: &referer,
            ip: client_ip_addr,
            country: geo.country.as_deref(),
            asn: geo.asn,
            headers,
        };
        if let Some(verdict) = waf_evaluate(&domain.waf, &waf_request) {
            if verdict.action != WafAction::Allow {
                let mode_is_block = domain.waf.mode == WafMode::Block;
                let challenge_capable = challenge_accepts_html(method, headers);
                let cleared = challenge::has_clearance(
                    headers,
                    host,
                    domain.waf.challenge_ttl_secs,
                    &state.challenge_secret,
                );
                let challenge_needed = verdict.action == WafAction::Challenge
                    && mode_is_block
                    && challenge_capable
                    && !cleared;
                let challenge_skipped = verdict.action == WafAction::Challenge
                    && mode_is_block
                    && !challenge_capable
                    && !cleared;
                let blocked = mode_is_block && verdict.is_block();

                if challenge_needed
                    || blocked
                    || challenge_skipped
                    || verdict.action == WafAction::Log
                    || !mode_is_block
                {
                    let action = if blocked {
                        "block"
                    } else if challenge_needed {
                        "challenge"
                    } else if challenge_skipped {
                        "skip-challenge"
                    } else if verdict.action == WafAction::Log {
                        "log"
                    } else {
                        "monitor"
                    };
                    let mode = if mode_is_block { "block" } else { "monitor" };
                    state
                        .waf_log
                        .push(
                            host,
                            client_ip,
                            method.as_str(),
                            path_and_query,
                            action,
                            &verdict.category,
                            &verdict.rule_name,
                            mode,
                        )
                        .await;

                    if challenge_needed {
                        log_access(
                            &state.access_log,
                            method,
                            host,
                            path_only,
                            403,
                            start,
                            client_ip,
                            &user_agent,
                            &referer,
                            0,
                            "CHALLENGE",
                            &request_id,
                        )
                        .await;
                        let nonce = challenge::issue_nonce(host, &state.challenge_secret);
                        return Some(challenge::page(
                            host,
                            &nonce,
                            path_and_query,
                            domain.waf.challenge_difficulty,
                            is_https,
                        ));
                    }

                    // A challenge verdict the client cannot render (no
                    // `Accept: text/html`, non-GET) used to fall through and
                    // reach the origin. Treat it as a block instead of "skip".
                    if blocked || challenge_skipped {
                        log_access(
                            &state.access_log,
                            method,
                            host,
                            path_only,
                            403,
                            start,
                            client_ip,
                            &user_agent,
                            &referer,
                            0,
                            "WAF",
                            &request_id,
                        )
                        .await;
                        return Some(default_page::waf_blocked_page(
                            host,
                            path_only,
                            &verdict.rule_name,
                            &verdict.category,
                        ));
                    }
                }
            }
        }
    }

    let hotlink_signature_ok = headers
        .get(crate::security::signed_url::HOTLINK_OK_HEADER)
        .is_some_and(|v| v == "1");
    if !hotlink_signature_ok
        && (domain.hotlink_signature_enabled || !domain.hotlink_allow_referers.is_empty())
        && !hotlink_allowed(&domain.hotlink_allow_referers, &referer)
    {
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            403,
            start,
            client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
            &request_id,
        )
        .await;
        return Some((StatusCode::FORBIDDEN, "Hotlink Forbidden").into_response());
    }

    None
}

pub(crate) fn cc_too_many(host: &str, path: &str, retry_after: u64, banned: bool) -> Response {
    default_page::rate_limited_page(host, path, retry_after, banned)
}

fn host_without_port(host: &str) -> String {
    let host = host.trim();
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return host[..=end].to_string();
        }
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name.to_string(),
        _ => host.to_string(),
    }
}

pub(crate) fn https_redirect_response(
    host: &str,
    path_and_query: &str,
    status: StatusCode,
    port: Option<u16>,
) -> Response {
    let mut authority = host_without_port(host);
    if let Some(p) = port.filter(|p| *p != 443) {
        authority = format!("{authority}:{p}");
    }
    let location = format!("https://{authority}{path_and_query}");
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    match HeaderValue::from_str(&location) {
        Ok(v) => {
            headers.insert(header::LOCATION, v);
        }
        Err(_) => {
            headers.insert(header::LOCATION, HeaderValue::from_static("/"));
        }
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-lagran-redirect"),
        HeaderValue::from_static("https"),
    );
    response
}
