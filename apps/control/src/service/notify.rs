//! Alert notification transports: webhook, Telegram and SMTP email.
//!
//! Every transport here talks to a tenant-supplied destination, so every
//! transport resolves through [`crate::service::net_guard`] and dials only
//! addresses that passed the policy. See that module for the DNS-rebinding
//! reasoning.

use crate::service::agent_http::{self, PublicDestination};
use crate::service::net_guard;
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use ring::hmac;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct WebhookConfig {
    url: String,
    #[serde(default)]
    secret: String,
}

#[derive(Debug, Deserialize)]
struct TelegramConfig {
    bot_token: String,
    chat_id: String,
    #[serde(default)]
    api_base: String,
    #[serde(default)]
    proxy: String,
}

#[derive(Debug, Deserialize)]
struct EmailConfig {
    smtp_host: String,
    #[serde(default = "default_smtp_port")]
    smtp_port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    from: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default = "default_smtp_tls")]
    tls: String,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_tls() -> String {
    "starttls".into()
}

pub async fn send_channel(
    kind: &str,
    config: &Value,
    subject: &str,
    message: &str,
    severity: &str,
) -> Result<(), String> {
    match kind {
        "webhook" => send_webhook(config, subject, message, severity).await,
        "telegram" => send_telegram(config, subject, message).await,
        "email" => send_email(config, subject, message).await,
        other => Err(format!("unsupported channel kind: {other}")),
    }
}

async fn send_webhook(
    config: &Value,
    subject: &str,
    message: &str,
    severity: &str,
) -> Result<(), String> {
    let cfg: WebhookConfig = serde_json::from_value(config.clone())
        .map_err(|e| format!("invalid webhook config: {e}"))?;
    if cfg.url.trim().is_empty() {
        return Err("webhook url is required".into());
    }
    let url = cfg.url.trim();
    crate::service::net_guard::validate_http_url(url)
        .await
        .map_err(|e| format!("webhook url rejected: {e}"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = json!({
        "event": "lagran.alert",
        "severity": severity,
        "subject": subject,
        "message": message,
        "timestamp": ts,
    });
    let payload = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let mut headers = vec![("user-agent", "lagran-control/0.1")];
    let signature;
    if !cfg.secret.is_empty() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, cfg.secret.as_bytes());
        let tag = hmac::sign(&key, &payload);
        signature = format!("sha256={}", hex(tag.as_ref()));
        headers.push(("x-lagran-signature-256", signature.as_str()));
    }
    // `post_json_with_headers` re-checks the destination at connect time: it
    // resolves through `GuardedResolver`, so a name that rebinds to an internal
    // address after the pre-flight check above is refused rather than dialled.
    let (status, _body) = agent_http::post_json_with_headers(url, &body, &headers)
        .await
        .map_err(|_| "webhook request failed".to_string())?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        // Never echo the upstream body: `POST /alert-channels/:id/test`
        // returns this string to the tenant and it used to leak up to 200 bytes
        // of whatever an internal service answered.
        Err(format!("webhook HTTP {status}"))
    }
}

/// The proxy to use for one alert destination, or `None` to connect directly.
///
/// Rules, in order:
///
/// 1. An explicit per-channel `proxy` wins: the tenant asked for that egress
///    specifically, so it is used verbatim (and still passes
///    [`net_guard::validate_proxy_url`], because the value is tenant input and
///    the SSRF guard must keep holding for it).
/// 2. A loopback/private/link-local target is **never** routed through an
///    external proxy (PERF-NEW-05). Self-hosted Bot API gateways and local
///    listeners sit inside the network the egress proxy cannot reach; silently
///    handing them to `HTTPS_PROXY` turned every alert into a connection
///    failure. DNS names are not classified here — the guarded resolver already
///    refuses private answers for the alert path.
/// 3. `NO_PROXY`/`no_proxy` from the environment is honoured for env-sourced
///    proxies (exact hosts, domain suffixes, `*`, IP/CIDR — reqwest's matcher).
/// 4. Otherwise the scheme-appropriate environment proxy is used:
///    `HTTPS_PROXY` only for `https`, `HTTP_PROXY` only for `http`, and
///    `ALL_PROXY` as the fallback for both. The previous code fed whichever
///    variable it found into `Proxy::all`, so an `https://` egress proxy also
///    captured plain-`http` destinations.
fn proxy_for_target(base: &str, explicit: Option<&str>) -> Option<String> {
    let parsed = reqwest::Url::parse(base).ok()?;
    if let Some(proxy) = explicit.map(str::trim).filter(|p| !p.is_empty()) {
        return Some(proxy.to_string());
    }
    if target_is_internal(&parsed) {
        return None;
    }
    env_proxy_url_for(parsed.scheme())
}

/// Whether a destination is loopback/private/link-local by literal or name.
fn target_is_internal(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        // The alert path only allows public destinations, so "not public" and
        // "internal" are the same set here.
        Ok(ip) => !net_guard::is_public_ip(ip),
        Err(_) => false,
    }
}

/// The environment proxy for one target scheme, or `None` to connect directly.
///
/// `Proxy::all` applies one proxy to every scheme, which is why the variable
/// that names the proxy has to match the destination scheme first: an operator
/// who exports only `HTTPS_PROXY` did not ask their plain-`http` traffic to be
/// captured.
fn env_proxy_url_for(scheme: &str) -> Option<String> {
    let vars: &[&str] = match scheme {
        "https" => &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"],
        "http" => &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"],
        _ => &[],
    };
    vars.iter()
        .find_map(|key| std::env::var(key).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Env-sourced proxies are operator configuration, so a loopback egress proxy —
/// the usual `clash`/`v2ray` setup on the same box — must be accepted. Only the
/// scheme is checked; the destination policy does not apply to them.
fn validate_env_proxy_scheme(proxy: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(proxy)
        .map_err(|e| format!("invalid telegram proxy {proxy:?}: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https" | "socks5" | "socks5h") {
        return Err(format!(
            "telegram proxy scheme must be http, https, socks5 or socks5h (got {:?})",
            parsed.scheme()
        ));
    }
    Ok(())
}

async fn send_telegram(config: &Value, subject: &str, message: &str) -> Result<(), String> {
    let cfg: TelegramConfig = serde_json::from_value(config.clone())
        .map_err(|e| format!("invalid telegram config: {e}"))?;
    if cfg.bot_token.trim().is_empty() || cfg.chat_id.trim().is_empty() {
        return Err("telegram bot_token and chat_id are required".into());
    }
    let base = if cfg.api_base.trim().is_empty() {
        std::env::var("TELEGRAM_API_BASE")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "https://api.telegram.org".to_string())
    } else {
        cfg.api_base.trim().trim_end_matches('/').to_string()
    };
    if !base.starts_with("http://") && !base.starts_with("https://") {
        return Err("telegram api_base must start with http:// or https://".into());
    }
    crate::service::net_guard::validate_http_url(&base)
        .await
        .map_err(|e| format!("telegram api_base rejected: {e}"))?;
    let url = format!("{base}/bot{}/sendMessage", cfg.bot_token.trim());
    let text = format!("<b>{}</b>\n{}", html_escape(subject), html_escape(message));
    let body = json!({
        "chat_id": cfg.chat_id.trim(),
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    });

    let builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("lagran-control/0.1")
        // Redirects are off: reqwest's default policy follows up to 10 hops and
        // every hop is a fresh URL. It skips `check_target` (which only saw the
        // initial URL) and, for proxied requests, the guarded resolver runs at
        // the proxy instead. A tenant-controlled `api_base` answering
        // `302 Location: http://169.254.169.254/...` made the control plane dial
        // metadata or an internal port (H2). Alert delivery does not need
        // redirects, so the 3xx is surfaced as an error below.
        .redirect(reqwest::redirect::Policy::none())
        // reqwest resolves on its own, so give it the same guarded resolver the
        // hyper client uses. Without this, `api_base` could be rebound between
        // `validate_http_url` and the actual request.
        .dns_resolver(net_guard::GuardedDns::new(
            net_guard::is_public_ip,
            PublicDestination::Internet.label(),
        ))
        // reqwest also picks up `HTTPS_PROXY`/`ALL_PROXY` on its own, and those
        // implicit proxies bypass the decision below: a request would be handed
        // to whatever endpoint the environment names, unchecked. Disabling the
        // auto-detection makes `proxy_for_target` the single authority for
        // whether a proxy applies.
        .no_proxy();
    // The channel-level `proxy` is tenant input and keeps the public-only
    // destination policy. The environment proxies below are operator
    // configuration, so they skip that policy (a loopback egress proxy is the
    // normal local setup) and instead honour `NO_PROXY` per request.
    let explicit = (!cfg.proxy.trim().is_empty()).then(|| cfg.proxy.trim().to_string());
    let builder = match proxy_for_target(&base, explicit.as_deref()) {
        Some(proxy) => {
            if explicit.is_some() {
                crate::service::net_guard::validate_proxy_url(&proxy)
                    .await
                    .map_err(|e| format!("telegram proxy rejected: {e}"))?;
            } else {
                validate_env_proxy_scheme(&proxy)?;
            }
            let proxy = reqwest::Proxy::all(&proxy)
                .map_err(|e| format!("invalid telegram proxy: {e}"))?;
            // `NO_PROXY` is operator configuration, so it only bends env-sourced
            // proxies. A channel that explicitly names a proxy is that channel's
            // egress decision and is honoured verbatim.
            let proxy = if explicit.is_some() {
                proxy
            } else {
                proxy.no_proxy(reqwest::NoProxy::from_env())
            };
            builder.proxy(proxy)
        }
        // Loopback/private destinations connect directly: routing them through
        // an egress proxy is what broke local Bot API gateways (PERF-NEW-05).
        None => builder,
    };
    let client = builder
        .build()
        .map_err(|e| format!("telegram client error: {e}"))?;
    // reqwest skips its resolver for IP-literal hosts, so check the literal too.
    net_guard::check_target(
        &url,
        net_guard::is_public_ip,
        PublicDestination::Internet.label(),
    )?;
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            format!(
                "telegram request failed: {e}（请检查服务器到 Telegram 的网络，或在渠道中配置代理/API 地址）"
            )
        })?;
    let status = response.status();
    let _body = response.text().await.unwrap_or_default();
    if status.is_success() {
        Ok(())
    } else if status.is_redirection() {
        // `Policy::none()` never dials the target of a redirect; make the
        // operator fix `api_base` instead of chasing a 3xx.
        tracing::warn!(
            status = status.as_u16(),
            api_base = %base,
            "telegram api_base returned a redirect; redirects are not followed"
        );
        Err(format!(
            "telegram HTTP {} (redirects are not followed; point api_base at the final URL)",
            status.as_u16()
        ))
    } else {
        Err(format!("telegram HTTP {}", status.as_u16()))
    }
}

async fn send_email(config: &Value, subject: &str, message: &str) -> Result<(), String> {
    let cfg: EmailConfig =
        serde_json::from_value(config.clone()).map_err(|e| format!("invalid email config: {e}"))?;
    if cfg.smtp_host.trim().is_empty() || cfg.from.trim().is_empty() || cfg.to.is_empty() {
        return Err("email smtp_host, from and to are required".into());
    }
    let smtp_host = cfg.smtp_host.trim();
    // Resolve once, then hand lettre the *validated IP*. lettre resolves the
    // hostname itself when it opens the socket, which would reopen the rebinding
    // window this module exists to close; an IP literal is used as-is.
    let addrs = crate::service::net_guard::resolve_smtp_host(smtp_host, cfg.smtp_port)
        .await
        .map_err(|e| format!("smtp host rejected: {e}"))?;
    // Pick an address that actually accepts a connection. Handing lettre the
    // hostname let it try every answer; now that it only gets one literal, probe
    // them in order so a dead first record does not take alerting down.
    let chosen = net_guard::connect_any(&addrs, std::time::Duration::from_secs(6))
        .await
        .map_err(|e| format!("smtp transport unreachable: {e}"))?;
    let dial = dial_host(chosen);
    let from: Mailbox = cfg
        .from
        .parse()
        .map_err(|e| format!("invalid from address: {e}"))?;
    let mut builder = Message::builder()
        .from(from)
        .subject(subject)
        .header(ContentType::TEXT_HTML);
    for address in &cfg.to {
        let mailbox: Mailbox = address
            .parse()
            .map_err(|e| format!("invalid to address {address}: {e}"))?;
        builder = builder.to(mailbox);
    }
    let html = format!(
        "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC',sans-serif;line-height:1.7\"><h2 style=\"margin:0 0 12px\">{}</h2><pre style=\"white-space:pre-wrap;background:#f7f8fa;padding:14px;border-radius:8px\">{}</pre></div>",
        html_escape(subject),
        html_escape(message)
    );
    let email = builder
        .body(html)
        .map_err(|e| format!("build email: {e}"))?;

    // TLS still needs the configured hostname for SNI and certificate
    // verification, so `TlsParameters` is built from it and the socket is dialled
    // to the checked IP. `builder_dangerous` is misnamed here: it only skips
    // lettre's own relay presets, and an explicit `Tls` is supplied below.
    let tls_name = smtp_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let mut transport_builder = match cfg.tls.as_str() {
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(dial.as_str())
            .port(cfg.smtp_port)
            .tls(Tls::None),
        "implicit" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(dial.as_str())
            .port(cfg.smtp_port)
            .tls(Tls::Wrapper(
                TlsParameters::new_rustls(tls_name.clone())
                    .map_err(|e| format!("smtp tls parameters: {e}"))?,
            )),
        _ => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(dial.as_str())
            .port(cfg.smtp_port)
            .tls(Tls::Required(
                TlsParameters::new_rustls(tls_name.clone())
                    .map_err(|e| format!("smtp tls parameters: {e}"))?,
            )),
    };
    if !cfg.username.is_empty() {
        transport_builder =
            transport_builder.credentials(Credentials::new(cfg.username, cfg.password));
    }
    let transport = transport_builder.build();
    transport
        .send(email)
        .await
        .map(|_| ())
        .map_err(|e| format!("smtp send: {e}"))
}

/// The literal lettre should dial.
///
/// Bare, not bracketed: lettre resolves `(host, port)` through tokio, whose
/// `(&str, u16)` impl parses a plain IPv4/IPv6 literal but not an authority-form
/// bracketed one. The brackets belong in URLs, not in this argument.
fn dial_host(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

pub fn test_message() -> (&'static str, &'static str, &'static str) {
    (
        "Lagran 告警测试",
        "这是一条来自 Lagran CDN 控制面的测试告警。收到此消息说明通知渠道配置正常。",
        "info",
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Proxy environment variables are process-wide; tests that set them must
    /// not overlap with each other or with the direct-connection test.
    static PROXY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const PROXY_VARS: &[&str] = &[
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ];

    fn clear_proxy_env() {
        for key in PROXY_VARS {
            std::env::remove_var(key);
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        PROXY_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A loopback `api_base` must never be handed to the environment proxy.
    ///
    /// This is the reported failure: with `HTTPS_PROXY` pointing at a local
    /// egress proxy (clash/v2ray), `Proxy::all` hijacked the request to a
    /// self-hosted Bot API on `127.0.0.1` and the alert failed. The mock proxy
    /// below would accept the connection, so "zero connections" proves the
    /// request went direct.
    #[tokio::test]
    async fn local_api_base_is_never_routed_through_the_env_proxy() {
        let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_addr = api.local_addr().unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let api_server = tokio::spawn(async move {
            let (mut socket, _) = api.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let proxy_hits_task = {
            let proxy_hits = proxy_hits.clone();
            tokio::spawn(async move {
                // Accept (and count) anything the client wrongly sends here.
                if let Ok(Ok((mut socket, _))) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), proxy.accept()).await
                {
                    proxy_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                }
            })
        };

        // The lock is released before the request runs: a decision for an internal
        // destination does not read the environment at all, so a concurrently
        // running test cannot change the outcome of this one.
        {
            let _guard = env_lock();
            clear_proxy_env();
            std::env::set_var("HTTPS_PROXY", format!("http://{proxy_addr}"));
            std::env::set_var("ALL_PROXY", format!("http://{proxy_addr}"));
        }

        let config = json!({
            "bot_token": "123:test",
            "chat_id": "456",
            "api_base": format!("http://{api_addr}"),
        });
        let result = send_telegram(&config, "subject", "message").await;
        {
            let _guard = env_lock();
            clear_proxy_env();
        }

        result.expect("a local api_base must be reachable with an env proxy set");
        api_server.await.unwrap();
        proxy_hits_task.await.unwrap();
        assert_eq!(
            proxy_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the env proxy must not see a loopback destination"
        );
    }

    /// The env proxy variable has to match the destination scheme.
    #[test]
    fn env_proxy_matches_the_target_scheme() {
        let _guard = env_lock();
        clear_proxy_env();
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:7890");
        assert_eq!(
            env_proxy_url_for("https").as_deref(),
            Some("http://127.0.0.1:7890")
        );
        assert_eq!(
            env_proxy_url_for("http"),
            None,
            "an https-only egress proxy must not capture plain http"
        );

        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:7891");
        assert_eq!(
            env_proxy_url_for("http").as_deref(),
            Some("http://127.0.0.1:7891")
        );
        assert_eq!(
            env_proxy_url_for("https").as_deref(),
            Some("http://127.0.0.1:7890")
        );

        // ALL_PROXY is the fallback for both schemes.
        clear_proxy_env();
        std::env::set_var("ALL_PROXY", "socks5h://127.0.0.1:1080");
        assert_eq!(
            env_proxy_url_for("https").as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );
        assert_eq!(
            env_proxy_url_for("http").as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );

        clear_proxy_env();
        assert_eq!(env_proxy_url_for("https"), None);
    }

    /// An explicit channel proxy wins over the environment, and internal
    /// destinations bypass proxies even when one is configured.
    #[test]
    fn explicit_proxy_wins_and_internal_targets_bypass_everything() {
        let _guard = env_lock();
        clear_proxy_env();
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:7890");

        assert_eq!(
            proxy_for_target("https://api.telegram.org", Some("http://egress.example:3128"))
                .as_deref(),
            Some("http://egress.example:3128"),
            "the channel configuration is the operator's explicit choice"
        );
        assert_eq!(
            proxy_for_target("https://api.telegram.org", None).as_deref(),
            Some("http://127.0.0.1:7890")
        );
        assert_eq!(proxy_for_target("http://127.0.0.1:8081", None), None, "loopback");
        assert_eq!(
            proxy_for_target("http://10.1.2.3:8081", None),
            None,
            "private range"
        );
        assert_eq!(
            proxy_for_target("http://169.254.169.254", None),
            None,
            "link-local"
        );
        assert_eq!(
            proxy_for_target("http://bot-gateway.localhost:8081", None),
            None,
            "the .localhost suffix is reserved for loopback"
        );
        clear_proxy_env();
    }

    /// Only the documented proxy schemes are accepted for env proxies; a
    /// loopback egress proxy is the normal local setup and must be allowed.
    #[test]
    fn env_proxy_scheme_is_validated_without_the_public_ip_policy() {
        assert!(validate_env_proxy_scheme("http://127.0.0.1:7890").is_ok());
        assert!(validate_env_proxy_scheme("socks5h://127.0.0.1:1080").is_ok());
        assert!(validate_env_proxy_scheme("ftp://127.0.0.1:21").is_err());
        assert!(validate_env_proxy_scheme("not-a-url").is_err());
    }

    #[tokio::test]
    async fn telegram_honors_custom_api_base() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let config = json!({
            "bot_token": "123:test",
            "chat_id": "456",
            "api_base": format!("http://{addr}"),
        });
        send_telegram(&config, "subject", "message").await.unwrap();
        server.await.unwrap();
    }

    /// A redirect from `api_base` must not be followed.
    ///
    /// reqwest's default policy follows up to 10 hops, and a redirect to an IP
    /// literal never reaches the guarded resolver: `check_target` only validated
    /// the initial URL. The mock Bot API below answers `302` pointing at a
    /// loopback "metadata" listener, so following it would be visible as a
    /// connection (loopback is permitted in `cfg(test)` builds on purpose).
    #[tokio::test]
    async fn telegram_redirect_to_internal_destination_is_not_followed() {
        let metadata = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metadata_addr = metadata.local_addr().unwrap();
        let metadata_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let metadata_task = {
            let metadata_hits = metadata_hits.clone();
            tokio::spawn(async move {
                if let Ok(Ok((mut socket, _))) =
                    tokio::time::timeout(std::time::Duration::from_secs(1), metadata.accept()).await
                {
                    metadata_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            })
        };

        let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_addr = api.local_addr().unwrap();
        let api_task = tokio::spawn(async move {
            let (mut socket, _) = api.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nlocation: http://{metadata_addr}/latest/meta-data\r\n\
                 content-length: 0\r\nconnection: close\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let config = json!({
            "bot_token": "123:test",
            "chat_id": "456",
            "api_base": format!("http://{api_addr}"),
        });
        let err = send_telegram(&config, "subject", "message")
            .await
            .expect_err("a redirect must not be followed");
        assert!(err.contains("redirect"), "{err}");

        api_task.await.unwrap();
        metadata_task.await.unwrap();
        assert_eq!(
            metadata_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the redirect target must never be dialled"
        );
    }

    #[tokio::test]
    async fn webhook_to_metadata_is_refused() {
        let config = json!({ "url": "http://169.254.169.254/latest/meta-data" });
        let err = send_webhook(&config, "s", "m", "info").await.unwrap_err();
        assert!(err.contains("rejected"), "{err}");
    }

    #[tokio::test]
    async fn telegram_api_base_pointing_at_metadata_is_refused() {
        let config = json!({
            "bot_token": "123:test",
            "chat_id": "456",
            "api_base": "http://169.254.169.254",
        });
        let err = send_telegram(&config, "s", "m").await.unwrap_err();
        assert!(err.contains("rejected"), "{err}");
    }

    #[tokio::test]
    async fn smtp_host_pointing_at_metadata_is_refused() {
        let config = json!({
            "smtp_host": "169.254.169.254",
            "from": "a@example.com",
            "to": ["b@example.com"],
        });
        let err = send_email(&config, "s", "m").await.unwrap_err();
        assert!(err.contains("rejected"), "{err}");
    }

    #[test]
    fn smtp_dials_the_validated_ip_not_the_name() {
        // Bare literals: tokio parses these directly, so lettre never consults
        // DNS and the guard's answer is what gets connected to.
        assert_eq!(
            dial_host("203.0.113.10:587".parse().unwrap()),
            "203.0.113.10"
        );
        let v6: SocketAddr = "[2001:db8::1]:587".parse().unwrap();
        assert_eq!(dial_host(v6), "2001:db8::1");
        assert!(
            "2001:db8::1".parse::<IpAddr>().is_ok(),
            "lettre's resolver must accept the literal as-is"
        );
    }
}
