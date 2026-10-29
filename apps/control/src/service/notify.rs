//! Alert notification transports: webhook, Telegram and SMTP email.

use crate::service::agent_http;
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::Tls;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use ring::hmac;
use serde::Deserialize;
use serde_json::{json, Value};
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
    let (status, body) = agent_http::post_json_with_headers(&cfg.url, &body, &headers)
        .await
        .map_err(|_| "webhook request failed".to_string())?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!(
            "webhook HTTP {status}: {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(200)
                .collect::<String>()
        ))
    }
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
    let url = format!("{base}/bot{}/sendMessage", cfg.bot_token.trim());
    let text = format!("<b>{}</b>\n{}", html_escape(subject), html_escape(message));
    let body = json!({
        "chat_id": cfg.chat_id.trim(),
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    });

    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("lagran-control/0.1");
    let proxy = if cfg.proxy.trim().is_empty() {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
            .iter()
            .find_map(|key| std::env::var(key).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    } else {
        Some(cfg.proxy.trim().to_string())
    };
    if let Some(proxy) = proxy {
        let proxy = reqwest::Proxy::all(&proxy)
            .map_err(|e| format!("invalid telegram proxy: {e}"))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| format!("telegram client error: {e}"))?;
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
    let body = response.text().await.unwrap_or_default();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "telegram HTTP {}: {}",
            status.as_u16(),
            body.chars().take(300).collect::<String>()
        ))
    }
}

async fn send_email(config: &Value, subject: &str, message: &str) -> Result<(), String> {
    let cfg: EmailConfig =
        serde_json::from_value(config.clone()).map_err(|e| format!("invalid email config: {e}"))?;
    if cfg.smtp_host.trim().is_empty() || cfg.from.trim().is_empty() || cfg.to.is_empty() {
        return Err("email smtp_host, from and to are required".into());
    }
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

    let mut transport_builder = match cfg.tls.as_str() {
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
            .port(cfg.smtp_port)
            .tls(Tls::None),
        "implicit" => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)
            .map_err(|e| format!("smtp relay: {e}"))?
            .port(cfg.smtp_port),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
            .map_err(|e| format!("smtp starttls: {e}"))?
            .port(cfg.smtp_port),
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
}

