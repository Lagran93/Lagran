//! Control plane configuration
//!
//! Every setting accepts both the documented name and the legacy variant so old
//! `.env` files keep working (`CONTROL_BIND` as well as `CONTROL_HOST`/`CONTROL_PORT`,
//! `JWT_EXPIRES_SECS` as well as `JWT_EXPIRE_HOURS`).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expire_hours: i64,
    /// Shared secret for edge agent APIs (empty = no check)
    pub agent_token: String,
    /// Public base URL of the control plane (used in node install commands).
    /// Empty = derive from the incoming request Host header.
    pub public_url: String,
    /// CIDR → geo JSON used by the scheduler (empty / missing = weights only).
    pub geoip_json_path: String,
    /// TTL returned by the scheduling API (seconds).
    pub schedule_ttl: u64,
    /// DNS server used by the console "DNS test" endpoint (host:port).
    pub dns_test_server: String,
    /// ACME directory for Let's Encrypt production.
    pub acme_directory_url: String,
    /// ACME directory for Let's Encrypt staging.
    pub acme_staging_directory_url: String,
    /// Optional ACME account contact email.
    pub acme_contact_email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        let (host, port) = parse_bind();
        Self {
            server: ServerConfig { host, port },
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://lagran:lagran@127.0.0.1:5432/lagran".into()),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "lagran-dev-secret-change-me".into()),
            jwt_expire_hours: jwt_expire_hours(),
            agent_token: std::env::var("AGENT_TOKEN")
                .or_else(|_| std::env::var("EDGE_AGENT_TOKEN"))
                .unwrap_or_default(),
            public_url: std::env::var("CONTROL_PUBLIC_URL").unwrap_or_default(),
            geoip_json_path: std::env::var("GEOIP_JSON_PATH")
                .unwrap_or_else(|_| "./data/geoip.json".into()),
            schedule_ttl: std::env::var("SCHEDULE_TTL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30)
                .clamp(5, 3600),
            dns_test_server: std::env::var("DNS_TEST_SERVER")
                .unwrap_or_else(|_| "127.0.0.1:53".into()),
            acme_directory_url: std::env::var("ACME_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://acme-v02.api.letsencrypt.org/directory".into()),
            acme_staging_directory_url: std::env::var("ACME_STAGING_DIRECTORY_URL").unwrap_or_else(
                |_| "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            ),
            acme_contact_email: std::env::var("ACME_CONTACT_EMAIL").unwrap_or_default(),
        }
    }
}

/// `CONTROL_BIND=0.0.0.0:8080` wins; otherwise `CONTROL_HOST`/`CONTROL_PORT`.
fn parse_bind() -> (String, u16) {
    if let Ok(bind) = std::env::var("CONTROL_BIND") {
        let bind = bind.trim();
        if !bind.is_empty() {
            if let Some((host, port)) = bind.rsplit_once(':') {
                if let Ok(port) = port.parse::<u16>() {
                    let host = host.trim_matches(['[', ']']).to_string();
                    if !host.is_empty() {
                        return (host, port);
                    }
                    return ("0.0.0.0".into(), port);
                }
            }
        }
    }
    let host = std::env::var("CONTROL_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("CONTROL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    (host, port)
}

fn jwt_expire_hours() -> i64 {
    if let Ok(v) = std::env::var("JWT_EXPIRE_HOURS") {
        if let Ok(hours) = v.parse::<i64>() {
            return hours.max(1);
        }
    }
    if let Ok(v) = std::env::var("JWT_EXPIRES_SECS") {
        if let Ok(secs) = v.parse::<i64>() {
            return (secs / 3600).max(1);
        }
    }
    72
}

impl AppConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        Self::default()
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_parses_host_and_port() {
        std::env::set_var("CONTROL_BIND", "127.0.0.1:9090");
        let (h, p) = parse_bind();
        assert_eq!((h.as_str(), p), ("127.0.0.1", 9090));
        std::env::set_var("CONTROL_BIND", "[::1]:8081");
        assert_eq!(parse_bind(), ("::1".to_string(), 8081));
        std::env::remove_var("CONTROL_BIND");
    }
}
