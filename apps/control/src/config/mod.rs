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
    /// Per-process PostgreSQL pool size (default 20).
    pub database_max_connections: u32,
    /// Kept warm even when idle (default 2).
    pub database_min_connections: u32,
    /// How long a request waits for a pooled connection (default 5s).
    pub database_acquire_timeout_secs: u64,
    /// Process-local cache TTL for the bulk edge config document (default 3s).
    pub config_cache_ttl_secs: u64,
    /// Optional Redis URL; empty keeps all P1 features on local/DB fallback.
    pub redis_url: String,
    /// Session cache TTL in Redis (default 30s).
    pub redis_session_ttl_secs: u64,
    pub jwt_secret: String,
    pub jwt_expire_hours: i64,
    /// Shared secret for edge agent APIs / DNS schedule (empty = weaker checks)
    pub agent_token: String,
    /// Public base URL of the control plane (used in node install commands).
    /// Empty = derive from the incoming request Host header.
    pub public_url: String,
    /// CIDR -> geo table used by the scheduler. Supports V2Ray `geoip.dat`
    /// (Loyalsoldier) and the legacy JSON format.
    pub geoip_path: String,
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
    /// Require image CAPTCHA on login and registration (default: true).
    pub captcha_enabled: bool,
    /// When false, POST /auth/register is disabled (default: false).
    pub allow_register: bool,
    /// Seed demo@lagran.dev on startup (default: true for local dev).
    pub seed_demo: bool,
    /// Reject startup if JWT_SECRET is the built-in default (default: false).
    pub require_secure_secrets: bool,
    /// Access/metrics log retention days (0 = never purge).
    pub log_retention_days: i64,
    /// Alert evaluator interval in seconds.
    pub alert_eval_secs: u64,
    /// OTLP/HTTP endpoint. Empty disables trace export.
    pub otel_endpoint: String,
    pub otel_service_name: String,
    pub otel_sample_ratio: f64,
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
            database_max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(20)
                .clamp(2, 200),
            database_min_connections: std::env::var("DATABASE_MIN_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(2),
            database_acquire_timeout_secs: std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5)
                .clamp(1, 60),
            config_cache_ttl_secs: std::env::var("CONFIG_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3)
                .clamp(1, 60),
            redis_url: std::env::var("REDIS_URL").unwrap_or_default(),
            redis_session_ttl_secs: std::env::var("REDIS_SESSION_TTL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30)
                .clamp(5, 300),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "lagran-dev-secret-change-me".into()),
            jwt_expire_hours: jwt_expire_hours(),
            agent_token: env_nonempty("AGENT_TOKEN")
                .or_else(|| env_nonempty("EDGE_AGENT_TOKEN"))
                .unwrap_or_default(),
            public_url: std::env::var("CONTROL_PUBLIC_URL").unwrap_or_default(),
            geoip_path: env_nonempty("GEOIP_PATH")
                .or_else(|| env_nonempty("GEOIP_DAT_PATH"))
                .or_else(|| env_nonempty("GEOIP_JSON_PATH"))
                .unwrap_or_else(|| "./data/geoip.dat".into()),
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
            allow_register: env_bool("ALLOW_REGISTER", false),
            captcha_enabled: env_bool("CAPTCHA_ENABLED", true),
            seed_demo: env_bool("SEED_DEMO", true),
            require_secure_secrets: env_bool("REQUIRE_SECURE_SECRETS", false),
            log_retention_days: std::env::var("LOG_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            alert_eval_secs: std::env::var("ALERT_EVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
                .clamp(5, 3600),
            otel_endpoint: env_nonempty("OTEL_EXPORTER_OTLP_ENDPOINT")
                .or_else(|| env_nonempty("OTEL_ENDPOINT"))
                .unwrap_or_default(),
            otel_service_name: env_nonempty("OTEL_SERVICE_NAME")
                .unwrap_or_else(|| "lagran-control".into()),
            otel_sample_ratio: std::env::var("OTEL_TRACES_SAMPLER_ARG")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
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
    24
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
        // unit smoke: defaults construct without panic
        let _ = AppConfig::default();
    }
}
