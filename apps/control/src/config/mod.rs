//! Control plane configuration

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expire_hours: i64,
    /// Shared secret for edge agent APIs (empty = no check)
    pub agent_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: std::env::var("CONTROL_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
                port: std::env::var("CONTROL_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080),
            },
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://lagran:lagran@127.0.0.1:5432/lagran".into()
            }),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "lagran-dev-secret-change-me".into()),
            jwt_expire_hours: std::env::var("JWT_EXPIRE_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(72),
            agent_token: std::env::var("AGENT_TOKEN")
                .or_else(|_| std::env::var("EDGE_AGENT_TOKEN"))
                .unwrap_or_default(),
        }
    }
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
