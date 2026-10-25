//! Lagran authoritative DNS for Geo/ISP edge scheduling.

mod config;
mod control;
mod server;
mod wire;

use config::DnsConfig;

fn main() {
    let _ = dotenvy::dotenv();
    // `RUST_LOG` in the shared .env is written for control/edge and may not
    // mention the DNS target. Always keep lagran_dns at info unless the user
    // explicitly configured it.
    let raw = std::env::var("RUST_LOG").unwrap_or_default();
    let trimmed = raw.trim();
    let filter = if trimmed.is_empty() {
        tracing_subscriber::EnvFilter::new("lagran_dns=info")
    } else if trimmed.contains("lagran_dns")
        || trimmed.eq_ignore_ascii_case("debug")
        || trimmed.eq_ignore_ascii_case("trace")
    {
        tracing_subscriber::EnvFilter::new(trimmed)
    } else {
        tracing_subscriber::EnvFilter::new(format!("lagran_dns=info,{trimmed}"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = DnsConfig::from_env();
    if let Err(e) = server::run(cfg) {
        // Logging may be filtered by the caller; always surface fatal errors.
        tracing::error!(error = %e, "dns server failed");
        eprintln!("lagran-dns failed: {e}");
        std::process::exit(1);
    }
}
