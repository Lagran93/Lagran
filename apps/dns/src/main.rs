//! Lagran authoritative DNS for Geo/ISP edge scheduling.

mod config;
mod control;
mod server;
mod wire;

use config::DnsConfig;

fn main() {
    let _ = dotenvy::dotenv();
    match handle_cli() {
        Ok(true) => return,
        Ok(false) => {}
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
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
    tracing::info!(
        version = version::VERSION,
        git_hash = version::GIT_HASH,
        "lagran-dns starting"
    );
    if let Err(e) = server::run(cfg) {
        // Logging may be filtered by the caller; always surface fatal errors.
        tracing::error!(error = %e, "dns server failed");
        eprintln!("lagran-dns failed: {e}");
        std::process::exit(1);
    }
}

fn handle_cli() -> Result<bool, String> {
    let command = std::env::args().nth(1);
    let Some(command) = command.as_deref() else {
        return Ok(false);
    };
    match command {
        "version" | "-V" | "--version" => {
            println!("lagran-dns {} ({})", version::VERSION, version::GIT_HASH);
            Ok(true)
        }
        "help" | "-h" | "--help" => {
            println!("{}", help_text());
            Ok(true)
        }
        "check-config" | "config-check" => {
            let cfg = DnsConfig::from_env();
            check_config(&cfg)?;
            Ok(true)
        }
        "serve" => Ok(false),
        other => Err(format!("unknown command {other:?}\n\n{}", help_text())),
    }
}

fn check_config(cfg: &DnsConfig) -> Result<(), String> {
    if cfg.zone.trim().is_empty() {
        return Err("DNS_ZONE must not be empty".into());
    }
    if cfg.ns_names.len() != cfg.ns_ips.len() {
        return Err(format!(
            "DNS_NS_NAME has {} entries but DNS_NS_IP has {}",
            cfg.ns_names.len(),
            cfg.ns_ips.len()
        ));
    }
    cfg.listen
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("DNS_LISTEN {:?} is invalid: {e}", cfg.listen))?;
    if !cfg.control_url.is_empty()
        && !(cfg.control_url.starts_with("http://") || cfg.control_url.starts_with("https://"))
    {
        return Err(format!(
            "CONTROL_URL must start with http:// or https:// (got {:?})",
            cfg.control_url
        ));
    }
    println!("config: ok");
    println!("listen: {}", cfg.listen);
    println!("zone: {}", cfg.zone);
    println!("ttl: {}", cfg.ttl);
    println!("ns_names: {}", cfg.ns_names.join(","));
    println!("ns_ips: {}", cfg.ns_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
    println!("control_url: {}", if cfg.control_url.is_empty() { "(disabled)" } else { &cfg.control_url });
    println!("workers: {}", cfg.workers);
    println!("tcp: {}", cfg.tcp_enabled);
    println!("fallback_ip: {}", cfg.fallback_ip.as_deref().unwrap_or("(none)"));
    println!("cache_secs: {}", cfg.cache_secs);
    println!("stale_secs: {}", cfg.stale_secs);
    Ok(())
}

fn help_text() -> &'static str {
    "Lagran DNS\n\nUsage:\n  lagran-dns [serve]      start the authoritative DNS server\n  lagran-dns check-config\n  lagran-dns version\n  lagran-dns help\n\nEnvironment:\n  DNS_LISTEN, DNS_ZONE, DNS_NS_NAME, DNS_NS_IP\n  CONTROL_URL, AGENT_TOKEN\n"
}

mod version;
