use edge::agent::{self, access_report, cert_sync, config_sync, metrics_report, origin_health};
use edge::cache::{self, policy::RuleSet};
use edge::config::registry::DomainRegistry;
use edge::config::EdgeConfig;
use edge::metrics::EdgeMetrics;
use edge::origin::OriginClient;
use edge::server::access_log::AccessLog;
use edge::server::handler::AppState;
use edge::server::inflight::Inflight;
use edge::server::{listener, tls};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// jemalloc instead of the system allocator: the data plane allocates on every
/// request (header vectors, access-log records, WAF decoding), and glibc's
/// per-arena contention is visible once the process is thread-heavy.
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn is_http_url(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.chars().any(char::is_whitespace)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env BEFORE EnvFilter reads RUST_LOG
    let _ = dotenvy::dotenv();

    if handle_cli()? {
        return Ok(());
    }

    init_tracing();

    let config = EdgeConfig::load();
    if !is_http_url(&config.control_url) {
        anyhow::bail!(
            "CONTROL_URL must start with http:// or https:// (got {:?})",
            config.control_url
        );
    }
    tracing::info!(
        http = %config.listen_addr,
        https = ?config.https_listen_addr,
        cache = %config.cache_backend,
        domain = %config.domain,
        "Lagran Edge starting (multi-domain + disk cache)"
    );

    let cache = cache::build_cache(&config).await?;
    let large_cache = if config.large_cache_enabled {
        Some(
            edge::cache::LargeCache::open(
                &config.large_cache_dir,
                config.large_cache_min_object_bytes,
                config.large_cache_max_object_bytes,
                config.large_cache_max_bytes,
            )
            .await?,
        )
    } else {
        None
    };
    let origin = OriginClient::with_connect_timeout(
        config.origin_url.clone(),
        std::time::Duration::from_millis(config.origin_connect_timeout_ms),
    );
    let rules = RuleSet::new();
    let metrics = EdgeMetrics::new();
    let cert_store = Arc::new(edge::server::cert_store::CertStore::with_persist_dir(
        &config.cert_dir,
    ));
    if !cert_store.is_empty() {
        tracing::info!(
            count = cert_store.len(),
            "HTTPS can start with disk-loaded certs"
        );
    }
    let challenges = edge::server::acme_challenge::ChallengeStore::new();
    let mut access_log = AccessLog::open(
        config.access_log_path.as_deref(),
        &config.node_id,
        config.access_log_buffer,
        config.access_log_json,
    )
    .await;
    if !config.access_log_enabled {
        tracing::warn!("ACCESS_LOG_ENABLED=0: access records will not be kept");
        access_log.set_enabled(false);
    }
    let rate_limiter = edge::server::rate_limit::RateLimiter::new(
        std::env::var("RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        std::env::var("RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    )
    .with_redis_url(&config.redis_url)
    .await;
    let origin_health_map = origin_health::OriginHealthMap::new();
    let domains = DomainRegistry::new();
    let control = agent::ControlClient::new(&config);
    let node_control = agent::NodeControl::new();
    let waf_log = edge::server::waf_log::WafLog::new(&config.node_id, 2000);
    let challenge_secret = if !config.challenge_secret.is_empty() {
        config.challenge_secret.clone()
    } else {
        // Never derive a signing key from AGENT_TOKEN: that token is shared by
        // every node and by the control plane, so anyone holding it could forge
        // clearance cookies. A random per-process key is the safe fallback.
        random_secret()
    };

    if config.challenge_secret.is_empty() {
        tracing::warn!(
            "CHALLENGE_SECRET is empty; using a random per-process key. Clearance cookies and nonces will not survive a restart or work across nodes until an explicit shared CHALLENGE_SECRET is configured."
        );
    }

    agent::spawn_heartbeat(config.clone(), control.clone(), node_control.clone());
    config_sync::spawn_config_sync(
        config.clone(),
        control.clone(),
        origin.clone(),
        rules.clone(),
        domains.clone(),
        cache.clone(),
        large_cache.clone(),
    );
    metrics_report::spawn_metrics_report(config.clone(), control.clone(), metrics.clone());
    access_report::spawn_access_report(config.clone(), control.clone(), access_log.clone());
    origin_health::spawn_origin_health(
        control.clone(),
        domains.clone(),
        origin.clone(),
        origin_health_map.clone(),
    );
    cert_sync::spawn_cert_sync(config.clone(), control.clone(), cert_store.clone());
    if config.waf_report {
        agent::waf_report::spawn_waf_report(
            control.clone(),
            waf_log.clone(),
            config.waf_report_interval_secs,
        );
    }

    let cc = if config.redis_url.trim().is_empty() {
        // Logged from the cc module, not here: `main`'s target is `lagran_edge`, which
        // a `RUST_LOG=edge=...` filter does not match. Silence in that branch used to
        // make "CC is per-node" indistinguishable from "CC failed".
        edge::server::cc::log_shared_wiring(&edge::server::cc::SharedWiring::Local {
            redis_url_present: false,
        });
        edge::server::cc::CcProtector::new()
    } else {
        match edge::server::cc::RedisCc::connect(&config.redis_url).await {
            Ok(redis) => {
                edge::server::cc::log_shared_wiring(&edge::server::cc::SharedWiring::Redis {
                    budget_ms: edge::server::cc::REDIS_TIMEOUT_MS,
                });
                edge::server::cc::CcProtector::with_redis(Some(redis))
            }
            Err(e) => {
                edge::server::cc::log_shared_wiring(
                    &edge::server::cc::SharedWiring::RedisUnavailable {
                        error: e.to_string(),
                    },
                );
                edge::server::cc::CcProtector::new()
            }
        }
    };

    // Periodic report on whether the cross-node CC budget is actually reaching Redis.
    //
    // Reported rather than logged per request: the counters answer "did any shared
    // round trip ever complete", which is the question a cross-region deployment
    // cannot answer from request logs alone. A rising `ok` means the shared limiter
    // works; a rising `timeout` with a flat `ok` means the link is too slow for
    // REDIS_TIMEOUT and every request is silently using the per-process budget.
    if cc.shared_counters().is_some() {
        let cc = cc.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some((ok, timeout, error)) = cc.shared_counters() else {
                    return;
                };
                if ok == 0 && timeout == 0 && error == 0 {
                    continue;
                }
                // Also emitted from the cc module so the periodic answer survives a
                // `RUST_LOG=edge=...` filter; a report nobody can see defeats the point.
                edge::server::cc::log_shared_counters(
                    ok,
                    timeout,
                    error,
                    edge::server::cc::REDIS_TIMEOUT_MS,
                );
            }
        });
    }

    let flight = if matches!(config.cache_backend.as_str(), "redis" | "l2") {
        let url = if config.cache_redis_url.trim().is_empty() {
            config.redis_url.clone()
        } else {
            config.cache_redis_url.clone()
        };
        if url.trim().is_empty() {
            None
        } else {
            match edge::cache::flight::RedisFlight::connect(
                &url,
                format!("{}:flight", config.cache_redis_prefix),
                std::time::Duration::from_millis(config.cache_flight_timeout_ms),
            )
            .await
            {
                Ok(flight) => Some(flight),
                Err(e) => {
                    tracing::warn!(error = %e, "cross-node cache flight unavailable");
                    None
                }
            }
        }
    } else {
        None
    };
    crate::cache::policy::configure_cache_key_ignored_headers(
        config.cache_key_ignore_headers.clone(),
    );
    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    let local_http_addr = SocketAddr::new(
        if listen_addr.ip().is_unspecified() {
            if listen_addr.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            }
        } else {
            listen_addr.ip()
        },
        listen_addr.port(),
    );
    let state = Arc::new(AppState {
        cache,
        flight,
        // 128 concurrent background revalidations: enough to refresh a large
        // deployment quickly, far below the request concurrency that would exhaust
        // the origin pool.
        revalidate_permits: Arc::new(tokio::sync::Semaphore::new(128)),
        large_cache,
        origin,
        default_ttl_secs: config.default_ttl_secs,
        rules,
        metrics,
        challenges,
        certs: cert_store.clone(),
        domains,
        access_log,
        rate_limiter,
        cc,
        control: control.clone(),
        origin_health: origin_health_map,
        agent_token: config.agent_token.clone(),
        inflight: Inflight::default(),
        waf_log,
        // Pingora overwrites X-Forwarded-For/Proto before it forwards to this
        // loopback-only engine, so the forwarded values are trusted exactly when
        // the peer is loopback. Previously this was a blanket `true`, which the
        // handler combined with a client header once the request arrived
        // directly.
        trust_proxy_headers: true,
        trusted_proxies: edge::security::trusted_proxy::TrustedProxies::parse("127.0.0.0/8, ::1")
            .unwrap_or_default(),
        challenge_secret,
        geo: Arc::new(edge::waf::geo::GeoLookup::load(
            &config.geoip_country_db,
            &config.geoip_asn_db,
        )),
        node_control,
        https_redirect_port: config.https_redirect_port,
        max_cacheable_body: config.max_cacheable_body,
        compressed: Arc::new(edge::cache::MemoryCache::with_max_bytes(
            config.compressed_cache_entries,
            config.compressed_cache_bytes,
        )),
        cache_key_ignore_headers: config.cache_key_ignore_headers.clone(),
        origin_read_timeout_ms: config.origin_read_timeout_ms,
        origin_stream_read_timeout_ms: config.origin_stream_read_timeout_ms,
        range_fill_max_bytes: config.range_fill_max_bytes,
        downstream_keepalive_secs: config.downstream_keepalive_secs,
        downstream_h2_idle_secs: config.downstream_h2_idle_secs,
        downstream_keepalive_requests: config.downstream_keepalive_requests,
        websocket_idle_secs: config.websocket_idle_secs,
        local_http_addr,
    });

    agent::cc_sync::spawn_cc_sync(config.clone(), control.clone(), state.cc.clone());

    let admin_listen = config.admin_listen_addr.clone();
    if let Some(ref admin) = admin_listen {
        if admin == &config.listen_addr {
            anyhow::bail!("EDGE_ADMIN_LISTEN must differ from EDGE_LISTEN");
        }
    }

    // The existing cache/WAF/CC engine stays on a loopback-only Axum listener.
    // Pingora owns the public listener and forwards every data-plane request to
    // this private upstream. When EDGE_ADMIN_LISTEN is unset, management also
    // stays on the data listener for backward compatibility.
    if let Some(admin) = admin_listen {
        let admin_addr: SocketAddr = admin.parse()?;
        // Probe the socket before spawning the server. A management listener that
        // cannot bind leaves purge, cert reload and config reload unreachable while
        // the process keeps serving traffic — the control plane's purge then fails
        // silently and only shows up as purge_retry rows. Refusing to start is the
        // honest outcome.
        match std::net::TcpListener::bind(admin_addr) {
            Ok(probe) => drop(probe),
            Err(e) => {
                anyhow::bail!("cannot bind EDGE_ADMIN_LISTEN {admin_addr}: {e}");
            }
        }
        let admin_app = listener::create_admin_router(state.clone());
        tracing::info!(admin = %admin_addr, "edge management listener started");
        // Not supervised: the listener owns a bound socket, so a restart would
        // fail with "address in use" and loop. Report a panic explicitly instead,
        // and keep the error path for a normal shutdown.
        tokio::spawn(async move {
            if let Err(e) = tls::serve_http(admin_addr, admin_app).await {
                tracing::error!(error = %e, "management listener stopped");
            }
        });
    }

    let pingora_config = config.clone();
    let pingora_certs = cert_store.clone();
    let pingora_state = state.clone();
    std::thread::Builder::new()
        .name("lagran-pingora".into())
        .spawn(move || {
            if let Err(e) = edge::pingora_edge::run(pingora_config, pingora_certs, pingora_state) {
                tracing::error!(error = %e, "Pingora listener stopped");
                std::process::exit(1);
            }
        })?;

    // Keep the Tokio runtime alive for background agents and the optional admin
    // listener; Pingora runs its own runtime on the spawned thread.
    //
    // Waits on SIGTERM/SIGINT instead of pending forever. A hard kill truncates
    // streaming bodies against their own Content-Length and drops the access log
    // writer's queued records, so the process now flushes what it can before
    // exiting.
    let shutdown = edge::server::shutdown::wait_async();
    let sig = tokio::select! {
        _ = shutdown => "signal",
        _ = tokio::signal::ctrl_c() => "ctrl-c",
    };
    tracing::info!(trigger = sig, "edge shutting down");

    // Flush the access log: records already accepted are on their way to the file,
    // and the writer flushes it when the sender is dropped. Pingora's own listener
    // runs on its own runtime and cannot be stopped cooperatively yet, so this is a
    // bounded flush followed by exit rather than a full drain.
    let remaining = state
        .access_log
        .flush(std::time::Duration::from_secs(5))
        .await;
    if remaining > 0 {
        tracing::warn!(remaining, "exiting with unflushed access log records");
    }
    tracing::info!("edge stopped");
    std::process::exit(0);
}

fn random_secret() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 32];
    if SystemRandom::new().fill(&mut buf).is_ok() {
        buf.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        format!(
            "{:x}{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }
}

fn handle_cli() -> anyhow::Result<bool> {
    let command = std::env::args().nth(1);
    let Some(command) = command.as_deref() else {
        return Ok(false);
    };
    // Let Pingora's own flags pass through.
    if command.starts_with('-') {
        return Ok(false);
    }
    match command {
        "version" | "-V" | "--version" => {
            println!(
                "lagran-edge {} ({})",
                edge::version::VERSION,
                edge::version::GIT_HASH
            );
            Ok(true)
        }
        "help" | "-h" | "--help" => {
            print_help();
            Ok(true)
        }
        "check-config" | "config-check" => {
            let config = EdgeConfig::load();
            check_config(&config)?;
            Ok(true)
        }
        "health" => {
            let config = EdgeConfig::load();
            health(&config)?;
            Ok(true)
        }
        "serve" => Ok(false),
        other => {
            anyhow::bail!("unknown command {other:?}\n\n{}", help_text());
        }
    }
}

fn check_config(config: &EdgeConfig) -> anyhow::Result<()> {
    if !is_http_url(&config.control_url) {
        anyhow::bail!(
            "CONTROL_URL must start with http:// or https:// (got {:?})",
            config.control_url
        );
    }
    println!("config: ok");
    println!("listen: {}", config.listen_addr);
    println!(
        "admin_listen: {}",
        config
            .admin_listen_addr
            .as_deref()
            .unwrap_or("(same as listen)")
    );
    println!(
        "https_listen: {}",
        config.https_listen_addr.as_deref().unwrap_or("disabled")
    );
    println!("control_url: {}", config.control_url);
    println!("domain: {}", config.domain);
    println!("node_id: {}", config.node_id);
    println!("region: {}", config.region);
    println!("cache_backend: {}", config.cache_backend);
    println!(
        "redis: {}",
        if config.redis_url.trim().is_empty() {
            "disabled"
        } else {
            "configured"
        }
    );
    println!("cert_dir: {}", config.cert_dir);
    println!("waf_rulepack_cache_dir: {}", config.waf_rulepack_cache_dir);
    println!("origin_read_timeout_ms: {}", config.origin_read_timeout_ms);
    println!(
        "origin_stream_read_timeout_ms: {}",
        config.origin_stream_read_timeout_ms
    );
    println!("range_fill_max_bytes: {}", config.range_fill_max_bytes);
    println!(
        "access_log: {}",
        config.access_log_path.as_deref().unwrap_or("disabled")
    );
    println!("large_cache: {}", config.large_cache_enabled);
    Ok(())
}

fn health(config: &EdgeConfig) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    let addr = config
        .admin_listen_addr
        .as_deref()
        .unwrap_or(&config.listen_addr);
    let port = addr
        .rsplit_once(':')
        .map(|(_, port)| port)
        .ok_or_else(|| anyhow::anyhow!("invalid listen address {addr:?}"))?;
    let target: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = TcpStream::connect_timeout(&target, std::time::Duration::from_secs(3))
        .map_err(|e| anyhow::anyhow!("edge health connect failed: {e}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    stream.write_all(
        b"GET /__lagran/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response.lines().next().unwrap_or("");
    println!("health: {status}");
    if !status.contains(" 200 ") {
        anyhow::bail!("edge health check failed: {status}");
    }
    Ok(())
}

fn help_text() -> &'static str {
    "Lagran Edge\n\nUsage:\n  lagran-edge [serve]      start the data plane\n  lagran-edge check-config\n  lagran-edge health\n  lagran-edge version\n  lagran-edge help\n\nEnvironment:\n  CONTROL_URL, EDGE_LISTEN, EDGE_ADMIN_LISTEN\n  CACHE_BACKEND, DATABASE_URL, REDIS_URL\n"
}

fn print_help() {
    println!("{}", help_text());
}

fn init_tracing() {
    // RUST_LOG examples:
    //   RUST_LOG=debug
    //   RUST_LOG=lagran_edge=info,edge=info,tower_http=info
    //   RUST_LOG=info,edge::server=debug,edge::agent=debug
    //
    // `lagran_edge` is this binary's own target (`main.rs`), distinct from the `edge`
    // library crate. A filter listing only `edge=...` therefore drops every line
    // written from `main` — startup summary, shutdown, the CC wiring decision — while
    // `edge::cache` and friends keep printing, which reads like a missing log rather
    // than a filter. The default covers both.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("lagran_edge=debug,edge=debug,tower_http=info")
    });
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true),
        )
        .init();
}
