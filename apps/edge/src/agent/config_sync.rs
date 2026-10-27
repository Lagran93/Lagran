use std::sync::OnceLock;
use tokio::sync::Notify;

static CONFIG_KICK: OnceLock<Notify> = OnceLock::new();

fn config_kick() -> &'static Notify {
    CONFIG_KICK.get_or_init(Notify::new)
}

/// Ask the background config sync loop to run immediately.
pub fn request_config_reload() {
    config_kick().notify_one();
}

// Sync all accelerated domains + rules from control plane.
// Runs periodically, sends the agent token, and follows the control plane's
// aggregate version so unchanged config is not re-applied.

use crate::agent::ControlClient;
use crate::cache::policy::{CacheRule, RuleSet};
use crate::config::registry::{DomainEntry, DomainRegistry};
use crate::config::EdgeConfig;
use crate::origin::OriginClient;
use crate::waf::{
    IpNet, ManagedRules, SecurityLevel, WafAction, WafConfig, WafField, WafMode, WafOp, WafRule,
};
use serde::Deserialize;
use std::time::Duration;


#[derive(Debug, Clone, Deserialize)]
struct OriginCfg {
    host: String,
    port: u16,
    protocol: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RuleCfg {
    path_pattern: String,
    #[serde(default = "default_glob")]
    match_type: String,
    ttl_seconds: u64,
    priority: i32,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    swr_seconds: Option<u64>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    match_methods: String,
    #[serde(default)]
    match_query: String,
    #[serde(default)]
    browser_ttl_seconds: u64,
    #[serde(default)]
    ignore_query: Option<bool>,
    #[serde(default)]
    ignore_cookie: bool,
}

impl RuleCfg {
    fn into_rule(self) -> CacheRule {
        let regex = if self.match_type.eq_ignore_ascii_case("regex") {
            match regex::Regex::new(&self.path_pattern) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(pattern = %self.path_pattern, error = %e, "invalid cache rule regex; rule disabled");
                    None
                }
            }
        } else {
            None
        };
        CacheRule {
            path_pattern: self.path_pattern,
            match_type: self.match_type,
            regex,
            ttl_seconds: self.ttl_seconds,
            priority: self.priority,
            action: self.action.unwrap_or_else(|| "cache".into()),
            swr_seconds: self.swr_seconds.unwrap_or(0),
            enabled: self.enabled,
            match_methods: self.match_methods,
            match_query: self.match_query,
            browser_ttl_seconds: self.browser_ttl_seconds,
            ignore_query: self.ignore_query,
            ignore_cookie: self.ignore_cookie,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CcCfg {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    rps: u32,
    #[serde(default)]
    burst: u32,
    #[serde(default)]
    ban_after: u32,
    #[serde(default)]
    ban_seconds: u64,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    allow_ips: String,
}

impl CcCfg {
    fn into_config(self) -> crate::server::cc::CcConfig {
        let allow_ips = self
            .allow_ips
            .split(',')
            .filter_map(crate::waf::IpNet::parse)
            .collect();
        crate::server::cc::CcConfig {
            enabled: self.enabled,
            rps: self.rps,
            burst: self.burst,
            ban_after: self.ban_after,
            ban_seconds: self.ban_seconds,
            mode: crate::server::cc::CcMode::parse(&self.mode),
            allow_ips,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DomainCfg {
    domain: String,
    origin: OriginCfg,
    rules: Vec<RuleCfg>,
    #[serde(default)]
    #[allow(dead_code)]
    status: String,
    #[serde(default)]
    rate_limit_rps: u32,
    #[serde(default)]
    rate_limit_burst: u32,
    #[serde(default)]
    ignore_query_string: bool,
    #[serde(default)]
    cors_origins: String,
    #[serde(default)]
    hotlink_allow_referers: String,
    #[serde(default)]
    origin_timeout_ms: u32,
    #[serde(default)]
    custom_headers: String,
    #[serde(default)]
    ssl_enabled: bool,
    #[serde(default)]
    backup_origin: Option<OriginCfg>,
    #[serde(default)]
    waf: Option<WafCfg>,
    #[serde(default)]
    cc: Option<CcCfg>,
    version: String,
}

impl DomainCfg {
    fn into_entry(self) -> DomainEntry {
        let origin_url = format_origin(&self.origin);
        let backup_origin_url = self
            .backup_origin
            .as_ref()
            .map(format_origin)
            .unwrap_or_default();
        DomainEntry {
            domain: self.domain,
            origin_url,
            rules: self.rules.into_iter().map(RuleCfg::into_rule).collect(),
            version: self.version,
            rate_limit_rps: self.rate_limit_rps,
            rate_limit_burst: self.rate_limit_burst,
            ignore_query_string: self.ignore_query_string,
            cors_origins: self.cors_origins,
            hotlink_allow_referers: self.hotlink_allow_referers,
            origin_timeout_ms: if self.origin_timeout_ms == 0 {
                10_000
            } else {
                self.origin_timeout_ms
            },
            custom_headers: self.custom_headers,
            backup_origin_url,
            ssl_enabled: self.ssl_enabled,
            waf: into_waf(self.waf),
            cc: self.cc.map(CcCfg::into_config).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct WafCfg {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    managed: WafManagedCfg,
    #[serde(default)]
    rules: Vec<WafRuleCfg>,
    #[serde(default)]
    ip_allow: Vec<String>,
    #[serde(default)]
    ip_deny: Vec<String>,
    #[serde(default = "default_challenge_difficulty")]
    challenge_difficulty: u8,
    #[serde(default = "default_challenge_ttl")]
    challenge_ttl_secs: u64,
    #[serde(default)]
    security_level: String,
}

fn default_challenge_difficulty() -> u8 {
    4
}

fn default_challenge_ttl() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize)]
struct WafManagedCfg {
    #[serde(default = "default_true")]
    sqli: bool,
    #[serde(default = "default_true")]
    xss: bool,
    #[serde(default = "default_true")]
    traversal: bool,
    #[serde(default = "default_true")]
    scanners: bool,
    #[serde(default = "default_true")]
    rce: bool,
    #[serde(default = "default_true")]
    ssrf: bool,
    #[serde(default = "default_true")]
    xxe: bool,
    #[serde(default = "default_true")]
    log4shell: bool,
    #[serde(default = "default_true")]
    crlf: bool,
}

impl Default for WafManagedCfg {
    fn default() -> Self {
        Self {
            sqli: true,
            xss: true,
            traversal: true,
            scanners: true,
            rce: true,
            ssrf: true,
            xxe: true,
            log4shell: true,
            crlf: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_glob() -> String {
    "glob".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
struct WafRuleCfg {
    #[serde(default)]
    name: String,
    #[serde(default)]
    field: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn into_waf(cfg: Option<WafCfg>) -> WafConfig {
    let Some(cfg) = cfg else {
        return WafConfig::default();
    };
    let rules = cfg
        .rules
        .into_iter()
        .filter_map(|r| {
            let field = WafField::parse(&r.field)?;
            let op = WafOp::parse(&r.operator)?;
            let action = match r.action.trim().to_ascii_lowercase().as_str() {
                "allow" => WafAction::Allow,
                "log" => WafAction::Log,
                "challenge" => WafAction::Challenge,
                _ => WafAction::Block,
            };
            Some(WafRule {
                name: if r.name.is_empty() {
                    "custom rule".into()
                } else {
                    r.name
                },
                field,
                op,
                value: r.value.to_ascii_lowercase(),
                action,
                priority: r.priority,
                enabled: r.enabled,
            })
        })
        .collect();

    WafConfig {
        enabled: cfg.enabled,
        mode: if cfg.mode.eq_ignore_ascii_case("monitor") {
            WafMode::Monitor
        } else {
            WafMode::Block
        },
        managed: ManagedRules {
            sqli: cfg.managed.sqli,
            xss: cfg.managed.xss,
            traversal: cfg.managed.traversal,
            scanners: cfg.managed.scanners,
            rce: cfg.managed.rce,
            ssrf: cfg.managed.ssrf,
            xxe: cfg.managed.xxe,
            log4shell: cfg.managed.log4shell,
            crlf: cfg.managed.crlf,
        },
        rules,
        ip_allow: parse_nets(cfg.ip_allow),
        ip_deny: parse_nets(cfg.ip_deny),
        challenge_difficulty: cfg.challenge_difficulty.clamp(1, 6),
        challenge_ttl_secs: cfg.challenge_ttl_secs.clamp(60, 86_400),
        security_level: SecurityLevel::parse(&cfg.security_level),
    }
}

fn parse_nets(entries: Vec<String>) -> Vec<IpNet> {
    entries.iter().filter_map(|s| IpNet::parse(s)).collect()
}

fn format_origin(o: &OriginCfg) -> String {
    format!("{}://{}:{}", o.protocol, o.host, o.port)
}

#[derive(Debug, Clone, Deserialize)]
struct AllConfig {
    domains: Vec<DomainCfg>,
    version: String,
}

pub fn spawn_config_sync(
    config: EdgeConfig,
    control: ControlClient,
    origin: OriginClient,
    rules: RuleSet,
    registry: DomainRegistry,
) {
    tokio::spawn(async move {
        tracing::info!(url = %control.endpoint("/api/v1/config"), "domain registry sync started");
        let mut last_version = String::new();

        loop {
            match control.get_json::<AllConfig>("/api/v1/config").await {
                Ok(cfg) => {
                    if cfg.version != last_version {
                        let entries: Vec<DomainEntry> =
                            cfg.domains.into_iter().map(DomainCfg::into_entry).collect();
                        let n = entries.len();
                        registry
                            .replace_all(entries.clone(), cfg.version.clone())
                            .await;
                        // Global rule set is only a legacy single-domain fallback,
                        // so keep the union but never use it for onboarded hosts.
                        rules
                            .replace(
                                entries
                                    .iter()
                                    .flat_map(|e| e.rules.iter().cloned())
                                    .collect(),
                            )
                            .await;

                        if !config.domain.is_empty() {
                            if let Some(d) = registry.get(&config.domain).await {
                                origin.set_base_url(d.origin_url.clone()).await;
                            }
                        }

                        tracing::info!(domains = n, version = %cfg.version, "domain registry updated");
                        last_version = cfg.version;
                    }
                }
                Err(e) => tracing::warn!(error = %e, "config sync failed"),
            }

            // Single-domain fallback if EDGE_DOMAIN is set and the registry is empty.
            if !config.domain.is_empty() && registry.is_empty().await {
                let path = format!("/api/v1/config/{}", config.domain);
                match control.get_json::<DomainCfg>(&path).await {
                    Ok(d) => {
                        let entry = d.into_entry();
                        origin.set_base_url(entry.origin_url.clone()).await;
                        rules.replace(entry.rules.clone()).await;
                        registry.upsert(entry).await;
                    }
                    Err(e) => tracing::debug!(error = %e, "single-domain config fetch failed"),
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(config.config_sync_interval_secs.max(5))) => {}
                _ = config_kick().notified() => {
                    tracing::info!("config reload requested; pulling immediately");
                }
            }
        }
    });
}
