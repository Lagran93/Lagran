//! Periodic alert evaluation, deduplication and notification delivery.

use crate::repository::{self, AlertChannelRow, AlertEventRow, AlertRuleRow};
use crate::service::notify;
use chrono::Utc;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone)]
struct Finding {
    fingerprint: String,
    severity: &'static str,
    value: f64,
    message: String,
}

pub fn spawn(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.clamp(5, 3600));
        tracing::info!(?interval, "alert evaluator started");
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = run_once(&pool).await {
                tracing::warn!(error = %e, "alert evaluation failed");
            }
        }
    });
}

async fn run_once(pool: &PgPool) -> Result<(), sqlx::Error> {
    let rules = repository::list_alert_rules(pool).await?;
    let channels = repository::list_alert_channels(pool).await?;
    let by_id: HashMap<String, AlertChannelRow> = channels
        .into_iter()
        .map(|c| (c.id.to_string(), c))
        .collect();
    for rule in rules.into_iter().filter(|r| r.enabled) {
        if let Err(e) = evaluate_rule(pool, &rule, &by_id).await {
            tracing::warn!(rule = %rule.name, error = %e, "alert rule evaluation failed");
        }
    }
    Ok(())
}

async fn evaluate_rule(
    pool: &PgPool,
    rule: &AlertRuleRow,
    channels: &HashMap<String, AlertChannelRow>,
) -> Result<(), sqlx::Error> {
    let findings = findings_for(pool, rule).await?;
    let active = repository::active_alert_events(pool, rule.id).await?;
    let active_by_fp: HashMap<&str, &AlertEventRow> =
        active.iter().map(|e| (e.fingerprint.as_str(), e)).collect();
    let current: HashSet<&str> = findings.iter().map(|f| f.fingerprint.as_str()).collect();

    for finding in &findings {
        if let Some(event) = active_by_fp.get(finding.fingerprint.as_str()) {
            let _ =
                repository::refresh_alert_event(pool, event.id, finding.value, &finding.message)
                    .await;
            if !event.notified {
                let subject = format!("[Lagran] {}", rule.name);
                if notify_channels(channels, rule, event, &subject, false).await {
                    let _ = repository::mark_alert_notified(pool, event.id).await;
                    let _ = repository::touch_alert_rule(pool, rule.id).await;
                }
            }
            continue;
        }
        let event = repository::insert_alert_event(
            pool,
            rule,
            &finding.fingerprint,
            finding.severity,
            finding.value,
            &finding.message,
        )
        .await?;
        let should_notify = match rule.last_triggered_at {
            Some(last) => {
                Utc::now().signed_duration_since(last).num_seconds()
                    >= i64::from(rule.cooldown_seconds.max(0))
            }
            None => true,
        };
        if should_notify {
            let subject = format!("[Lagran] {}", rule.name);
            let delivered = notify_channels(channels, rule, &event, &subject, false).await;
            if delivered {
                let _ = repository::mark_alert_notified(pool, event.id).await;
            }
            let _ = repository::touch_alert_rule(pool, rule.id).await;
        }
    }

    for event in active.iter() {
        if !current.contains(event.fingerprint.as_str()) {
            let _ = repository::resolve_alert_event(pool, event.id).await;
            if event.notified {
                let subject = format!("[Lagran] 恢复：{}", rule.name);
                notify_channels(channels, rule, event, &subject, true).await;
            }
        }
    }
    Ok(())
}

async fn notify_channels(
    channels: &HashMap<String, AlertChannelRow>,
    rule: &AlertRuleRow,
    event: &AlertEventRow,
    subject: &str,
    recovery: bool,
) -> bool {
    let mut any = false;
    for id in &rule.channel_ids.0 {
        let Some(channel) = channels.get(id) else {
            continue;
        };
        if !channel.enabled {
            continue;
        }
        let text = if recovery {
            format!(
                "规则：{}\n对象：{}\n状态：已恢复",
                rule.name, event.fingerprint
            )
        } else {
            format!(
                "规则：{}\n级别：{}\n对象：{}\n当前值：{:.2}\n\n{}",
                rule.name, event.severity, event.fingerprint, event.value, event.message
            )
        };
        match notify::send_channel(
            &channel.kind,
            &channel.config.0,
            subject,
            &text,
            &event.severity,
        )
        .await
        {
            Ok(()) => any = true,
            Err(e) => tracing::warn!(
                channel = %channel.name,
                kind = %channel.kind,
                error = %e,
                "alert notification failed"
            ),
        }
    }
    any
}

async fn findings_for(pool: &PgPool, rule: &AlertRuleRow) -> Result<Vec<Finding>, sqlx::Error> {
    match rule.metric.as_str() {
        "origin_unhealthy" => origin_findings(pool, rule.threshold).await,
        "cert_expiring" => cert_findings(pool, rule.threshold).await,
        "node_offline" => node_findings(pool, rule.threshold).await,
        "cache_hit_ratio" => cache_findings(pool, rule).await,
        "waf_spike" => waf_findings(pool, rule).await,
        _ => Ok(Vec::new()),
    }
}

async fn origin_findings(pool: &PgPool, threshold: f64) -> Result<Vec<Finding>, sqlx::Error> {
    let min_fails = threshold.max(1.0) as i32;
    let rows: Vec<(String, String, i32, String)> = sqlx::query_as(
        r#"
        SELECT domain_name, origin_url, consecutive_fails, last_error
        FROM origin_health
        WHERE healthy = FALSE AND consecutive_fails >= $1
        ORDER BY domain_name, origin_url
        "#,
    )
    .bind(min_fails)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(domain, origin, fails, error)| Finding {
            fingerprint: format!("{domain}|{origin}"),
            severity: "critical",
            value: fails as f64,
            message: format!(
                "源站健康检查失败，连续失败 {fails} 次。\n域名：{domain}\n源站：{origin}\n错误：{}",
                if error.is_empty() {
                    "未知错误"
                } else {
                    &error
                }
            ),
        })
        .collect())
}

async fn cert_findings(pool: &PgPool, threshold: f64) -> Result<Vec<Finding>, sqlx::Error> {
    let days = threshold.max(0.0);
    let rows: Vec<(String, f64)> = sqlx::query_as(
        r#"
        SELECT domain_name,
               (EXTRACT(EPOCH FROM (not_after - NOW())) / 86400.0)::DOUBLE PRECISION
        FROM certificates
        WHERE status = 'active'
          AND not_after IS NOT NULL
          AND not_after <= NOW() + make_interval(days => $1::int)
        ORDER BY not_after
        "#,
    )
    .bind(days.ceil() as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(domain, days_left)| Finding {
            fingerprint: format!("cert|{domain}"),
            severity: "warning",
            value: days_left,
            message: format!(
                "证书即将到期。\n域名：{domain}\n剩余时间：{:.1} 天",
                days_left.max(0.0)
            ),
        })
        .collect())
}

async fn node_findings(pool: &PgPool, threshold: f64) -> Result<Vec<Finding>, sqlx::Error> {
    let minutes = threshold.max(1.0);
    let rows: Vec<(String, String, f64)> = sqlx::query_as(
        r#"
        SELECT name, status,
               (EXTRACT(EPOCH FROM (NOW() - COALESCE(last_heartbeat, created_at))) / 60.0)::DOUBLE PRECISION
        FROM nodes
        WHERE status IN ('offline', 'pending')
          AND EXTRACT(EPOCH FROM (NOW() - COALESCE(last_heartbeat, created_at))) / 60.0 >= $1
        ORDER BY name
        "#,
    )
    .bind(minutes)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, status, offline_minutes)| Finding {
            fingerprint: format!("node|{name}"),
            severity: "critical",
            value: offline_minutes,
            message: format!(
                "边缘节点离线。\n节点：{name}\n状态：{status}\n已离线：{:.1} 分钟",
                offline_minutes
            ),
        })
        .collect())
}

async fn cache_findings(pool: &PgPool, rule: &AlertRuleRow) -> Result<Vec<Finding>, sqlx::Error> {
    let window = rule.window_minutes.clamp(1, 1440);
    let (requests, hits): (i64, i64) = sqlx::query_as(
        r#"
        SELECT COALESCE(SUM(requests), 0)::BIGINT,
               COALESCE(SUM(cache_hits), 0)::BIGINT
        FROM edge_metrics
        WHERE reported_at > NOW() - make_interval(mins => $1)
        "#,
    )
    .bind(window)
    .fetch_one(pool)
    .await?;
    if requests <= 0 {
        return Ok(Vec::new());
    }
    let ratio = hits as f64 * 100.0 / requests as f64;
    if ratio >= rule.threshold {
        return Ok(Vec::new());
    }
    Ok(vec![Finding {
        fingerprint: "global".into(),
        severity: "warning",
        value: ratio,
        message: format!(
            "缓存命中率低于阈值。\n最近 {window} 分钟命中率：{ratio:.1}%\n阈值：{:.1}%\n请求数：{requests}",
            rule.threshold
        ),
    }])
}

async fn waf_findings(pool: &PgPool, rule: &AlertRuleRow) -> Result<Vec<Finding>, sqlx::Error> {
    let window = rule.window_minutes.clamp(1, 1440);
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM waf_events
        WHERE ts > NOW() - make_interval(mins => $1)
        "#,
    )
    .bind(window)
    .fetch_one(pool)
    .await?;
    if (count as f64) < rule.threshold {
        return Ok(Vec::new());
    }
    Ok(vec![Finding {
        fingerprint: "global".into(),
        severity: "warning",
        value: count as f64,
        message: format!(
            "WAF 拦截量突增。\n最近 {window} 分钟事件数：{count}\n阈值：{:.0}",
            rule.threshold
        ),
    }])
}
