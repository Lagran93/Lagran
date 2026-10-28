//! Health and readiness endpoints

use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub database: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "lagran-control",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, StatusCode> {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => Ok(Json(ReadyResponse {
            status: "ready",
            service: "lagran-control",
            version: env!("CARGO_PKG_VERSION"),
            database: "ok",
        })),
        Err(e) => {
            tracing::error!(error = %e, "readiness db check failed");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

use axum::response::IntoResponse;
use chrono::{DateTime, Utc};

/// Prometheus text exposition for the control plane.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let db_up = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok() as u8;
    let mut out = String::with_capacity(4096);
    out.push_str("# HELP lagran_control_up Control plane process up\n# TYPE lagran_control_up gauge\nlagran_control_up 1\n");
    out.push_str(&format!(
        "# HELP lagran_control_info Build information\n# TYPE lagran_control_info gauge\nlagran_control_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!(
        "# HELP lagran_control_db_up Database reachable\n# TYPE lagran_control_db_up gauge\nlagran_control_db_up {db_up}\n"
    ));

    let domains: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, COUNT(*)::BIGINT FROM domains GROUP BY status")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    out.push_str(
        "# HELP lagran_domains_total Domains by status\n# TYPE lagran_domains_total gauge\n",
    );
    for (status, count) in domains {
        out.push_str(&format!(
            "lagran_domains_total{{status=\"{}\"}} {count}\n",
            escape_label(&status)
        ));
    }

    let nodes: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, COUNT(*)::BIGINT FROM nodes GROUP BY status")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    out.push_str(
        "# HELP lagran_nodes_total Edge nodes by status\n# TYPE lagran_nodes_total gauge\n",
    );
    for (status, count) in nodes {
        out.push_str(&format!(
            "lagran_nodes_total{{status=\"{}\"}} {count}\n",
            escape_label(&status)
        ));
    }

    let origins: Vec<(String, String, bool, i32)> = sqlx::query_as(
        "SELECT domain_name, origin_url, healthy, consecutive_fails FROM origin_health",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    out.push_str("# HELP lagran_origin_health Origin health (1 healthy, 0 unhealthy)\n# TYPE lagran_origin_health gauge\n");
    out.push_str("# HELP lagran_origin_consecutive_failures Consecutive origin probe failures\n# TYPE lagran_origin_consecutive_failures gauge\n");
    for (domain, origin, healthy, fails) in origins {
        let labels = format!(
            "domain=\"{}\",origin=\"{}\"",
            escape_label(&domain),
            escape_label(&origin)
        );
        out.push_str(&format!(
            "lagran_origin_health{{{labels}}} {}\n",
            if healthy { 1 } else { 0 }
        ));
        out.push_str(&format!(
            "lagran_origin_consecutive_failures{{{labels}}} {}\n",
            fails.max(0)
        ));
    }

    let certs: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT domain_name, not_after FROM certificates WHERE not_after IS NOT NULL AND status = 'active'",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    out.push_str("# HELP lagran_cert_expiry_timestamp_seconds Certificate expiry as Unix timestamp\n# TYPE lagran_cert_expiry_timestamp_seconds gauge\n");
    for (domain, not_after) in certs {
        out.push_str(&format!(
            "lagran_cert_expiry_timestamp_seconds{{domain=\"{}\"}} {}\n",
            escape_label(&domain),
            not_after.timestamp()
        ));
    }

    let firing: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_events WHERE status = 'firing'")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);
    let channels: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_channels WHERE enabled = TRUE")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);
    out.push_str("# HELP lagran_alerts_firing Alert events currently firing\n# TYPE lagran_alerts_firing gauge\n");
    out.push_str(&format!("lagran_alerts_firing {firing}\n"));
    out.push_str("# HELP lagran_alert_channels_enabled Enabled notification channels\n# TYPE lagran_alert_channels_enabled gauge\n");
    out.push_str(&format!("lagran_alert_channels_enabled {channels}\n"));

    let (requests, hits): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(requests),0)::BIGINT, COALESCE(SUM(cache_hits),0)::BIGINT \
         FROM edge_metrics WHERE reported_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0));
    let ratio = if requests > 0 {
        hits as f64 * 100.0 / requests as f64
    } else {
        0.0
    };
    out.push_str("# HELP lagran_edge_requests_24h Requests reported in the last 24 hours\n# TYPE lagran_edge_requests_24h gauge\n");
    out.push_str(&format!("lagran_edge_requests_24h {requests}\n"));
    out.push_str("# HELP lagran_edge_cache_hit_ratio_24h Cache hit ratio percent in the last 24 hours\n# TYPE lagran_edge_cache_hit_ratio_24h gauge\n");
    out.push_str(&format!("lagran_edge_cache_hit_ratio_24h {ratio:.4}\n"));

    let waf: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM waf_events WHERE ts > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    out.push_str("# HELP lagran_waf_events_24h WAF events in the last 24 hours\n# TYPE lagran_waf_events_24h gauge\n");
    out.push_str(&format!("lagran_waf_events_24h {waf}\n"));

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}
