//! Pull the shared CC ban list from the control plane.
//!
//! The control plane is the single source of truth: an edge that auto-bans a
//! client reports it, and every edge (including the reporting one) refreshes
//! its local overlay from `GET /api/v1/cc/bans`.

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::server::cc::CcProtector;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct BanList {
    #[serde(default)]
    bans: Vec<Ban>,
}

#[derive(Debug, Deserialize)]
struct Ban {
    domain: String,
    ip: String,
    #[serde(default)]
    remaining_secs: u64,
}

pub fn spawn_cc_sync(config: EdgeConfig, control: ControlClient, cc: CcProtector) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.cc_sync_interval_secs.max(2));
        loop {
            match control.get_json::<BanList>("/api/v1/cc/bans").await {
                Ok(list) => {
                    let bans = list
                        .bans
                        .into_iter()
                        .filter(|b| b.remaining_secs > 0)
                        .map(|b| {
                            (
                                format!(
                                    "{}|{}",
                                    b.domain.trim_end_matches('.').to_ascii_lowercase(),
                                    b.ip
                                ),
                                b.remaining_secs,
                            )
                        })
                        .collect();
                    cc.replace_shared(bans).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "shared CC ban sync failed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}
