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
    /// Seconds left, as measured by the *control plane* when it built the reply.
    ///
    /// Relative, so the edge cannot tell how long the reply sat in flight or in a
    /// retry: applying it late bans for longer than intended. Kept as a fallback for
    /// a control plane that predates `expires_at`.
    #[serde(default)]
    remaining_secs: u64,
    /// Absolute expiry (RFC 3339). Preferred: it is immune to transfer delay.
    #[serde(default)]
    expires_at: Option<String>,
}

impl Ban {
    /// Seconds of ban still to apply, measured from now.
    ///
    /// `expires_at` is authoritative when present; the relative field is only used
    /// when it is missing or unparseable, and even then it is clamped so a stale
    /// value cannot extend a ban indefinitely.
    fn remaining_now(&self) -> u64 {
        if let Some(deadline) = self
            .expires_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            let now = chrono::Utc::now();
            let secs = (deadline.with_timezone(&chrono::Utc) - now).num_seconds();
            return secs.max(0) as u64;
        }
        self.remaining_secs
    }
}

pub fn spawn_cc_sync(config: EdgeConfig, control: ControlClient, cc: CcProtector) {
    // Supervised: a panic here would silently stop refreshing the shared ban
    // list, so this edge would keep enforcing whatever it had at that moment.
    crate::agent::spawn_supervised("cc-sync", move || {
        let config = config.clone();
        let control = control.clone();
        let cc = cc.clone();
        async move {
            let interval = Duration::from_secs(config.cc_sync_interval_secs.max(2));
            loop {
                match control.get_json::<BanList>("/api/v1/cc/bans").await {
                    Ok(list) => {
                        let bans = list
                            .bans
                            .into_iter()
                            .map(|b| {
                                let remaining = b.remaining_now();
                                (
                                    format!(
                                        "{}|{}",
                                        b.domain.trim_end_matches('.').to_ascii_lowercase(),
                                        b.ip
                                    ),
                                    remaining,
                                )
                            })
                            // Expiry is recomputed here, so a ban that elapsed during
                            // the transfer drops out instead of being applied for its
                            // full original duration.
                            .filter(|(_, remaining)| *remaining > 0)
                            .collect();
                        cc.replace_shared(bans).await;
                    }
                    Err(e) => {
                        // The local list keeps its previous contents. Entries carry
                        // their own `banned_until`, so they still expire locally; the
                        // gap only affects bans the control plane added or removed
                        // during the outage, and those converge on the next success.
                        tracing::warn!(error = %e, "shared CC ban sync failed; keeping the local list until the next attempt");
                    }
                }
                tokio::time::sleep(interval).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::Ban;

    fn ban(remaining_secs: u64, expires_at: Option<&str>) -> Ban {
        Ban {
            domain: "a.test".into(),
            ip: "203.0.113.9".into(),
            remaining_secs,
            expires_at: expires_at.map(str::to_string),
        }
    }

    /// An absolute expiry is used in preference to the relative field.
    ///
    /// The relative value was measured when the control plane built the reply, so
    /// a slow transfer or a retry meant the edge banned for longer than intended —
    /// an hour of ban could become an hour plus however long the response took.
    #[test]
    fn absolute_expiry_wins_over_the_relative_field() {
        // 10 seconds from now, while the stale relative field claims an hour.
        let deadline = (chrono::Utc::now() + chrono::Duration::seconds(10)).to_rfc3339();
        let b = ban(3600, Some(&deadline));
        let remaining = b.remaining_now();
        assert!(
            (0..=10).contains(&remaining),
            "expected the absolute expiry (~10s) to win, got {remaining}s"
        );
    }

    /// An already-expired absolute timestamp yields zero, so the ban is dropped.
    #[test]
    fn an_elapsed_ban_reports_zero() {
        let deadline = (chrono::Utc::now() - chrono::Duration::seconds(30)).to_rfc3339();
        assert_eq!(ban(3600, Some(&deadline)).remaining_now(), 0);
    }

    /// Without a usable `expires_at` the relative field is still honoured, so an
    /// older control plane keeps working.
    #[test]
    fn the_relative_field_is_the_fallback() {
        assert_eq!(ban(120, None).remaining_now(), 120);
        assert_eq!(ban(120, Some("not-a-timestamp")).remaining_now(), 120);
    }
}
