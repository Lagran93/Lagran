//! Single-flight helper: collapse concurrent origin fetches for the same key.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};

#[derive(Clone, Default)]
pub struct Inflight {
    inner: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
}

pub enum Slot {
    Leader(Leader),
    Follower(watch::Receiver<bool>),
}

pub struct Leader {
    inner: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
    key: String,
    tx: watch::Sender<bool>,
    finished: bool,
}

impl Inflight {
    /// Start (or join) the fetch for `key`.
    pub async fn begin(&self, key: &str) -> Slot {
        let mut map = self.inner.lock().await;
        // A completed/abandoned leader leaves its sender behind with `true`;
        // treat that as free so the next caller can lead again.
        let stale = map.get(key).map(|tx| *tx.borrow()).unwrap_or(false);
        if stale {
            map.remove(key);
        } else if let Some(tx) = map.get(key) {
            return Slot::Follower(tx.subscribe());
        }
        let (tx, _rx) = watch::channel(false);
        map.insert(key.to_string(), tx.clone());
        Slot::Leader(Leader {
            inner: self.inner.clone(),
            key: key.to_string(),
            tx,
            finished: false,
        })
    }

    pub async fn in_flight(&self) -> usize {
        self.inner.lock().await.len()
    }
}

impl Leader {
    /// Wake followers and clear the key. Safe to call once; a later call is a no-op.
    pub async fn finish(mut self) {
        self.finished = true;
        self.tx.send_replace(true);
        self.inner.lock().await.remove(&self.key);
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Panic/cancel path: release waiters best-effort. `remove` is async, so
        // only signal; followers re-check the cache and fall back to fetching.
        self.tx.send_replace(true);
    }
}

/// Wait until the in-flight fetch for a key completes (or the timeout elapses).
pub async fn wait_for(receiver: &mut watch::Receiver<bool>, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, receiver.wait_for(|done| *done)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
impl Inflight {
    fn new_for_test() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn second_caller_waits_for_leader() {
        let inflight = Inflight::new_for_test();
        let leader = match inflight.begin("k").await {
            Slot::Leader(l) => l,
            _ => panic!("expected leader"),
        };
        let mut follower = match inflight.begin("k").await {
            Slot::Follower(rx) => rx,
            _ => panic!("expected follower"),
        };
        assert_eq!(inflight.in_flight().await, 1);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            leader.finish().await;
        });
        assert!(wait_for(&mut follower, Duration::from_secs(1)).await);
        assert_eq!(inflight.in_flight().await, 0);

        // A later caller becomes leader again.
        assert!(matches!(inflight.begin("k").await, Slot::Leader(_)));
    }

    #[tokio::test]
    async fn timeout_when_leader_hangs() {
        let inflight = Inflight::new_for_test();
        let _leader = match inflight.begin("slow").await {
            Slot::Leader(l) => l,
            _ => panic!(),
        };
        let mut follower = match inflight.begin("slow").await {
            Slot::Follower(rx) => rx,
            _ => panic!(),
        };
        assert!(!wait_for(&mut follower, Duration::from_millis(20)).await);
    }
}
