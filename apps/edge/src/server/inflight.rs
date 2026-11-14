//! Single-flight helper: collapse concurrent origin fetches for the same key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// Key -> sender for the fetch currently leading that key.
///
/// A `std::sync::Mutex` rather than `tokio::sync::Mutex` on purpose: the guard is
/// only ever held across a HashMap lookup or insert (no await), and a synchronous
/// lock is what lets `Leader::drop` remove its own entry. With an async mutex the
/// drop path could not await, so a cancelled leader left its key behind forever —
/// and a signed download URL is unique, so no later request would ever reclaim it.
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
        let mut map = self.lock();
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
        self.lock().len()
    }

    /// Lock the map, recovering from a poisoned mutex.
    ///
    /// A panic while the guard is held would otherwise poison the lock and turn
    /// every later `begin` into a panic. The map only holds senders, which stay
    /// valid whatever the panicking task did, so the data is safe to reuse.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, watch::Sender<bool>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Leader {
    /// Wake followers and clear the key. Safe to call once; a later call is a no-op.
    pub async fn finish(mut self) {
        self.finished = true;
        self.tx.send_replace(true);
        self.remove_if_owner();
    }

    /// Remove the entry only while it is still ours.
    ///
    /// Signalling `true` before removing leaves a window in which a new leader
    /// can claim the key; an unconditional `remove` then evicted *that* leader,
    /// so a follower subscribed to it never got a wake-up and the key stayed
    /// unowned.
    fn remove_if_owner(&self) {
        if let Ok(mut map) = self.inner.lock() {
            if map
                .get(&self.key)
                .is_some_and(|tx| tx.same_channel(&self.tx))
            {
                map.remove(&self.key);
            }
        }
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Cancel/panic path: wake followers and release the key. Followers then
        // re-check the cache and fall back to fetching. Removing the entry here is
        // what keeps the map bounded; signalling alone leaked one entry per
        // cancelled request on a key that is never requested again.
        self.tx.send_replace(true);
        self.remove_if_owner();
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
    /// A cancelled (dropped) leader must release its key immediately.
    ///
    /// This is the normal path when a client disconnects mid-fetch. The entry used
    /// to be removed only by a later request for the same key, so a unique URL
    /// (a signed download) leaked one map entry per cancellation, forever.
    #[tokio::test]
    async fn stale_leader_does_not_remove_the_new_owner() {
        let inflight = Inflight::default();
        let Slot::Leader(leader) = inflight.begin("k").await else {
            panic!("expected leader");
        };
        // Simulate a new leader claiming the key after the old sender was
        // signalled but before the old leader's cleanup ran.
        {
            let mut map = inflight.lock();
            map.insert("k".to_string(), watch::channel(false).0);
        }
        drop(leader);
        assert!(
            inflight.lock().contains_key("k"),
            "stale leader removed the new leader's entry"
        );
    }

    #[tokio::test]
    async fn dropped_leader_releases_its_key() {
        let inflight = Inflight::new_for_test();
        {
            let _leader = match inflight.begin("cancelled").await {
                Slot::Leader(l) => l,
                _ => panic!("expected leader"),
            };
            assert_eq!(inflight.in_flight().await, 1);
            // Dropped here without `finish`, as on a cancelled request.
        }
        assert_eq!(
            inflight.in_flight().await,
            0,
            "a dropped leader must not leave its key behind"
        );
    }

    /// Many cancelled fetches on distinct keys must not accumulate.
    #[tokio::test]
    async fn repeated_cancellation_does_not_accumulate() {
        let inflight = Inflight::new_for_test();
        for i in 0..50 {
            let key = format!("signed-{i}");
            let leader = match inflight.begin(&key).await {
                Slot::Leader(l) => l,
                _ => panic!("expected leader"),
            };
            drop(leader);
        }
        assert_eq!(
            inflight.in_flight().await,
            0,
            "cancelled unique keys must not pile up"
        );
    }

    /// A follower waiting on a leader that is dropped must be woken, not stranded.
    #[tokio::test]
    async fn dropping_the_leader_wakes_followers() {
        let inflight = Inflight::new_for_test();
        let leader = match inflight.begin("k").await {
            Slot::Leader(l) => l,
            _ => panic!("expected leader"),
        };
        let mut follower = match inflight.begin("k").await {
            Slot::Follower(rx) => rx,
            _ => panic!("expected follower"),
        };
        drop(leader);
        assert!(
            wait_for(&mut follower, Duration::from_secs(1)).await,
            "followers must be released when the leader disappears"
        );
        assert_eq!(inflight.in_flight().await, 0);
    }
}
