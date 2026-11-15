//! The queue `HostReputationTracker::subscribe` hands back (#843dforeign).

use super::host_reputation_tracker::RankChangeEvent;
use tokio::sync::broadcast::{
    self,
    error::{RecvError, TryRecvError},
};

/// The queue [`HostReputationTracker::subscribe`] hands back: this crate's
/// type (#843dforeign), so no public signature names another crate's channel
/// and a `tokio` major is never this crate's break. The rank events are this
/// crate's addition: the reference's tracker has no subscription
/// (`ts-stack@edf6e03` `HostReputationTracker.ts:87-205`).
///
/// Events arrive in the order the tracker sent them, each receiver reading
/// every event sent after its `subscribe`. [`recv`] waits for the next; it
/// answers `None` once the tracker is gone and the queue is empty (the
/// process-wide tracker is never gone). [`try_recv`] answers at once. Neither
/// needs a runtime: any executor drives `recv`.
///
/// The tracker keeps the newest 64 events. A receiver further behind does not
/// fail: it reads on from the oldest event kept, and [`missed`] counts the
/// events it passed over. `Debug` prints no event.
///
/// [`HostReputationTracker::subscribe`]: super::HostReputationTracker::subscribe
/// [`recv`]: RankChangeReceiver::recv
/// [`try_recv`]: RankChangeReceiver::try_recv
/// [`missed`]: RankChangeReceiver::missed
pub struct RankChangeReceiver {
    inner: broadcast::Receiver<RankChangeEvent>,
    missed: u64,
}

impl RankChangeReceiver {
    pub(super) fn new(inner: broadcast::Receiver<RankChangeEvent>) -> Self {
        Self { inner, missed: 0 }
    }

    /// The next event, waiting for it; `None` once the tracker is gone and
    /// every queued event has been taken, and `None` again on every call
    /// after that. A lag is counted in [`missed`](Self::missed) and read past.
    pub async fn recv(&mut self) -> Option<RankChangeEvent> {
        loop {
            match self.inner.recv().await {
                Ok(event) => return Some(event),
                Err(RecvError::Lagged(passed)) => self.count(passed),
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// The next queued event without waiting; `None` when the queue is empty
    /// now (the tracker may still send more) or the tracker is gone. A lag is
    /// counted in [`missed`](Self::missed) and read past.
    pub fn try_recv(&mut self) -> Option<RankChangeEvent> {
        loop {
            match self.inner.try_recv() {
                Ok(event) => return Some(event),
                Err(TryRecvError::Lagged(passed)) => self.count(passed),
                Err(TryRecvError::Empty | TryRecvError::Closed) => return None,
            }
        }
    }

    /// How many events this receiver passed over because it was more than the
    /// tracker's 64 kept events behind; 0 for a receiver that kept up.
    pub fn missed(&self) -> u64 {
        self.missed
    }

    fn count(&mut self, passed: u64) {
        self.missed = self.missed.saturating_add(passed);
    }
}

impl std::fmt::Debug for RankChangeReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RankChangeReceiver")
            .field("missed", &self.missed)
            .finish_non_exhaustive()
    }
}
