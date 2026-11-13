//! The interested hosts cached as the reference caches them (#815;
//! `ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//! a discovery's answer kept five minutes (`:409-411`, `:445`,
//! `this.#interestedHostsTtlMs = 5 * 60 * 1000`) and one discovery in
//! flight at a time (`:700-718`):
//!
//! ```text
//! 700:    const now = Date.now()
//! 701:    if (this.#interestedHostsCache != null && this.#interestedHostsCache.expiresAt > now) {
//! 702:      return this.#interestedHostsCache.hosts
//! 706:    if (this.#interestedHostsInFlight != null) {
//! 707:      return await this.#interestedHostsInFlight
//! 710:    this.#interestedHostsInFlight = this.#fetchInterestedHosts()
//! 712:      const hosts = await this.#interestedHostsInFlight
//! 713:      this.#interestedHostsCache = { hosts, expiresAt: Date.now() + this.#interestedHostsTtlMs }
//! 716:      this.#interestedHostsInFlight = null
//! ```
//!
//! Here the in-flight promise is an async mutex held across the fetch: a
//! caller arriving while a discovery runs waits for the lock and reads the
//! leader's answer from the cache. A failed discovery caches nothing, as
//! there; its `Err` is the leader's alone, and a waiter then asks for
//! itself, where the reference's waiters receive the leader's rejection
//! (stated, #815). An empty answer is cached, as the reference caches it.
//! The clock is `crate::util`'s wall clock (rule 6), behind a seam the
//! unit tests move.

use crate::Result;
use futures::lock::Mutex;
use std::collections::{HashMap, HashSet};
use std::future::Future;

/// The interested hosts: each host's origin and the topics it takes.
pub(super) type InterestedHosts = HashMap<String, HashSet<String>>;

/// `#interestedHostsTtlMs` (`:445`): five minutes.
pub(super) const INTERESTED_HOSTS_TTL_MS: u64 = 5 * 60 * 1000;

struct Cached {
    hosts: InterestedHosts,
    expires_at: u64,
}

/// One broadcaster's cache and in-flight lock.
pub(super) struct InterestedHostsCache {
    cached: Mutex<Option<Cached>>,
    now_ms: fn() -> u64,
}

impl InterestedHostsCache {
    pub(super) fn new() -> Self {
        Self::with_clock(crate::util::time::current_time_ms)
    }

    /// The seam: a cache reading `now_ms` for the time.
    pub(super) fn with_clock(now_ms: fn() -> u64) -> Self {
        Self {
            cached: Mutex::new(None),
            now_ms,
        }
    }

    /// The cached answer while it has not expired (`expiresAt > now`),
    /// else `fetch`'s, cached on success alone for five minutes from when
    /// it answered.
    pub(super) async fn get_or_fetch<F, Fut>(&self, fetch: F) -> Result<InterestedHosts>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<InterestedHosts>>,
    {
        let mut cached = self.cached.lock().await;
        if let Some(c) = cached.as_ref() {
            if c.expires_at > (self.now_ms)() {
                return Ok(c.hosts.clone());
            }
        }
        let hosts = fetch().await?;
        *cached = Some(Cached {
            hosts: hosts.clone(),
            expires_at: (self.now_ms)().saturating_add(INTERESTED_HOSTS_TTL_MS),
        });
        Ok(hosts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static NOW: AtomicU64 = AtomicU64::new(1_000_000);

    fn now() -> u64 {
        NOW.load(Ordering::SeqCst)
    }

    fn hosts(name: &str) -> InterestedHosts {
        HashMap::from([(name.to_string(), HashSet::from(["tm_a".to_string()]))])
    }

    #[tokio::test]
    async fn the_interested_hosts_are_asked_again_after_five_minutes_815() {
        let cache = InterestedHostsCache::with_clock(now);
        let asked = AtomicUsize::new(0);
        let fetch = |name: &'static str| {
            let asked = &asked;
            move || async move {
                asked.fetch_add(1, Ordering::SeqCst);
                Ok(hosts(name))
            }
        };
        let start = now();
        assert_eq!(
            cache.get_or_fetch(fetch("one")).await.unwrap(),
            hosts("one")
        );
        // One millisecond short of five minutes: the cached answer
        NOW.store(start + INTERESTED_HOSTS_TTL_MS - 1, Ordering::SeqCst);
        assert_eq!(
            cache.get_or_fetch(fetch("two")).await.unwrap(),
            hosts("one")
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // At five minutes `expiresAt > now` is false: asked again
        NOW.store(start + INTERESTED_HOSTS_TTL_MS, Ordering::SeqCst);
        assert_eq!(
            cache.get_or_fetch(fetch("two")).await.unwrap(),
            hosts("two")
        );
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        // The new answer kept five minutes from when it answered
        NOW.store(start + 2 * INTERESTED_HOSTS_TTL_MS - 1, Ordering::SeqCst);
        assert_eq!(
            cache.get_or_fetch(fetch("three")).await.unwrap(),
            hosts("two")
        );
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failure_is_not_cached_and_an_empty_answer_is_815() {
        fn fixed() -> u64 {
            7
        }
        let cache = InterestedHostsCache::with_clock(fixed);
        let refused = cache
            .get_or_fetch(|| async { Err(Error::OverlayError("down".into())) })
            .await;
        assert_eq!(refused, Err(Error::OverlayError("down".into())));
        let empty = cache.get_or_fetch(|| async { Ok(HashMap::new()) }).await;
        assert_eq!(empty, Ok(HashMap::new()));
        let again = cache.get_or_fetch(|| async { Ok(hosts("late")) }).await;
        assert_eq!(again, Ok(HashMap::new()));
    }
}
