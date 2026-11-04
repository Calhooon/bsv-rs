//! The SLAP discovery's backoff rules (#769), beside the parent file, which
//! sits under the ratchet's 800-line bound: the trackers a discovery may ask
//! and the refusal when every one is backing off, and the reuse rule of a
//! cached host list (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:1898-1903`,
//! `:2284-2314`).

use super::{now_ms, LookupResolver};
use crate::{Error, Result};

impl LookupResolver {
    /// The SLAP trackers not backing off, best ranked first; no trackers
    /// configured is no tracker to ask. Every tracker backing off is the
    /// reference's refusal (`prepareHostsForQuery`, `:2306-2314`, caught at
    /// `:1963` and thrown by the query at `:1671`), its wait the soonest end
    /// of a tracker's backoff:
    ///
    /// ```text
    /// const soonest = Math.min(...ranked.map(h => h.backoffUntil))
    /// const waitMs = Math.max(soonest - now, 0)
    /// throw new Error(
    ///   `All ${context} hosts are backing off for approximately ${waitMs}ms due to repeated failures.`
    /// ```
    pub(super) fn available_slap_trackers(&self) -> Result<Vec<String>> {
        let now = now_ms();
        let ranked = self
            .reputation_tracker
            .rank_hosts_at(&self.slap_trackers, now);
        let available: Vec<String> = ranked
            .iter()
            .filter(|h| h.entry.backoff_until <= now)
            .map(|h| h.entry.host.clone())
            .collect();
        if !available.is_empty() || ranked.is_empty() {
            return Ok(available);
        }
        let soonest = ranked.iter().map(|h| h.entry.backoff_until).min();
        Err(Error::OverlayError(format!(
            "All SLAP trackers hosts are backing off for approximately {}ms due to repeated failures.",
            soonest.unwrap_or(now).saturating_sub(now)
        )))
    }

    /// A discovery's refusal read beside the service's additional hosts: the
    /// reference admits them whatever its trackers do (`:2063-2071`) and
    /// refuses only when no host was admitted (`:1669-1671`), so with some
    /// configured the refusal is an empty discovery they stand beside.
    pub(super) fn beside_additional_hosts(
        &self,
        service: &str,
        discovered: Result<Vec<String>>,
    ) -> Result<Vec<String>> {
        match discovered {
            Err(_)
                if self
                    .additional_hosts
                    .get(service)
                    .is_some_and(|h| !h.is_empty()) =>
            {
                Ok(Vec::new())
            }
            discovered => discovered,
        }
    }

    /// Whether a cached host list may be reused: some host in it is not
    /// backing off (`lookupCacheHasAvailableHost`, `:1898-1903`; a cache
    /// without one refreshes, `:1913-1918`). An empty list has none, so it
    /// is never reused.
    pub(super) fn has_available_host(&self, hosts: &[String], now: u64) -> bool {
        hosts.iter().any(|host| {
            self.reputation_tracker
                .snapshot(host)
                .map_or(0, |entry| entry.backoff_until)
                <= now
        })
    }
}

#[cfg(test)]
mod waiter_tests_769 {
    use super::*;
    use crate::overlay::LookupResolverConfig;
    use tokio::sync::watch;

    /// A lookup that joined an in-flight discovery receives the leader's
    /// error itself, its text the leader's (#769's fold; until then the
    /// leader's `to_string()` wrapped again, `overlay error: overlay error:
    /// All SLAP ...`). On one thread the public path never yields between a
    /// leader's registration and its broadcast (the refusal comes before any
    /// `.await`); two threads sharing one resolver (`Send + Sync`) can race
    /// into the waiter's arm, but not on demand, so the sender is registered
    /// here.
    #[tokio::test]
    async fn a_waiter_on_a_refused_discovery_receives_the_leader_error_769() {
        let service = "ls_waiter_refusal";
        let resolver = LookupResolver::new(LookupResolverConfig::default());
        let leader = Error::OverlayError(
            "All SLAP trackers hosts are backing off for approximately 7ms due to repeated failures."
                .into(),
        );
        let (tx, _rx) = watch::channel(None);
        resolver
            .hosts_in_flight
            .write()
            .await
            .insert(service.to_string(), tx.clone());
        let broadcast = async {
            tokio::task::yield_now().await;
            let _ = tx.send(Some(Err(leader.clone())));
        };
        let (waited, ()) = tokio::join!(resolver.get_competent_hosts(service), broadcast);
        let waited = waited.unwrap_err();
        assert_eq!(waited.to_string(), leader.to_string());
        assert_eq!(waited, leader);
    }
}
