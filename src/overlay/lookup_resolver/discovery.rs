//! `LookupResolver::find_competent_hosts`, the SLAP discovery (moved here
//! from `lookup_resolver.rs`, which sits near the ratchet's 800-line bound),
//! in the trackers' answer order within the reference's bounds (#785) and
//! under the lookup limits (#775): `ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupDiscovery.ts:62-78,82-95,103-108`
//! and `LookupResolver.ts:2006-2009`.

use super::LookupResolver;
use crate::overlay::lookup_limits::{earliest_distinct, LookupByteBudget};
use crate::overlay::types::{LookupAnswer, LookupQuestion, MAX_TRACKER_WAIT_TIME_MS};
use crate::{Error, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::time::Instant;

impl LookupResolver {
    /// Find hosts that can answer queries for a given lookup service via SLAP.
    ///
    /// Queries all available SLAP trackers in parallel to discover hosts that
    /// advertise the specified service. Each tracker response is parsed as a
    /// SLAP admin token to extract the host domain. Each tracker is accounted
    /// as a host is (#760, #762): an output list a success, a freeform answer
    /// nothing, an error or a formula answer a failure. A tracker backing off
    /// is not asked; with every tracker backing off the discovery refuses in
    /// the reference's words, `All SLAP trackers hosts are backing off for
    /// approximately <N>ms due to repeated failures.`, N the soonest end of a
    /// backoff (`LookupResolver.ts:2306-2314`, #769).
    ///
    /// The hosts are the reference's list (#785): the trackers taken in the
    /// order their answers arrive, each answer's hosts in its own order,
    /// deduplicated and cut to the tracker's share (the lesser of
    /// `limits.max_hosts_per_tracker` and `limits.max_hosts` divided by the
    /// trackers asked, `LookupDiscovery.ts:62-78,105-108`), the whole
    /// deduplicated by earliest occurrence and cut to `limits.max_hosts`
    /// (`LookupResolver.ts:2006-2009`).
    ///
    /// A tracker's answer is read under the lookup limits (#775): one past
    /// `limits.max_response_bytes` or `limits.max_outputs`, or past what the
    /// discovery's `limits.max_total_bytes` has left, names no host and
    /// records nothing for the tracker, neither a success nor a failure
    /// (`LookupResolver.ts:2415`, `LookupDiscovery.ts:80-83`).
    ///
    /// This is the low-level discovery method. It does **not** use the hosts
    /// cache or request coalescing (those are handled by `get_competent_hosts`,
    /// which is called internally by `query`).
    ///
    /// # Arguments
    ///
    /// * `service` - The lookup service name (e.g. `"ls_myservice"`)
    ///
    /// # Returns
    ///
    /// A list of host URLs that advertise the given service, empty when the
    /// trackers asked named none (or no tracker is configured).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let resolver = LookupResolver::default();
    /// let hosts = resolver.find_competent_hosts("ls_myservice").await?;
    /// for host in &hosts {
    ///     println!("Found host: {}", host);
    /// }
    /// ```
    pub async fn find_competent_hosts(&self, service: &str) -> Result<Vec<String>> {
        let question = LookupQuestion::new("ls_slap", serde_json::json!({ "service": service }));

        // The trackers not backing off; every one backing off refuses (#769)
        let available = self.available_slap_trackers()?;
        if available.is_empty() {
            return Ok(Vec::new());
        }

        let share = self.limits.tracker_share(available.len());
        let budget = LookupByteBudget::new(self.limits.max_total_bytes);

        // Query all available trackers in parallel, taken as they answer
        let mut answers: FuturesUnordered<_> = available
            .iter()
            .map(|tracker| {
                let tracker = tracker.clone();
                let facilitator = self.facilitator.clone();
                let question = question.clone();
                let options = self.limits.request(&budget);

                async move {
                    let start = Instant::now();
                    let result = facilitator
                        .lookup_bounded(
                            &tracker,
                            &question,
                            None,
                            Some(MAX_TRACKER_WAIT_TIME_MS),
                            &options,
                        )
                        .await
                        .and_then(|answer| {
                            options.assert_tracked_answer(&answer)?;
                            Ok(answer)
                        });
                    let elapsed = start.elapsed().as_millis() as u64;
                    (tracker, result, elapsed)
                }
            })
            .collect();

        // Each tracker's hosts in its own order, the trackers in arrival order
        let mut sources: Vec<Vec<String>> = Vec::new();

        while let Some((tracker, result, elapsed)) = answers.next().await {
            match result {
                Ok(LookupAnswer::OutputList { outputs }) => {
                    self.reputation_tracker.record_success(&tracker, elapsed);

                    // A refused output is skipped, the tracker still a
                    // success, as the reference's `continue` (`:2197-2213`,
                    // #786), before the tracker's share is counted.
                    let named = outputs
                        .iter()
                        .filter_map(|output| self.parse_slap_token(output, service).ok());
                    sources.push(earliest_distinct(named, share));
                }
                // A tracker's question is the reference's tracked call too
                // (`ts-stack@edf6e03` `LookupResolver.ts:1974`, #762): a
                // freeform answer neutral, a formula one a failure (`:2399-2405`).
                Ok(LookupAnswer::Freeform { .. }) => {}
                Ok(LookupAnswer::Formula { .. }) => self
                    .reputation_tracker
                    .record_failure(&tracker, Some("Invalid lookup response")),
                // A resource limit is neutral: nothing recorded (`:2415`, #775)
                Err(Error::OverlayResourceLimit(_)) => {}
                Err(e) => {
                    self.reputation_tracker
                        .record_failure(&tracker, Some(&e.to_string()));
                }
            }
        }

        Ok(earliest_distinct(
            sources.into_iter().flatten(),
            self.limits.max_hosts,
        ))
    }
}
