//! `LookupResolver::query`, moved here from `lookup_resolver.rs` with the
//! ordered lookup beside it (#394): the parent file is over the ratchet's
//! 800-line bound and may not grow.

use super::{now_ms, LookupResolver};
use crate::overlay::lookup_limits::{earliest_distinct, retained_bytes, LookupByteBudget};
use crate::overlay::types::{LookupAnswer, LookupQuestion, OutputListItem};
use crate::{Error, Result};
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// The reference's hint test at the merge (`ts-stack@edf6e03`
/// `LookupResolver.ts:2229`, `:2235`): a hint present that, ASCII
/// lower-cased, is not the BEEF subject's txid. The reference drops such an
/// output; this crate keeps and counts it (#796, the owner's word on #735).
fn hint_disagrees(hint: Option<&str>, tx_id: &str) -> bool {
    hint.is_some_and(|hint| hint.to_ascii_lowercase() != tx_id)
}

impl LookupResolver {
    /// How many lookup outputs this resolver merged whose host's `txid` hint
    /// disagreed with the BEEF's subject (#796): every one received, kept in
    /// the answer or not, counted as the host's fault for the caller to log
    /// or act on. The reference drops such an output at its merge
    /// (`ts-stack@edf6e03` `LookupResolver.ts:1104-1105`, `:2223-2240`;
    /// ts-stack #1482); here it is kept, by the owner's word on #735, unless
    /// a copy of the same output whose hint agrees (or is absent) arrives,
    /// which displaces it and stands where it arrived, so the answer less
    /// its kept lying outputs is the reference's copies, and its order while
    /// the hosts answer in rank order (this crate merges the answers in rank
    /// order once every host has answered, the reference each answer as it
    /// completes, `:1501-1502` into `:1065-1072`). The host's reputation is
    /// not touched, as the reference's merge touches none. This count is separate from
    /// `IdentityClient::txid_hint_contradictions`: an identity lookup that
    /// keeps a lying output counts it here at the merge and again there at
    /// the evidence check, and a lying copy the merge displaced, or dropped
    /// behind a copy it already held, is counted here alone, that count
    /// reading 0 for it (#818). To read both, the identity client is built
    /// by `IdentityClient::with_resolver` over an `Arc<LookupResolver>` the
    /// caller keeps: one built by `IdentityClient::new` owns its resolver
    /// and has no door to this count.
    pub fn txid_hint_contradictions(&self) -> u64 {
        self.hint_contradictions.load(Ordering::Relaxed)
    }

    /// Execute a lookup query.
    ///
    /// Discovers competent hosts and queries them in parallel,
    /// aggregating results. Each host's answer feeds the global host
    /// reputation as the reference's does (#760): an output list, empty or
    /// not, a success; a freeform answer nothing, a backoff kept; an error or
    /// any other answer a failure.
    ///
    /// The answer is always the merged output list, empty when no host
    /// answered one, as the reference's `query` answers (`ts-stack@edf6e03`
    /// `LookupResolver.ts:1369-1375`, `:1445-1450`): a host's freeform
    /// answer is not returned and does not blank the other hosts' lists
    /// (#815; until then the earliest freeform answer was returned over the
    /// aggregate).
    ///
    /// The hosts asked are the admitted ones (#785): the discovered (or
    /// overriding) hosts and then the additional ones, each at its earliest
    /// occurrence, at most `limits.max_hosts` (`ts-stack@edf6e03`
    /// `LookupResolver.ts:1842-1849`; the reference admits the additional
    /// hosts ahead of a refreshing discovery's, `:2063-2072`, a stated row). Each answer is read under the lookup
    /// limits (#775): one past `limits.max_response_bytes` or
    /// `limits.max_outputs`, or past what the query's
    /// `limits.max_total_bytes` has left, contributes nothing and records
    /// nothing for its host, neither a success nor a failure (`:2415`,
    /// `:1764-1767`); the query answers what the other hosts gave, as the
    /// reference's does.
    ///
    /// # Arguments
    ///
    /// * `question` - The lookup question to execute
    /// * `timeout_ms` - Optional timeout in milliseconds
    ///
    /// # Returns
    ///
    /// The aggregated lookup answer.
    pub async fn query(
        &self,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        self.query_with_text(question, None, timeout_ms).await
    }

    /// Execute a lookup query whose body keeps the query's key order: an
    /// `IndexMap` inside `query` is sent in insertion order, as the
    /// reference's `JSON.stringify` writes a `Record`, where the question's
    /// `serde_json::Value` sorts its keys (#394).
    #[cfg_attr(not(feature = "identity"), allow(dead_code))] // the identity client's
    pub(crate) async fn query_ordered<T: Serialize + ?Sized>(
        &self,
        service: &str,
        query: &T,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        let invalid = |e: serde_json::Error| Error::OverlayError(e.to_string());
        let text = serde_json::value::to_raw_value(query).map_err(invalid)?;
        let value = serde_json::from_str(text.get()).map_err(invalid)?;
        let question = LookupQuestion::new(service, value);
        self.query_with_text(&question, Some(&text), timeout_ms)
            .await
    }

    async fn query_with_text(
        &self,
        question: &LookupQuestion,
        query_text: Option<&RawValue>,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        // Find hosts that can answer this query
        let hosts = self.get_competent_hosts(&question.service).await?;
        // The query's admission past `seen` and `maxHosts` (`:1842-1849`, #785)
        let hosts = earliest_distinct(hosts, self.limits.max_hosts);

        if hosts.is_empty() {
            return Err(Error::OverlayError(format!(
                "No competent {} hosts found by the SLAP trackers for lookup service: {}",
                self.network_preset_str(),
                question.service
            )));
        }

        // Rank hosts by reputation, filtering out those in backoff
        let now = now_ms();
        let ranked = self.reputation_tracker.rank_hosts(&hosts);
        let available: Vec<_> = ranked
            .iter()
            .filter(|h| h.entry.backoff_until <= now)
            .map(|h| h.entry.host.clone())
            .collect();

        if available.is_empty() {
            let soonest = ranked
                .iter()
                .map(|h| h.entry.backoff_until)
                .min()
                .unwrap_or(0);
            let wait_ms = soonest.saturating_sub(now);
            return Err(Error::OverlayError(format!(
                "All lookup service {} hosts are backing off for approximately {}ms due to repeated failures.",
                question.service, wait_ms
            )));
        }

        // Query all available hosts in parallel
        // A slot emptied when an agreeing copy displaces a lying one (#796).
        let mut all_outputs: Vec<Option<OutputListItem>> = Vec::new();
        // The key to the held copy's slot in `all_outputs` and whether its
        // hint disagrees with its subject (#796).
        let mut seen_outputs: HashMap<String, (usize, bool)> = HashMap::new();

        // The query's byte budget, shared by its hosts (`:1624-1631`, #775)
        let budget = LookupByteBudget::new(self.limits.max_total_bytes);
        let mut retained = 0usize;

        let futures: Vec<_> = available
            .iter()
            .map(|host| {
                let host = host.clone();
                let facilitator = self.facilitator.clone();
                let question = question.clone();
                let query_text = query_text.map(ToOwned::to_owned);
                let timeout = timeout_ms;
                let options = self.limits.request(&budget);

                async move {
                    let start = Instant::now();
                    // The tracked call's check of the answer, before any
                    // accounting (`:2351-2375`, `:2392`)
                    let result = facilitator
                        .lookup_bounded(&host, &question, query_text.as_deref(), timeout, &options)
                        .await
                        .and_then(|answer| {
                            options.assert_tracked_answer(&answer)?;
                            Ok(answer)
                        });
                    let elapsed = start.elapsed().as_millis() as u64;
                    (host, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (host, result, elapsed) in results {
            match result {
                Ok(answer) => {
                    // The reference's accounting (#760): any output list a
                    // success, the empty one included (`ts-stack@edf6e03`
                    // `LookupResolver.ts:2395-2398`, `ts-sdk@9e3ede6`
                    // `:518-528`); a freeform answer neutral, nothing
                    // recorded (`edf6e03` `:2399-2402`); any other a failure.
                    match &answer {
                        LookupAnswer::OutputList { .. } => {
                            self.reputation_tracker.record_success(&host, elapsed)
                        }
                        LookupAnswer::Freeform { .. } => {}
                        LookupAnswer::Formula { .. } => self
                            .reputation_tracker
                            .record_failure(&host, Some("Invalid lookup response")),
                    }

                    // An answer past what the query may retain is dropped
                    // after its host's success (`retainLookupHostAnswer`,
                    // `:1734-1743`, a `maxTotalBytes` limit, #775).
                    let bytes = retained_bytes(&answer);
                    if bytes > self.limits.max_total_bytes - retained {
                        continue;
                    }
                    retained += bytes;

                    match answer {
                        LookupAnswer::OutputList { outputs } => {
                            // Deduplicate using TX memoization (txId.outputIndex as unique key)
                            for output in outputs {
                                // Skip outputs with invalid BEEF (can't parse)
                                let Some(tx_id) = self.get_or_cache_tx_id(&output.beef).await
                                else {
                                    continue;
                                };
                                let disagrees = hint_disagrees(output.txid.as_deref(), &tx_id);
                                if disagrees {
                                    self.hint_contradictions.fetch_add(1, Ordering::Relaxed);
                                }
                                let uniq_key = format!("{}.{}", tx_id, output.output_index);
                                match seen_outputs.get_mut(&uniq_key) {
                                    None => {
                                        seen_outputs
                                            .insert(uniq_key, (all_outputs.len(), disagrees));
                                        all_outputs.push(Some(output));
                                    }
                                    // A held copy whose hint lies is displaced by the
                                    // first agreeing (or hintless) one (#796), which
                                    // takes its own arrival's place: the reference drops
                                    // the lying copy (`LookupResolver.ts:2229,2235`) and
                                    // keys the agreeing one when it arrives (`:1106-1112`),
                                    // so this answer less its kept lone liars is the
                                    // reference's copies, and its order while the hosts
                                    // answer in rank order (the reference merges in
                                    // completion order, `:1501-1502`).
                                    Some((slot, held_disagrees))
                                        if *held_disagrees && !disagrees =>
                                    {
                                        all_outputs[*slot] = None;
                                        *slot = all_outputs.len();
                                        *held_disagrees = false;
                                        all_outputs.push(Some(output));
                                    }
                                    // Otherwise the earlier copy stays (`:1107`).
                                    Some(_) => {}
                                }
                            }
                        }
                        // A freeform answer is counted by the reference's
                        // session and never answered (`recordFreeformAnswer`,
                        // `:1085-1087`, from `:1512`; the session's
                        // `snapshot`, `:1123-1135`, and `queryDetailed`'s
                        // answer, `:1445-1450`, an output list), so it
                        // contributes nothing here (#815); a formula answer
                        // is a failure already recorded above.
                        LookupAnswer::Freeform { .. } | LookupAnswer::Formula { .. } => {}
                    }
                }
                // A resource limit is neutral: nothing recorded for the
                // host (`:2415`, `:1764-1767`, #775)
                Err(Error::OverlayResourceLimit(_)) => {}
                Err(e) => {
                    self.reputation_tracker
                        .record_failure(&host, Some(&e.to_string()));
                }
            }
        }

        // The merged output list, empty when no host answered one: no path
        // of the reference's `query` answers freeform (`:1369-1375`,
        // `:1445-1450`; #815).
        Ok(LookupAnswer::OutputList {
            outputs: all_outputs.into_iter().flatten().collect(),
        })
    }
}
