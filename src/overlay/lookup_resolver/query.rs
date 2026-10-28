//! `LookupResolver::query`, moved here from `lookup_resolver.rs` with the
//! ordered lookup beside it (#394): the parent file is over the ratchet's
//! 800-line bound and may not grow.

use super::{now_ms, LookupResolver};
use crate::overlay::types::{LookupAnswer, LookupQuestion, OutputListItem};
use crate::{Error, Result};
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::HashSet;
use std::time::Instant;

impl LookupResolver {
    /// Execute a lookup query.
    ///
    /// Discovers competent hosts and queries them in parallel,
    /// aggregating results.
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
                "All competent hosts for {} are backing off for approximately {}ms",
                question.service, wait_ms
            )));
        }

        // Query all available hosts in parallel
        let mut all_outputs: Vec<OutputListItem> = Vec::new();
        let mut seen_outputs: HashSet<String> = HashSet::new();
        let mut first_freeform: Option<LookupAnswer> = None;

        let futures: Vec<_> = available
            .iter()
            .map(|host| {
                let host = host.clone();
                let facilitator = self.facilitator.clone();
                let question = question.clone();
                let query_text = query_text.map(ToOwned::to_owned);
                let timeout = timeout_ms;

                async move {
                    let start = Instant::now();
                    let result = facilitator
                        .lookup_ordered(&host, &question, query_text.as_deref(), timeout)
                        .await;
                    let elapsed = start.elapsed().as_millis() as u64;
                    (host, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (host, result, elapsed) in results {
            match result {
                Ok(answer) => {
                    // Validate the response
                    let is_valid = matches!(&answer, LookupAnswer::OutputList { outputs } if !outputs.is_empty())
                        || matches!(&answer, LookupAnswer::Freeform { .. });

                    if is_valid {
                        self.reputation_tracker.record_success(&host, elapsed);
                    } else {
                        self.reputation_tracker
                            .record_failure(&host, Some("Invalid lookup response"));
                    }

                    match answer {
                        LookupAnswer::OutputList { outputs } => {
                            // Deduplicate using TX memoization (txId.outputIndex as unique key)
                            for output in outputs {
                                if let Some(tx_id) = self.get_or_cache_tx_id(&output.beef).await {
                                    let uniq_key = format!("{}.{}", tx_id, output.output_index);
                                    if !seen_outputs.contains(&uniq_key) {
                                        seen_outputs.insert(uniq_key);
                                        all_outputs.push(output);
                                    }
                                }
                                // Skip outputs with invalid BEEF (can't parse)
                            }
                        }
                        LookupAnswer::Freeform { .. } => {
                            if first_freeform.is_none() {
                                first_freeform = Some(answer);
                            }
                        }
                        LookupAnswer::Formula { .. } => {
                            // Formula responses are not aggregated
                        }
                    }
                }
                Err(e) => {
                    self.reputation_tracker
                        .record_failure(&host, Some(&e.to_string()));
                }
            }
        }

        // Return freeform if we got one, otherwise aggregated output list
        if let Some(freeform) = first_freeform {
            Ok(freeform)
        } else {
            Ok(LookupAnswer::OutputList {
                outputs: all_outputs,
            })
        }
    }
}
