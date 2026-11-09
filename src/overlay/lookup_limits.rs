//! The lookup client's operational limits (#775, #785), the reference's
//! `LookupLimits` (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResources.ts:2-27`): "operational
//! client limits, not BEEF validity or service authority rules".
//!
//! A limit reached is [`Error::OverlayResourceLimit`] naming the limit, the
//! reference's `LookupResourceLimitError` (`LookupResources.ts:29-34`), and
//! is NEUTRAL for host reputation: the resolver records neither a success
//! nor a failure for the host (`LookupResolver.ts:2415`, the tracked call
//! rethrowing it before `recordFailure`; `:1764-1767`, the query keeping it
//! as its session's limit).
//!
//! The reference's `maxTrackers`, `hostConcurrency`, `trackerConcurrency`,
//! `maxEvidenceOutputs` and `maxEvidenceBytes` are not here: this crate asks
//! every tracker and host at once (`CLAUDE.md`, the #769 row).

use crate::overlay::types::LookupAnswer;
use crate::{Error, Result};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// `DEFAULT_LOOKUP_LIMITS.maxHosts` (`LookupResources.ts:17`).
pub const DEFAULT_LOOKUP_MAX_HOSTS: usize = 256;
/// `DEFAULT_LOOKUP_LIMITS.maxHostsPerTracker` (`LookupResources.ts:18`).
pub const DEFAULT_LOOKUP_MAX_HOSTS_PER_TRACKER: usize = 64;
/// `DEFAULT_LOOKUP_LIMITS.maxResponseBytes` (`LookupResources.ts:22`): 32 MiB.
pub const DEFAULT_LOOKUP_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// `DEFAULT_LOOKUP_LIMITS.maxTotalBytes` (`LookupResources.ts:23`): 64 MiB.
pub const DEFAULT_LOOKUP_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// `DEFAULT_LOOKUP_LIMITS.maxOutputs` (`LookupResources.ts:24`).
pub const DEFAULT_LOOKUP_MAX_OUTPUTS: usize = 4096;

/// The reference's normalizer's output bound (`ts-stack@edf6e03`
/// `LookupResolver.ts:254`, `MAX_LOOKUP_OUTPUTS =
/// DEFAULT_LOOKUP_LIMITS.maxOutputs`, read at `:395`): a constant, not the
/// configured `maxOutputs`. `normalizeLookupAnswer` refuses a longer output
/// list as no answer, so the facilitator's JSON parse throws `Malformed
/// lookup response` after its configured count (`:859-866`) and the tracked
/// call does so before `assertTrackedLookupAnswer` (`:2385-2392`): a plain
/// `Error`, recorded against the host (`:2408-2419`), never the neutral
/// limit.
pub(crate) const MAX_LOOKUP_OUTPUTS: usize = DEFAULT_LOOKUP_MAX_OUTPUTS;

/// The normalizer's count refusal ([`MAX_LOOKUP_OUTPUTS`]), in the
/// reference's words with the member named after the colon as #768's
/// refusals name theirs: an [`Error::OverlayError`], a host failure.
pub(crate) fn normalized_output_count(count: usize) -> Result<()> {
    if count > MAX_LOOKUP_OUTPUTS {
        return Err(Error::OverlayError(format!(
            "Malformed lookup response: an output list of {count} outputs, past {MAX_LOOKUP_OUTPUTS}"
        )));
    }
    Ok(())
}

/// The limits a [`LookupResolver`](crate::overlay::LookupResolver) keeps, the
/// reference's defaults unless a host sets them
/// ([`LookupResolverConfig::limits`](crate::overlay::LookupResolverConfig)).
///
/// The struct is `#[non_exhaustive]`: build it from `default()` and set the
/// fields that differ.
///
/// ```
/// use bsv_rs::overlay::LookupLimits;
/// let mut limits = LookupLimits::default();
/// limits.max_outputs = 512;
/// assert_eq!(limits.max_response_bytes, 32 * 1024 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LookupLimits {
    /// The hosts one discovery keeps and one query asks (`maxHosts`, 256).
    pub max_hosts: usize,
    /// The hosts kept from one tracker's answer (`maxHostsPerTracker`, 64);
    /// a tracker's share is the lesser of this and `max_hosts` divided by
    /// the trackers asked (`LookupDiscovery.ts:105-108`).
    pub max_hosts_per_tracker: usize,
    /// One response's bytes (`maxResponseBytes`, 32 MiB): the body as read,
    /// and the BEEF and context bytes of the outputs it yields.
    pub max_response_bytes: usize,
    /// The bytes of one query's hosts together, and of one discovery's
    /// trackers together (`maxTotalBytes`, 64 MiB).
    pub max_total_bytes: usize,
    /// The outputs of one answer (`maxOutputs`, 4096).
    pub max_outputs: usize,
}

impl Default for LookupLimits {
    fn default() -> Self {
        Self {
            max_hosts: DEFAULT_LOOKUP_MAX_HOSTS,
            max_hosts_per_tracker: DEFAULT_LOOKUP_MAX_HOSTS_PER_TRACKER,
            max_response_bytes: DEFAULT_LOOKUP_MAX_RESPONSE_BYTES,
            max_total_bytes: DEFAULT_LOOKUP_MAX_TOTAL_BYTES,
            max_outputs: DEFAULT_LOOKUP_MAX_OUTPUTS,
        }
    }
}

impl LookupLimits {
    /// One tracker's share of a discovery over `trackers` trackers
    /// (`LookupDiscovery.ts:105-108`): each tracker keeps a reserved share,
    /// so an early advertisement flood cannot consume the whole budget.
    pub(crate) fn tracker_share(&self, trackers: usize) -> usize {
        self.max_hosts_per_tracker
            .min((self.max_hosts / trackers.max(1)).max(1))
    }

    /// The options of one request under these limits, charging `budget`.
    pub(crate) fn request(&self, budget: &Arc<LookupByteBudget>) -> LookupRequestOptions {
        LookupRequestOptions {
            max_response_bytes: self.max_response_bytes,
            max_outputs: self.max_outputs,
            budget: Some(LookupByteBudget::metered(budget)),
        }
    }
}

/// The limit reached, in the reference's class (`LookupResourceLimitError`,
/// `LookupResources.ts:29-34`), named as the reference names it
/// (`maxResponseBytes`, `maxOutputs`, `maxTotalBytes`).
pub(crate) fn resource_limit(limit: &str) -> Error {
    Error::OverlayResourceLimit(limit.to_string())
}

/// A byte budget shared by the requests of one query or one discovery, the
/// reference's `consumeBytes` (`LookupResolver.ts:1624-1631`,
/// `LookupDiscovery.ts:21-29`). A facilitator that reads a response charges
/// the bytes as it reads them; the charge that would pass the budget is
/// refused as [`Error::OverlayResourceLimit`] naming `maxTotalBytes`.
#[derive(Debug)]
pub struct LookupByteBudget {
    max: usize,
    received: AtomicUsize,
    parent: Option<Arc<LookupByteBudget>>,
}

impl LookupByteBudget {
    /// A budget of `max` bytes.
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            received: AtomicUsize::new(0),
            parent: None,
        })
    }

    /// One request's meter over a shared budget: its charges reach the
    /// shared budget, and its own count says whether the facilitator
    /// reported any (`LookupResolver.ts:2332-2338`).
    fn metered(parent: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self {
            max: usize::MAX,
            received: AtomicUsize::new(0),
            parent: Some(parent.clone()),
        })
    }

    /// Charge `bytes`: `Err` naming `maxTotalBytes` when they pass what is
    /// left, nothing charged.
    pub fn consume(&self, bytes: usize) -> Result<()> {
        if let Some(parent) = &self.parent {
            parent.consume(bytes)?;
        }
        // A compare-exchange loop, not `fetch_update`: stable rustc 1.99
        // deprecates that name for `try_update`, which the MSRV (1.88) lacks.
        let mut received = self.received.load(Ordering::SeqCst);
        loop {
            if bytes > self.max.saturating_sub(received) {
                return Err(resource_limit("maxTotalBytes"));
            }
            match self.received.compare_exchange_weak(
                received,
                received + bytes,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => received = current,
            }
        }
    }

    /// The bytes charged so far.
    pub fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

/// The bounds of one lookup request, the reference's `LookupRequestOptions`
/// (`LookupResolver.ts:711-715`), handed to
/// [`OverlayLookupFacilitator::lookup_bounded`](crate::overlay::OverlayLookupFacilitator::lookup_bounded).
/// `default()` is the reference's defaults with no shared budget.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LookupRequestOptions {
    /// The response's byte bound (`maxResponseBytes`).
    pub max_response_bytes: usize,
    /// The answer's output bound (`maxOutputs`).
    pub max_outputs: usize,
    /// The budget the bytes read are charged to (`consumeBytes`), if any.
    pub budget: Option<Arc<LookupByteBudget>>,
}

impl Default for LookupRequestOptions {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_LOOKUP_MAX_RESPONSE_BYTES,
            max_outputs: DEFAULT_LOOKUP_MAX_OUTPUTS,
            budget: None,
        }
    }
}

impl LookupRequestOptions {
    /// Charge `bytes` to the budget, when there is one.
    pub fn consume(&self, bytes: usize) -> Result<()> {
        match &self.budget {
            Some(budget) => budget.consume(bytes),
            None => Ok(()),
        }
    }

    /// The resolver's check of an answer a facilitator returned, the
    /// reference's two steps (`trackLookupAnswer`, `LookupResolver.ts:2380-2392`):
    /// the normalizer's constant count first (`normalizeLookupAnswer`,
    /// `:2388-2391`, [`MAX_LOOKUP_OUTPUTS`]), an output list past 4096
    /// `Malformed lookup response`, a host failure, whatever `max_outputs`
    /// is; then `assertTrackedLookupAnswer` and `assertTrackedOutputBudget`
    /// (`:2351-2375`): an output list above `max_outputs` is `maxOutputs`,
    /// one whose BEEF and context bytes pass `max_response_bytes` is
    /// `maxResponseBytes`, both neutral, and the bytes of an answer whose
    /// facilitator charged none are charged here. A custom facilitator that
    /// ignores the options is bounded by this check alone, after its answer
    /// is in memory, as the reference's is.
    pub(crate) fn assert_tracked_answer(&self, answer: &LookupAnswer) -> Result<()> {
        let LookupAnswer::OutputList { outputs } = answer else {
            return Ok(());
        };
        normalized_output_count(outputs.len())?;
        if outputs.len() > self.max_outputs {
            return Err(resource_limit("maxOutputs"));
        }
        let bytes = retained_bytes(answer);
        if bytes > self.max_response_bytes {
            return Err(resource_limit("maxResponseBytes"));
        }
        match &self.budget {
            Some(budget) if budget.received() == 0 => budget.consume(bytes),
            _ => Ok(()),
        }
    }
}

/// An output list's BEEF and context bytes (`lookupAnswerRetainedBytes`,
/// `LookupResolver.ts:450-455`); 0 for any other answer.
pub(crate) fn retained_bytes(answer: &LookupAnswer) -> usize {
    let LookupAnswer::OutputList { outputs } = answer else {
        return 0;
    };
    outputs.iter().fold(0usize, |bytes, output| {
        bytes
            .saturating_add(output.beef.len())
            .saturating_add(output.context.as_ref().map_or(0, Vec::len))
    })
}

/// Hosts in the order given, each kept at its earliest occurrence, at most
/// `max` of them: the reference's `Array.from(new Set(..)).slice(0, max)`
/// (`LookupResolver.ts:2006-2009`), its per-tracker collection
/// (`LookupDiscovery.ts:62-78`) and its query's admission past `seen` and
/// `maxHosts` (`:1842-1849`).
pub(crate) fn earliest_distinct(
    hosts: impl IntoIterator<Item = String>,
    max: usize,
) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut kept = Vec::new();
    for host in hosts {
        if kept.len() >= max {
            break;
        }
        if seen.insert(host.clone()) {
            kept.push(host);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_reference_defaults_775() {
        let limits = LookupLimits::default();
        assert_eq!(limits.max_hosts, 256);
        assert_eq!(limits.max_hosts_per_tracker, 64);
        assert_eq!(limits.max_response_bytes, 33_554_432);
        assert_eq!(limits.max_total_bytes, 67_108_864);
        assert_eq!(limits.max_outputs, 4096);
    }

    #[test]
    fn a_tracker_share_is_the_reference_formula_785() {
        let mut limits = LookupLimits::default();
        assert_eq!(limits.tracker_share(4), 64);
        assert_eq!(limits.tracker_share(16), 16);
        assert_eq!(limits.tracker_share(0), 64);
        limits.max_hosts = 3;
        assert_eq!(limits.tracker_share(2), 1);
        assert_eq!(limits.tracker_share(8), 1);
    }

    #[test]
    fn a_budget_refuses_the_charge_that_passes_it_and_charges_nothing_775() {
        let budget = LookupByteBudget::new(10);
        budget.consume(6).unwrap();
        let meter = LookupByteBudget::metered(&budget);
        assert_eq!(
            meter.consume(5),
            Err(Error::OverlayResourceLimit("maxTotalBytes".into()))
        );
        assert_eq!((budget.received(), meter.received()), (6, 0));
        meter.consume(4).unwrap();
        assert_eq!((budget.received(), meter.received()), (10, 4));
    }

    #[test]
    fn earliest_distinct_keeps_order_and_cuts_785() {
        let hosts = ["b", "a", "b", "c", "a", "d"].map(String::from);
        assert_eq!(earliest_distinct(hosts.clone(), 256), ["b", "a", "c", "d"]);
        assert_eq!(earliest_distinct(hosts, 2), ["b", "a"]);
    }
}
