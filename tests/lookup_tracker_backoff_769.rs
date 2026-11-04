//! #769: with every SLAP tracker backing off, the lookup is refused in the
//! reference's words, and a cached host list with no host available is not
//! reused (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts`). The discovery asks
//! only the trackers not backing off, and throws when none is left
//! (`prepareHostsForQuery`, `:2306-2314`, caught at `:1963`, the query's
//! refusal at `:1671`):
//!
//! ```text
//! const soonest = Math.min(...ranked.map(h => h.backoffUntil))
//! const waitMs = Math.max(soonest - now, 0)
//! throw new Error(
//!   `All ${context} hosts are backing off for approximately ${waitMs}ms due to repeated failures.`
//! ```
//!
//! and the cache is reused only while some host in it is available
//! (`lookupCacheHasAvailableHost`, `:1898-1903`, `refresh` at `:1913-1918`).
//! Until #769 the discovery answered no hosts, `query` refused in `No
//! competent mainnet hosts found by the SLAP trackers for lookup service:
//! <service>` and `get_competent_hosts` cached the empty list for the
//! hosts cache's TTL (5 minutes), though a tracker's backoff ends after 1 s.
//! On #762's scripted facilitator (three formula answers back a tracker
//! off); each test names its own tracker and host, as the reputation tracker
//! is one global keyed by URL.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, get_overlay_host_reputation_tracker, LookupAnswer,
    LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator, Protocol,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// An `ls_` name of lowercase words alone, as an advertisement must carry.
const SERVICE: &str = "ls_tracker_backoff_issue";

type Asked = Arc<Mutex<Vec<(String, String)>>>;

/// #762's scripted facilitator, recording the URL and service of each
/// question; past its script it answers an empty output list.
struct Recording {
    asked: Asked,
    script: Mutex<VecDeque<bsv_rs::Result<LookupAnswer>>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.asked
            .lock()
            .unwrap()
            .push((url.to_string(), question.service.clone()));
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(LookupAnswer::OutputList { outputs: vec![] }))
    }
}

/// A resolver whose one SLAP tracker is `tracker`, no host overrides.
fn tracker_resolver(
    tracker: &str,
    script: Vec<bsv_rs::Result<LookupAnswer>>,
) -> (LookupResolver, Asked) {
    with_additional_host(tracker, None, script)
}

/// `tracker_resolver`, with `additional` configured for the service when
/// named.
fn with_additional_host(
    tracker: &str,
    additional: Option<&str>,
    script: Vec<bsv_rs::Result<LookupAnswer>>,
) -> (LookupResolver, Asked) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording {
            asked: asked.clone(),
            script: Mutex::new(script.into()),
        })),
        slap_trackers: Some(vec![tracker.to_string()]),
        additional_hosts: additional
            .map(|host| HashMap::from([(SERVICE.to_string(), vec![host.to_string()])])),
        ..Default::default()
    });
    (resolver, asked)
}

fn formula() -> bsv_rs::Result<LookupAnswer> {
    Ok(LookupAnswer::Formula { formulas: vec![] })
}

/// A tracker's answer naming `host` for the service, a SLAP advertisement
/// signed by this crate's writer.
fn advertising(host: &str) -> bsv_rs::Result<LookupAnswer> {
    let lock =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Slap, host, SERVICE);
    Ok(LookupAnswer::OutputList {
        outputs: vec![lock_position::output_of(lock)],
    })
}

fn question() -> LookupQuestion {
    LookupQuestion::new(SERVICE, json!({}))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Three formula answers through the discovery back `tracker` off; the
/// discovery is uncached, so each asks it.
async fn back_off(resolver: &LookupResolver, tracker: &str) -> u64 {
    for n in 1..=3 {
        let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
        assert!(hosts.is_empty(), "discovery {n}: {hosts:?}");
    }
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(tracker)
        .unwrap();
    assert_eq!(entry.consecutive_failures, 3);
    assert!(entry.backoff_until > now_ms(), "{entry:?}");
    entry.backoff_until
}

/// The wait the refusal names, read from the reference's words.
fn backing_off_wait(refusal: &Error) -> u64 {
    let Error::OverlayError(text) = refusal else {
        panic!("not an overlay refusal: {refusal:?}");
    };
    text.strip_prefix("All SLAP trackers hosts are backing off for approximately ")
        .and_then(|rest| rest.strip_suffix("ms due to repeated failures."))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("not the reference's words: {text}"))
}

#[tokio::test]
async fn a_lookup_with_every_slap_tracker_backing_off_is_refused_in_the_reference_words_769() {
    let tracker = "https://refused-tracker-769.invalid";
    let (resolver, asked) = tracker_resolver(tracker, vec![formula(), formula(), formula()]);
    let backoff_until = back_off(&resolver, tracker).await;
    let before = now_ms();
    let refusal = resolver.query(&question(), None).await.unwrap_err();
    let wait = backing_off_wait(&refusal);
    // The soonest end of a tracker's backoff, from the refusal's clock: the
    // tracker's one backoff, at most its 1 s base, and no less than what is
    // left of it after the refusal (the fold's lower bound: a constant `0ms`
    // fails).
    let after = now_ms();
    let snapshot = get_overlay_host_reputation_tracker()
        .snapshot(tracker)
        .unwrap();
    assert!(wait <= backoff_until - before, "{wait} {refusal:?}");
    assert!(wait <= 1000, "{refusal:?}");
    assert!(
        wait >= snapshot.backoff_until.saturating_sub(after),
        "{wait} {snapshot:?} {refusal:?}"
    );
    assert_eq!(
        asked.lock().unwrap().len(),
        3,
        "the backed-off tracker was asked"
    );
    // The discovery itself refuses, as the reference's does.
    let refusal = resolver.find_competent_hosts(SERVICE).await.unwrap_err();
    backing_off_wait(&refusal);
}

#[tokio::test]
async fn a_lookup_after_the_tracker_backoff_asks_the_tracker_again_and_is_answered_769() {
    let tracker = "https://returning-tracker-769.invalid";
    let host = "https://returning-host-769.example";
    let script = vec![formula(), formula(), formula(), advertising(host)];
    let (resolver, asked) = tracker_resolver(tracker, script);
    let backoff_until = back_off(&resolver, tracker).await;
    // Inside the backoff the lookup is refused (the words are the test
    // above's), and the empty discovery is not cached.
    resolver.query(&question(), None).await.unwrap_err();
    // Past the backoff the next lookup asks the tracker again.
    tokio::time::sleep(Duration::from_millis(
        backoff_until.saturating_sub(now_ms()) + 20,
    ))
    .await;
    let answer = resolver.query(&question(), None).await.unwrap();
    assert!(
        matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
        "{answer:?}"
    );
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 5, "{asked:?}");
    assert_eq!(asked[3], (tracker.to_string(), "ls_slap".to_string()));
    assert_eq!(asked[4], (host.to_string(), SERVICE.to_string()));
}

#[tokio::test]
async fn a_discovery_that_named_a_host_is_cached_769() {
    let tracker = "https://caching-tracker-769.invalid";
    let host = "https://caching-host-769.example";
    let (resolver, asked) = tracker_resolver(tracker, vec![advertising(host)]);
    for n in 1..=2 {
        let answer = resolver.query(&question(), None).await.unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { .. }),
            "lookup {n}: {answer:?}"
        );
    }
    let asked = asked.lock().unwrap().clone();
    let to_tracker = asked.iter().filter(|(url, _)| url == tracker).count();
    assert_eq!(to_tracker, 1, "the tracker was asked again: {asked:?}");
    assert_eq!(asked.len(), 3, "{asked:?}");
}

#[tokio::test]
async fn a_cached_host_list_whose_every_host_is_backing_off_asks_the_trackers_again_769() {
    let tracker = "https://stale-tracker-769.invalid";
    let host = "https://stale-host-769.example";
    let script = vec![
        advertising(host),
        formula(),
        formula(),
        formula(),
        advertising(host),
    ];
    let (resolver, asked) = tracker_resolver(tracker, script);
    // Three lookups, the cached host failing each: the third backs it off.
    for n in 1..=3 {
        let answer = resolver.query(&question(), None).await.unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
            "lookup {n}: {answer:?}"
        );
    }
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(host)
        .unwrap();
    assert!(entry.backoff_until > now_ms(), "{entry:?}");
    // The cache has no available host: the fourth lookup asks the tracker
    // again (`:1913-1918`), which names the same host, still backing off.
    let refusal = resolver.query(&question(), None).await.unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("are backing off for approximately"),
        "{refusal:?}"
    );
    let asked = asked.lock().unwrap().clone();
    let to_tracker = asked.iter().filter(|(url, _)| url == tracker).count();
    assert_eq!(to_tracker, 2, "the cache was reused: {asked:?}");
}

#[tokio::test]
async fn an_additional_host_is_asked_with_every_slap_tracker_backing_off_769() {
    // The cold read's probe (#769's fold): the reference admits the service's
    // additional hosts beside the discovery (`:2063-2071`) and refuses with
    // the trackers' words only when no host was admitted (`:1669-1671`).
    let tracker = "https://additional-tracker-769.invalid";
    let extra = "https://additional-host-769.example";
    let script = vec![formula(), formula(), formula()];
    let (resolver, asked) = with_additional_host(tracker, Some(extra), script);
    back_off(&resolver, tracker).await;
    let answer = resolver.query(&question(), None).await;
    let asked = asked.lock().unwrap().clone();
    assert!(
        matches!(&answer, Ok(LookupAnswer::OutputList { outputs }) if outputs.is_empty()),
        "{answer:?} asked {asked:?}"
    );
    assert_eq!(asked.len(), 4, "{asked:?}");
    assert_eq!(asked[3], (extra.to_string(), SERVICE.to_string()));
    // The discovery itself still refuses: the additional hosts are the
    // lookup's, not the trackers'.
    let refusal = resolver.find_competent_hosts(SERVICE).await.unwrap_err();
    backing_off_wait(&refusal);
}

#[tokio::test]
async fn every_host_discovered_backing_off_is_refused_in_the_reference_words_769() {
    // `query`'s own refusal (`:1860`, the context `lookup service <s>` at
    // `:2313`): the one discovered host backed off by three failures.
    let tracker = "https://discovered-tracker-769.invalid";
    let host = "https://discovered-host-769.example";
    // The fourth lookup finds no available host in the cache and asks the
    // tracker again, which names the same host.
    let script = vec![
        advertising(host),
        formula(),
        formula(),
        formula(),
        advertising(host),
    ];
    let (resolver, _asked) = tracker_resolver(tracker, script);
    for _ in 1..=3 {
        resolver.query(&question(), None).await.unwrap();
    }
    let backoff_until = get_overlay_host_reputation_tracker()
        .snapshot(host)
        .unwrap()
        .backoff_until;
    let before = now_ms();
    let refusal = resolver.query(&question(), None).await.unwrap_err();
    let Error::OverlayError(text) = &refusal else {
        panic!("not an overlay refusal: {refusal:?}");
    };
    let wait: u64 = text
        .strip_prefix(&format!(
            "All lookup service {SERVICE} hosts are backing off for approximately "
        ))
        .and_then(|rest| rest.strip_suffix("ms due to repeated failures."))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("not the reference's words: {text}"));
    assert!(wait <= backoff_until.saturating_sub(before), "{text}");
}
