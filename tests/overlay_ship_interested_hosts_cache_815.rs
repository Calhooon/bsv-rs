//! #815: the interested hosts are kept five minutes and one discovery runs
//! at a time, as the reference's `findInterestedHosts` keeps them
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//!
//! ```text
//! 445:    this.#interestedHostsTtlMs = 5 * 60 * 1000 // 5 minutes
//! 701:    if (this.#interestedHostsCache != null && this.#interestedHostsCache.expiresAt > now) {
//! 702:      return this.#interestedHostsCache.hosts
//! 706:    if (this.#interestedHostsInFlight != null) {
//! 707:      return await this.#interestedHostsInFlight
//! 711:    try {
//! 712:      const hosts = await this.#interestedHostsInFlight
//! 713:      this.#interestedHostsCache = { hosts, expiresAt: Date.now() + this.#interestedHostsTtlMs }
//! 715:    } finally {
//! 716:      this.#interestedHostsInFlight = null
//! ```
//!
//! Until #815 every broadcast asked `ls_ship` again. A counting lookup
//! facilitator behind a real `LookupResolver` (an `.invalid` `ls_ship`
//! override) answers each call from a script; the advertisements are this
//! crate's writer's; the broadcast facilitator acknowledges every topic.
//! The five-minute expiry is the unit test
//! `the_interested_hosts_are_asked_again_after_five_minutes_815`
//! (`src/overlay/topic_broadcaster/cache.rs`, the clock behind a seam).
//! Nothing is dialled.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, AdmittanceInstructions, LookupAnswer, LookupQuestion,
    LookupResolver, LookupResolverConfig, OutputListItem, OverlayBroadcastFacilitator,
    OverlayLookupFacilitator, Protocol, Steak, TaggedBEEF, TopicBroadcaster,
    TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TOPIC: &str = "tm_ship_cache";

/// A lookup facilitator answering its calls from a script, the last answer
/// repeated, counting the calls.
struct Counting {
    answers: Vec<LookupAnswer>,
    calls: AtomicUsize,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Counting {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers[n.min(self.answers.len() - 1)].clone())
    }
}

/// A broadcast facilitator acknowledging every topic it is sent.
struct Acknowledging(Mutex<usize>);

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Acknowledging {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        *self.0.lock().unwrap() += 1;
        Ok(tagged
            .topics
            .iter()
            .map(|t| {
                (
                    t.clone(),
                    AdmittanceInstructions {
                        outputs_to_admit: vec![0],
                        coins_to_retain: vec![],
                        coins_removed: None,
                    },
                )
            })
            .collect())
    }
}

/// A SHIP advertisement of `domain` for `TOPIC` by this crate's writer, its
/// own transaction (`seed` its source index) proven by a block of its own.
fn advertisement(domain: &str, seed: u32) -> (OutputListItem, Transaction) {
    let script =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Ship, domain, TOPIC);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), seed))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let txid = tx.id();
    let mut beef = Beef::new();
    let index = beef
        .merge_bump(MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, txid)]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    let bytes = beef.to_binary().unwrap();
    let subject = Transaction::from_beef(&bytes, None).unwrap();
    (
        OutputListItem {
            beef: bytes,
            output_index: 0,
            context: None,
            txid: None,
        },
        subject,
    )
}

fn host(name: &str) -> String {
    format!("https://{name}.ship-cache-815.invalid")
}

/// A broadcaster over a resolver whose `ls_ship` host (one of its own: the
/// reputation tracker is one global keyed by URL) answers `answers` in turn.
fn broadcaster(
    answers: Vec<LookupAnswer>,
) -> (TopicBroadcaster, Arc<Counting>, Arc<Acknowledging>) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let lookup = Arc::new(Counting {
        answers,
        calls: AtomicUsize::new(0),
    });
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(lookup.clone()),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![format!("https://ls-ship-{n}.ship-cache-815-rs.invalid")],
        )])),
        ..Default::default()
    }));
    let sender = Arc::new(Acknowledging(Mutex::new(0)));
    let b = TopicBroadcaster::new(
        vec![TOPIC.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver),
            facilitator: Some(sender.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    (b, lookup, sender)
}

fn list(outputs: Vec<OutputListItem>) -> LookupAnswer {
    LookupAnswer::OutputList { outputs }
}

/// `:701-702`: a second broadcast within five minutes reads the kept hosts;
/// `ls_ship` is asked once (twice on the base), the second answer, a host
/// advertised since, unseen.
#[tokio::test]
async fn two_broadcasts_ask_ls_ship_once_815() {
    let (early, subject) = advertisement(&host("early"), 0);
    let (later, _) = advertisement(&host("later"), 1);
    let (b, lookup, sender) =
        broadcaster(vec![list(vec![early.clone()]), list(vec![early, later])]);
    b.broadcast_tx(&subject).await.unwrap();
    b.broadcast_tx(&subject).await.unwrap();
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*sender.0.lock().unwrap(), 2);
    let hosts: Vec<String> = b
        .find_interested_hosts()
        .await
        .unwrap()
        .into_keys()
        .collect();
    assert_eq!(hosts, vec![host("early")]);
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
}

/// `:706-707`: discoveries started together share one `ls_ship` lookup.
#[tokio::test]
async fn concurrent_discoveries_ask_ls_ship_once_815() {
    let (together, _) = advertisement(&host("together"), 0);
    let (b, lookup, _) = broadcaster(vec![list(vec![together])]);
    let (x, y, z) = futures::join!(
        b.find_interested_hosts(),
        b.find_interested_hosts(),
        b.find_interested_hosts()
    );
    assert_eq!(x.unwrap(), y.clone().unwrap());
    assert_eq!(y.unwrap(), z.unwrap());
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
}

/// `:711-716`: a failed discovery caches nothing (an answer of 257 outputs,
/// refused `SHIP answer is not a bounded output list.`); the next call asks
/// again and its answer is then kept.
#[tokio::test]
async fn a_failed_discovery_is_not_cached_815() {
    let too_many: Vec<OutputListItem> = (0..257)
        .map(|seed| advertisement(&host("many"), seed).0)
        .collect();
    let (good, _) = advertisement(&host("good"), 300);
    let (b, lookup, _) = broadcaster(vec![list(too_many), list(vec![good])]);
    assert_eq!(
        b.find_interested_hosts().await,
        Err(Error::OverlayError(
            "SHIP answer is not a bounded output list.".into()
        ))
    );
    let hosts: Vec<String> = b
        .find_interested_hosts()
        .await
        .unwrap()
        .into_keys()
        .collect();
    assert_eq!(hosts, vec![host("good")]);
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    b.find_interested_hosts().await.unwrap();
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
}

/// An empty discovery is kept, as the reference keeps `{}`: the broadcast
/// is `ERR_NO_HOSTS_INTERESTED` both times and `ls_ship` asked once.
#[tokio::test]
async fn an_empty_discovery_is_kept_815() {
    let (_, subject) = advertisement(&host("none"), 0);
    let (b, lookup, _) = broadcaster(vec![list(vec![])]);
    for _ in 0..2 {
        assert_eq!(
            b.broadcast_tx(&subject).await.unwrap_err().code,
            "ERR_NO_HOSTS_INTERESTED"
        );
    }
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
}
