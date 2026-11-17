//! Every public async trait is `Send` on every target (#843, the captain's
//! ruling 1 of 2026-11-17), seen from outside the crate: a broadcast, a
//! lookup and a history future are spawned as a `verify` future is, run on a
//! thread other than the one that built them, and awaited inside another
//! `Send` trait's method.
//!
//! Until this change `Broadcaster`, `OverlayLookupFacilitator` and
//! `OverlayBroadcastFacilitator` were `#[async_trait(?Send)]` and the
//! historian's interpreter returned a future with no `Send` bound, so
//! `LookupResolver::query`, `TopicBroadcaster::broadcast_tx`, every client
//! over them and `Historian::build_history` returned futures no
//! multi-threaded runtime could spawn: this file did not compile there
//! (E0053 at each implementation written the plain way, then "future cannot
//! be sent between threads safely" at each spawn).
//!
//! The crate's own witnesses, for every public async door and on wasm32 too,
//! are `src/send_rule/`; `tests/arch_send_rule_843.rs` holds their census.
//! The reference has no such notion (a promise at each of these doors,
//! `ts-stack@edf6e03` `Broadcaster.ts:148-151`, `LookupResolver.ts:692-707`,
//! `SHIPBroadcaster.ts:88-90`): no wire byte, verdict or error text moves.
//!
//! Nothing is dialled: every host is an `.invalid` name handed to a scripted
//! facilitator.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, AdmittanceInstructions, Historian, HistorianConfig,
    InterpreterFn, LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig,
    OutputListItem, OverlayBroadcastFacilitator, OverlayLookupFacilitator, Protocol, Steak,
    TaggedBEEF, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::transaction::{
    Beef, BroadcastResponse, BroadcastResult, Broadcaster, ChainTracker, ChainTrackerError,
    MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::ThreadId;

const TOPIC: &str = "tm_send_rule";

fn assert_send<T: Send>(value: T) -> T {
    value
}

/// Runs a future to its end on a thread of its own, which the future must be
/// `Send` to reach, and answers its output with that thread's id.
fn on_another_thread<F>(future: F) -> (F::Output, ThreadId)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        (runtime.block_on(future), std::thread::current().id())
    })
    .join()
    .unwrap()
}

/// A lookup facilitator answering every question with its one answer and
/// counting the questions.
struct Scripted {
    answer: LookupAnswer,
    asked: AtomicUsize,
}

#[async_trait::async_trait]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(self.answer.clone())
    }
}

/// A broadcast facilitator admitting output 0 under the topic sent.
struct Admitting(AtomicUsize);

#[async_trait::async_trait]
impl OverlayBroadcastFacilitator for Admitting {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(tagged
            .topics
            .iter()
            .map(|topic| {
                (
                    topic.clone(),
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

/// A broadcaster of the caller's own, written the plain way.
struct Counting(AtomicUsize);

#[async_trait::async_trait]
impl Broadcaster for Counting {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(BroadcastResponse::success(tx.id(), "taken".to_string()))
    }
}

/// A resolver whose `service` is one `.invalid` host answering `answer`.
fn resolver(
    service: &str,
    host: &str,
    answer: LookupAnswer,
) -> (Arc<LookupResolver>, Arc<Scripted>) {
    let scripted = Arc::new(Scripted {
        answer,
        asked: AtomicUsize::new(0),
    });
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(scripted.clone()),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            service.to_string(),
            vec![format!("https://{host}.send-rule-843.invalid")],
        )])),
        ..Default::default()
    }));
    (resolver, scripted)
}

/// One SHIP advertisement of `TOPIC` by this crate's writer, proven by a
/// block of its own, as a lookup output; the transaction broadcast is the
/// advertisement itself (proven, so `to_beef` needs no source).
fn advertisement(host: &str) -> (OutputListItem, Transaction) {
    let script = create_signed_overlay_admin_token(
        &PrivateKey::random(),
        Protocol::Ship,
        &format!("https://{host}.send-rule-843.invalid"),
        TOPIC,
    );
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap(),
    );
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

/// A topic broadcaster whose one interested host is `host`, and the
/// transaction to broadcast.
fn topic_broadcaster(host: &str) -> (TopicBroadcaster, Arc<Admitting>, Transaction) {
    let (output, subject) = advertisement(host);
    let (resolver, _) = resolver(
        "ls_ship",
        &format!("ls-ship-{host}"),
        LookupAnswer::OutputList {
            outputs: vec![output],
        },
    );
    let facilitator = Arc::new(Admitting(AtomicUsize::new(0)));
    let broadcaster = TopicBroadcaster::new(
        vec![TOPIC.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver),
            facilitator: Some(facilitator.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    (broadcaster, facilitator, subject)
}

/// The three traits' own futures, through a trait object, by the signatures
/// alone: held at compile time.
const _: fn() = || {
    fn traits(
        broadcaster: &dyn Broadcaster,
        lookup: &dyn OverlayLookupFacilitator,
        submit: &dyn OverlayBroadcastFacilitator,
        tx: &Transaction,
        question: &LookupQuestion,
        tagged: &TaggedBEEF,
    ) {
        drop(assert_send(broadcaster.broadcast(tx)));
        drop(assert_send(broadcaster.broadcast_many(Vec::new())));
        drop(assert_send(lookup.lookup("", question, None)));
        drop(assert_send(lookup.lookup_ordered("", question, None, None)));
        drop(assert_send(submit.send("", tagged)));
    }
    let _ = traits;
};

#[test]
fn a_lookup_future_runs_on_another_thread_843() {
    let (resolver, scripted) = resolver(
        "ls_send_rule_lookup",
        "lookup-thread",
        LookupAnswer::OutputList { outputs: vec![] },
    );
    let question = LookupQuestion::new("ls_send_rule_lookup", serde_json::json!({ "any": 1 }));
    let (answer, ran_on) = on_another_thread(async move { resolver.query(&question, None).await });
    assert!(matches!(
        answer.unwrap(),
        LookupAnswer::OutputList { outputs } if outputs.is_empty()
    ));
    assert_eq!(scripted.asked.load(Ordering::SeqCst), 1);
    assert_ne!(ran_on, std::thread::current().id());
}

#[tokio::test]
async fn a_lookup_future_is_spawned_as_a_verify_future_is_843() {
    let (resolver, scripted) = resolver(
        "ls_send_rule_spawn",
        "lookup-spawn",
        LookupAnswer::OutputList { outputs: vec![] },
    );
    let question = LookupQuestion::new("ls_send_rule_spawn", serde_json::json!({ "any": 1 }));
    let asking = resolver.clone();
    let answer = tokio::spawn(async move { asking.query(&question, None).await })
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()));
    // a door that asks no host, the same way
    let held = tokio::spawn(async move { resolver.tx_memo_cache_size().await })
        .await
        .unwrap();
    assert_eq!(held, 0);
    assert_eq!(scripted.asked.load(Ordering::SeqCst), 1);
}

#[test]
fn a_broadcast_future_runs_on_another_thread_843() {
    // a caller's own broadcaster, held as the trait object every door takes
    let counting = Arc::new(Counting(AtomicUsize::new(0)));
    let held: Arc<dyn Broadcaster> = counting.clone();
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput::new(
        1,
        bsv_rs::script::LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    let again = tx.clone();
    let (answers, ran_on) = on_another_thread(async move {
        let one = held.broadcast(&tx).await;
        // the default method, over the same future
        let many = held.broadcast_many(vec![again.clone(), again]).await;
        (one, many)
    });
    assert_eq!(answers.0.unwrap().txid, txid);
    assert_eq!(answers.1.len(), 2);
    assert_eq!(counting.0.load(Ordering::SeqCst), 3);
    assert_ne!(ran_on, std::thread::current().id());

    // the crate's overlay broadcaster, by its own door and by the trait's
    let (broadcaster, facilitator, subject) = topic_broadcaster("broadcast-thread");
    let expected = subject.id();
    let (answers, ran_on) = on_another_thread(async move {
        let by_door = broadcaster.broadcast_tx(&subject).await;
        let by_trait = Broadcaster::broadcast(&broadcaster, &subject).await;
        (by_door, by_trait)
    });
    assert_eq!(answers.0.unwrap().txid, expected);
    assert_eq!(answers.1.unwrap().txid, expected);
    assert_eq!(facilitator.0.load(Ordering::SeqCst), 2);
    assert_ne!(ran_on, std::thread::current().id());
}

#[tokio::test]
async fn a_broadcast_future_is_spawned_as_a_verify_future_is_843() {
    let (broadcaster, facilitator, subject) = topic_broadcaster("broadcast-spawn");
    let expected = subject.id();
    let broadcaster = Arc::new(broadcaster);
    let sending = broadcaster.clone();
    let answer = tokio::spawn(async move { sending.broadcast_tx(&subject).await })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer.txid, expected);
    let hosts = tokio::spawn(async move { broadcaster.find_interested_hosts().await })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(facilitator.0.load(Ordering::SeqCst), 1);
}

/// A tracker that answers from an overlay lookup: a lookup awaited inside a
/// method of another `Send` trait, which a future that is not `Send` cannot
/// be.
struct LookupTracker(Arc<LookupResolver>);

#[async_trait::async_trait]
impl ChainTracker for LookupTracker {
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Ok(false)
    }

    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        let question = LookupQuestion::new("ls_send_rule_tracker", serde_json::json!({}));
        match self.0.query(&question, None).await {
            Ok(LookupAnswer::OutputList { outputs }) => Ok(outputs.len() as u32),
            other => Err(ChainTrackerError::Other(format!("{other:?}"))),
        }
    }
}

#[test]
fn a_lookup_is_awaited_inside_another_send_traits_method_843() {
    let (resolver, scripted) = resolver(
        "ls_send_rule_tracker",
        "lookup-tracker",
        LookupAnswer::OutputList { outputs: vec![] },
    );
    let tracker: Arc<dyn ChainTracker> = Arc::new(LookupTracker(resolver));
    let (height, ran_on) = on_another_thread(async move { tracker.current_height().await });
    assert_eq!(height.unwrap(), 0);
    assert_eq!(scripted.asked.load(Ordering::SeqCst), 1);
    assert_ne!(ran_on, std::thread::current().id());
}

#[test]
fn a_history_future_runs_on_another_thread_843() {
    // the interpreter's future is `Send` by the alias: `Box::pin(async move ..)`
    // over `Send` captures is written as before
    let interpreter: InterpreterFn<u32, ()> =
        Box::new(|_tx, vout, _context| Box::pin(async move { Some(vout) }));
    let historian = Historian::new(interpreter, HistorianConfig::default());
    let mut tx = Transaction::new();
    for _ in 0..3 {
        tx.add_output(TransactionOutput::new(
            1,
            bsv_rs::script::LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
    }
    let (history, ran_on) =
        on_another_thread(async move { historian.build_history(&tx, None).await });
    assert_eq!(history.unwrap(), vec![2, 1, 0]);
    assert_ne!(ran_on, std::thread::current().id());
}
