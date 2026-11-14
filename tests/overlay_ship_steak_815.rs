//! #815: a host's STEAK is judged as the reference judges it
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//!
//! ```text
//! 486:        if (steak == null || Object.keys(steak).length === 0) {
//! 487:          throw new Error('Steak has no topics.')
//! 489:        return {
//! 492:          steak: validateSTEAK(steak, [...topics])
//! 494:      } catch (error) {
//! 495:        return { host, success: false, error }
//! 240: function validateSTEAK(value: unknown, topics: string[]): STEAK {
//! 243:   if (entries.length > MAX_SHIP_TOPICS) throw new Error('SHIP response contains too many topics.')
//! 247:     if (!allowedTopics.has(topic) || !isPlainRecord(rawInstructions)) {
//! 248:       throw new Error('SHIP response acknowledged an unexpected topic.')
//! 222: function validateInstructionIndexes(value: unknown, label: string): number[] {
//! 223:   if (!Array.isArray(value) || value.length > MAX_SHIP_INSTRUCTION_INDEXES) {
//! 224:     throw new Error(`SHIP ${label} is invalid.`)
//! 231:     if (!Number.isSafeInteger(index) || index < 0 || index > 0xffffffff || seen.has(index)) {
//! ```
//!
//! A host whose STEAK is refused is a failed host: the only interested host
//! failing, the broadcast is `ERR_ALL_HOSTS_REJECTED` (`:500-506`), where
//! until #815 the STEAK was taken as given and the broadcast succeeded. The
//! advertisement is this crate's writer's, read through a real
//! `LookupResolver` (an `.invalid` `ls_ship` override, a scripted lookup
//! facilitator); the STEAK a scripted broadcast facilitator's. Nothing is
//! dialled.
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
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TOPIC: &str = "tm_ship_steak";

/// A lookup facilitator answering every question with its one answer.
struct Scripted(LookupAnswer);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0.clone())
    }
}

/// A broadcast facilitator answering its one STEAK, recording the topics
/// each send carried.
struct Answering {
    steak: Steak,
    sent: Mutex<Vec<Vec<String>>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Answering {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        self.sent.lock().unwrap().push(tagged.topics.clone());
        Ok(self.steak.clone())
    }
}

/// One SHIP advertisement of `TOPIC` by this crate's writer, proven by a
/// block of its own, as a lookup output; the transaction broadcast is the
/// advertisement itself (proven, so `to_beef` needs no source).
fn advertisement() -> (OutputListItem, Transaction) {
    let script = create_signed_overlay_admin_token(
        &PrivateKey::random(),
        Protocol::Ship,
        "https://steak.ship-steak-815.invalid",
        TOPIC,
    );
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32).parse().unwrap(), 0))
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

/// The broadcast's code (`None` on success) when the one interested host
/// answers `steak`, and the topics sent to it.
async fn broadcast(steak: Steak) -> (Option<String>, Vec<Vec<String>>) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let (output, subject) = advertisement();
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted(LookupAnswer::OutputList {
            outputs: vec![output],
        }))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![format!("https://ls-ship-{n}.ship-steak-815-rs.invalid")],
        )])),
        ..Default::default()
    }));
    let facilitator = Arc::new(Answering {
        steak,
        sent: Mutex::new(vec![]),
    });
    let b = TopicBroadcaster::new(
        vec![TOPIC.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver),
            facilitator: Some(facilitator.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let code = b.broadcast_tx(&subject).await.err().map(|f| f.code);
    let sent = facilitator.sent.lock().unwrap().clone();
    (code, sent)
}

fn admit(indexes: Vec<u32>) -> AdmittanceInstructions {
    AdmittanceInstructions {
        outputs_to_admit: indexes,
        coins_to_retain: vec![],
        coins_removed: None,
    }
}

/// The control: a STEAK of the topic sent, distinct indexes, is taken.
#[tokio::test]
async fn a_steak_of_the_sent_topic_is_taken_815() {
    let (code, sent) = broadcast(Steak::from([(TOPIC.to_string(), admit(vec![0]))])).await;
    assert_eq!(code, None);
    assert_eq!(sent, vec![vec![TOPIC.to_string()]]);
}

/// `:247-248`: a topic the host was not sent fails the host; it was the
/// only host, so every host rejected (on the base, `Ok`: the sent topic
/// acknowledged, the other taken as given).
#[tokio::test]
async fn a_steak_acknowledging_an_unsent_topic_fails_its_host_815() {
    let (code, sent) = broadcast(Steak::from([
        (TOPIC.to_string(), admit(vec![0])),
        ("tm_other".to_string(), admit(vec![0])),
    ]))
    .await;
    assert_eq!(sent, vec![vec![TOPIC.to_string()]]);
    assert_eq!(code.as_deref(), Some("ERR_ALL_HOSTS_REJECTED"));
}

/// `:231`: an index seen twice in one list fails the host.
#[tokio::test]
async fn a_steak_with_a_repeated_index_fails_its_host_815() {
    let (code, _) = broadcast(Steak::from([(TOPIC.to_string(), admit(vec![0, 0]))])).await;
    assert_eq!(code.as_deref(), Some("ERR_ALL_HOSTS_REJECTED"));
    let removed = AdmittanceInstructions {
        outputs_to_admit: vec![0],
        coins_to_retain: vec![],
        coins_removed: Some(vec![1, 1]),
    };
    let (code, _) = broadcast(Steak::from([(TOPIC.to_string(), removed)])).await;
    assert_eq!(code.as_deref(), Some("ERR_ALL_HOSTS_REJECTED"));
}

/// `:223`: a list of more than 4096 indexes fails the host; 4096 is taken.
#[tokio::test]
async fn a_steak_of_4097_indexes_fails_its_host_815() {
    let (code, _) = broadcast(Steak::from([(
        TOPIC.to_string(),
        admit((0..4096).collect()),
    )]))
    .await;
    assert_eq!(code, None);
    let (code, _) = broadcast(Steak::from([(
        TOPIC.to_string(),
        admit((0..4097).collect()),
    )]))
    .await;
    assert_eq!(code.as_deref(), Some("ERR_ALL_HOSTS_REJECTED"));
}
