//! #725: three BEEF shapes of an `ls_identity` lookup output the #721 vector
//! leaves, each built here by this crate's BEEF writer to the bytes the
//! reference's writer recorded and served through both identity parsers
//! (`parse_output_to_certificate` by `resolve_by_attributes`,
//! `parse_output_to_verifiable_certificate` by `discover_certificates`):
//! an Atomic BEEF header naming a txid absent from the entries, a txid-only
//! parent before a raw unproven subject, and a three-transaction chain.
//! Against `tests/vectors/identity_beef_subject_725.json`
//! (`tests/support/identity_beef_subject_725.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03`): per shape the bytes, `parseEvidence`'s selected txid
//! or refusal (`packages/sdk/src/transaction/TransactionEvidence.ts:110-127`,
//! `:143`), the check that refused, and `parseResults`' outcome; every shape
//! answered as the reference answers it since #730 (the txid-only parent
//! skipped by the reference's evidence walk). Hermetic: an in-process
//! facilitator on an `.invalid` host.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::IdentityClient;
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_hex, to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// `parseEvidence`'s answer on every shape it refuses.
const REFUSED: &str = "refused: Transaction evidence: invalid-evidence";

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_beef_subject_725.json")).unwrap()
}

/// The recorded shape of `name`.
fn shape<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no shape {name}"))
}

/// The reference's own revelation token and its subject (#553's vector).
fn token_and_subject() -> (LockingScript, String) {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    let script = LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap());
    (script.unwrap(), v["subject"].as_str().unwrap().to_string())
}

/// One input spending `txid:0` with `unlocking`, one 1-satoshi output.
fn spending(txid: String, unlocking: &str, output: LockingScript) -> Transaction {
    let mut input = TransactionInput::new(txid, 0);
    input.set_unlocking_script(UnlockingScript::from_hex(unlocking).unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, output)).unwrap();
    tx
}

/// A block of `tx` alone at height 900: its BUMP a lone leaf at offset 0.
fn lone_leaf(tx: &Transaction) -> MerklePath {
    MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap()
}

/// The recorder's transactions, their txids checked against the vector.
struct Txs {
    alone: Transaction,
    parent: Transaction,
    subject: Transaction,
    middle: Transaction,
    tip: Transaction,
}

fn txs(v: &Value, token: &LockingScript) -> Txs {
    let op_true = LockingScript::from_hex("51").unwrap();
    let alone = spending("11".repeat(32), "51", token.clone());
    let parent = spending("11".repeat(32), "51", op_true.clone());
    let subject = spending(parent.id(), "", token.clone());
    let middle = spending(parent.id(), "", op_true);
    let tip = spending(middle.id(), "", token.clone());
    for (tx, key) in [
        (&alone, "alone_txid"),
        (&parent, "parent_txid"),
        (&parent, "grandparent_txid"),
        (&subject, "subject_txid"),
        (&middle, "middle_txid"),
        (&tip, "tip_txid"),
    ] {
        assert_eq!(tx.id(), v[key].as_str().unwrap(), "{key}");
    }
    Txs {
        alone,
        parent,
        subject,
        middle,
        tip,
    }
}

/// Shape (a)'s BEEF: the lone token transaction, proven, after an Atomic
/// BEEF prefix naming `absent`, in the order held (`to_binary_atomic`
/// refuses a subject it does not hold, as the reference's `toBinaryAtomic`
/// does, so both sides write the prefix by hand).
fn absent_atomic_txid(t: &Txs, absent: &str) -> Vec<u8> {
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(&t.alone));
    beef.merge_raw_tx(t.alone.to_binary(), Some(index));
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut subject = from_hex(absent).unwrap();
    subject.reverse();
    writer.write_bytes(&subject);
    beef.to_writer(&mut writer);
    writer.into_bytes()
}

/// Shape (b)'s BEEF: the parent's BUMP, the parent as a txid-only entry
/// and the raw unproven subject spending it.
fn txid_only_parent(t: &Txs) -> Beef {
    let mut beef = Beef::new();
    beef.merge_bump(lone_leaf(&t.parent));
    beef.merge_txid_only(t.parent.id());
    beef.merge_raw_tx(t.subject.to_binary(), None);
    beef
}

/// Shape (c)'s BEEF: the tip and the middle unproven, the grandparent
/// proven, merged newest first so the writer's sort decides the order.
fn chain(t: &Txs) -> Beef {
    let mut beef = Beef::new();
    beef.merge_raw_tx(t.tip.to_binary(), None);
    beef.merge_raw_tx(t.middle.to_binary(), None);
    let index = beef.merge_bump(lone_leaf(&t.parent));
    beef.merge_raw_tx(t.parent.to_binary(), Some(index));
    beef
}

/// A facilitator answering every question with one output.
struct Answering(OutputListItem);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![self.0.clone()],
        })
    }
}

/// How many identities and certificates the two parsers return for `beef`.
async fn read(beef: Vec<u8>, subject: &str) -> (usize, usize) {
    let output = OutputListItem {
        beef,
        output_index: 0,
        context: None,
    };
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(output))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let certificates = client.discover_certificates(subject).await.unwrap();
    (identities.len(), certificates.len())
}

/// The recorded shape's bytes equal `built`, its selected txid (the one
/// field the reference's `parseEvidence` itself produces) is `selected`, and
/// its recorded outcome and refusing line.
fn recorded(v: &Value, name: &str, built: &[u8], selected: &str) -> (String, String) {
    let case = shape(v, name);
    assert_eq!(
        to_hex(built),
        case["beef"].as_str().unwrap(),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        case["selected_txid"], selected,
        "{name}: parseEvidence's answer"
    );
    (
        case["outcome"].as_str().unwrap().to_string(),
        case["refused_at"].as_str().unwrap_or("").to_string(),
    )
}

/// (a) An Atomic BEEF whose header names a txid none of its entries
/// carries: the reference's `findAtomicTransaction(beef.atomicTxid)` is
/// undefined and `parseEvidence` throws (`TransactionEvidence.ts:118-121`),
/// so `parseResults` skips the output. Here the output never reaches a
/// parser: `LookupResolver`'s dedup takes each output's txid from
/// `Transaction::from_beef`, which refuses this BEEF ("not found in BEEF"),
/// and drops it, as the reference's resolver drops an output whose
/// `Transaction.fromBEEF` throws (`LookupResolver.ts:2232-2237`). So the
/// public doors skip it on the base too; the parsers' own skip, RED on
/// `0d8546c0` (`beef.txs.first()` read the token's transaction), is the unit
/// test `src/identity/client_beef_subject_725_tests.rs`.
#[tokio::test]
async fn an_atomic_header_naming_an_absent_txid_is_skipped_by_both_parsers_725() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let beef = absent_atomic_txid(&t, v["absent_txid"].as_str().unwrap());
    let (outcome, refused_at) = recorded(&v, "absent_atomic_txid", &beef, REFUSED);
    assert_eq!(outcome, "skipped");
    assert_eq!(
        refused_at,
        format!(
            "TransactionEvidence.ts:120-121: findAtomicTransaction({}) is undefined",
            v["absent_txid"].as_str().unwrap()
        )
    );
    // The BEEF itself parses, its one entry the token's transaction
    let parsed = Beef::from_binary(&beef).unwrap();
    assert_eq!(parsed.txs.len(), 1);
    assert_eq!(parsed.txs[0].txid(), t.alone.id());
    assert!(Transaction::from_beef(&beef, None).is_err());
    assert_eq!(read(beef, &subject).await, (0, 0));
}

/// (b) A txid-only parent (proven by its BUMP) before the raw unproven
/// subject, in the order both writers' sorts give, plain and atomic. The
/// reference selects the subject and then refuses it in
/// `assertUnconfirmedGraph` (`TransactionEvidence.ts:155-177`): its input's
/// source transaction is absent (`enqueueUnconfirmedParents`, `:143`), so
/// `parseResults` skips the output. Since #730 both parsers run that walk
/// (`src/identity/evidence.rs`) and skip it at the same node, the subject's
/// input: the agreement. RED on `11bb04ce`, which read the subject's token
/// (`(1, 1)`), #553's stated evidence-layer residue that #730 closes.
#[tokio::test]
async fn a_txid_only_parent_before_an_unproven_subject_is_skipped_as_the_reference_skips_it_725() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let plain = txid_only_parent(&t).to_binary();
    let atomic = txid_only_parent(&t)
        .to_binary_atomic(&t.subject.id())
        .unwrap();
    for (name, beef) in [
        ("txid_only_parent", plain),
        ("txid_only_parent_atomic", atomic),
    ] {
        let (outcome, refused_at) = recorded(&v, name, &beef, REFUSED);
        assert_eq!(outcome, "skipped", "{name}: the reference");
        assert_eq!(
            refused_at,
            format!(
                "TransactionEvidence.ts:143: {} input {}.0 has no source transaction",
                t.subject.id(),
                t.parent.id()
            ),
            "{name}: the reference's pick is the subject"
        );
        let selected = Transaction::from_beef(&beef, None).unwrap().id();
        assert_eq!(selected, t.subject.id(), "{name}");
        assert_eq!(read(beef, &subject).await, (0, 0), "{name}: this crate");
    }
}

/// (c) A proven grandparent with its BUMP, an unproven parent and the
/// unproven subject, merged newest first and written by both writers'
/// sorts (`to_binary`, `to_binary_atomic`; the reference's `toBinary`,
/// `toBinaryAtomic`): the grandparent first and the subject last on both
/// sides, byte for byte. The reference reads the subject (the last, or the
/// header's) and walks the whole unconfirmed graph to the proof; both
/// parsers read it since #721. Until #721 both read `beef.txs.first()`, the
/// grandparent, whose output 0 is `OP_TRUE`, and skipped the token.
#[tokio::test]
async fn a_three_transaction_chain_is_read_from_its_subject_by_both_parsers_725() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let plain = chain(&t).to_binary();
    let atomic = chain(&t).to_binary_atomic(&t.tip.id()).unwrap();
    for (name, beef) in [("chain", plain), ("chain_atomic", atomic)] {
        let (outcome, refused_at) = recorded(&v, name, &beef, &t.tip.id());
        assert_eq!(
            (outcome.as_str(), refused_at.as_str()),
            ("read", ""),
            "{name}: the reference"
        );
        let parsed = Beef::from_binary(&beef).unwrap();
        let order: Vec<String> = parsed.txs.iter().map(|tx| tx.txid()).collect();
        assert_eq!(
            order,
            [t.parent.id(), t.middle.id(), t.tip.id()],
            "{name}: grandparent first, subject last"
        );
        assert_eq!(
            Transaction::from_beef(&beef, None).unwrap().id(),
            t.tip.id()
        );
        assert_eq!(read(beef, &subject).await, (1, 1), "{name}: this crate");
    }
}
