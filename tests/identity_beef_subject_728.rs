//! #728: four BEEF shapes of an `ls_identity` lookup output the #721 and
//! #725 vectors leave, each built here by this crate's BEEF writer to the
//! bytes the reference's writer recorded and served through both identity
//! parsers (`parse_output_to_certificate` by `resolve_by_attributes`,
//! `parse_output_to_verifiable_certificate` by `discover_certificates`):
//! an `outputIndex` past the subject's outputs, a txid-only entry written
//! last, an Atomic BEEF header naming a txid-only entry, and a raw parent
//! whose BUMP names another txid. Against
//! `tests/vectors/identity_beef_subject_728.json`
//! (`tests/support/identity_beef_subject_728.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03`): per shape the bytes, the output index,
//! `parseEvidence`'s selected txid or refusal
//! (`packages/sdk/src/transaction/TransactionEvidence.ts:110-128`, `:143`),
//! the check that refused, and `parseResults`' outcome. Every shape is
//! skipped on both sides, each by its own check (the fourth since #730,
//! whose evidence check is the reference's walk). Hermetic: an in-process
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
    Beef, Kind, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_beef_subject_728.json")).unwrap()
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

/// A block of one transaction, `txid`, at `height`: its BUMP a lone leaf
/// at offset 0.
fn lone_leaf(txid: &str, height: u32) -> MerklePath {
    MerklePath::new(
        height,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// The recorder's transactions (#725's), their txids checked against the
/// vector.
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

/// Shape 1's BEEF, #725's `chain`: the tip and the middle unproven, the
/// grandparent (`parent`) proven, merged newest to oldest.
fn chain(t: &Txs) -> Vec<u8> {
    let mut beef = Beef::new();
    beef.merge_raw_tx(t.tip.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(t.middle.to_binary(), None)
        .expect("the bytes are one transaction");
    let index = beef.merge_bump(lone_leaf(&t.parent.id(), 900));
    beef.merge_raw_tx(t.parent.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    beef.to_binary().expect("the BEEF is writable")
}

/// Shape 2's BEEF: the token's transaction proven at 900, then the parent
/// as a txid-only entry proven by its own BUMP at 901.
fn txid_only_last(t: &Txs) -> Beef {
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(&t.alone.id(), 900));
    beef.merge_raw_tx(t.alone.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    beef.merge_bump(lone_leaf(&t.parent.id(), 901));
    beef.merge_txid_only(t.parent.id());
    beef
}

/// Shape 3's second BEEF: an Atomic BEEF prefix naming the txid-only
/// entry, written by hand as the recorder writes it, before shape 2's bytes
/// (`to_binary_atomic` keeps the subject's graph alone).
fn beside_token(t: &Txs) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut subject = from_hex(&t.parent.id()).unwrap();
    subject.reverse();
    writer.write_bytes(&subject);
    writer.write_bytes(&txid_only_last(t).to_binary().expect("the BEEF is writable"));
    writer.into_bytes()
}

/// Shape 4's BEEF: the parent merged with the index of a BUMP whose one
/// leaf names `another`, and the raw unproven subject spending it.
fn another_bump(t: &Txs, another: &str) -> Vec<u8> {
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(another, 900));
    beef.merge_raw_tx(t.parent.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(t.subject.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.to_binary().expect("the BEEF is writable")
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

/// How many identities and certificates the two parsers return for `beef`
/// served at `output_index`.
async fn read(beef: Vec<u8>, output_index: u32, subject: &str) -> (usize, usize) {
    let output = OutputListItem {
        beef,
        output_index,
        context: None,
        txid: None,
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

/// The recorded shape's bytes equal `built`; its output index, its
/// recorded outcome and refusing line; its selected txid, the one field the
/// reference's `parseEvidence` itself produces, `refused: Transaction
/// evidence: invalid-evidence` on every shape here.
fn recorded(v: &Value, name: &str, built: &[u8]) -> (u32, String, String) {
    let case = shape(v, name);
    assert_eq!(
        to_hex(built),
        case["beef"].as_str().unwrap(),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        case["selected_txid"], "refused: Transaction evidence: invalid-evidence",
        "{name}: parseEvidence's answer"
    );
    (
        case["output_index"].as_u64().unwrap() as u32,
        case["outcome"].as_str().unwrap().to_string(),
        case["refused_at"].as_str().unwrap_or("").to_string(),
    )
}

/// 1. #725's chain served at `outputIndex` 1, past the subject's one
/// output: the reference reads the subject and refuses the index
/// (`TransactionEvidence.ts:126`), so `parseResults` skips the output. Here
/// `Transaction::from_beef` reads the same subject, the resolver keeps the
/// output (its dedup reads the txid alone), and both parsers skip it at
/// `outputs.get`. The same verdict through the same check; GREEN on
/// `0d8546c0` too, whose `beef.txs.first()` (the grandparent) has one
/// output: an agreement pinned.
#[tokio::test]
async fn an_output_index_past_the_subjects_outputs_is_skipped_by_both_parsers_728() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let beef = chain(&t);
    let v725: Value =
        serde_json::from_str(include_str!("vectors/identity_beef_subject_725.json")).unwrap();
    assert_eq!(
        to_hex(&beef),
        shape(&v725, "chain")["beef"].as_str().unwrap(),
        "#725's chain bytes"
    );
    let (index, outcome, refused_at) = recorded(&v, "output_index_past_outputs", &beef);
    assert_eq!(index, 1);
    assert_eq!(outcome, "skipped");
    assert_eq!(
        refused_at,
        format!(
            "TransactionEvidence.ts:126: {} has 1 outputs, outputIndex 1",
            t.tip.id()
        )
    );
    let tx = Transaction::from_beef(&beef, None).unwrap();
    assert_eq!((tx.id(), tx.outputs.len()), (t.tip.id(), 1));
    assert_eq!(read(beef.clone(), index, &subject).await, (0, 0));
    // The control: the same output at index 0 is read
    assert_eq!(read(beef, 0, &subject).await, (1, 1));
}

/// 2. A txid-only entry written after the token's proven transaction, no
/// atomic header, by both writers (`to_binary`; the reference's
/// `Beef.toBinary`, whose sort keeps the txid-only entry last, so no hand
/// bytes). The reference picks the last entry and its
/// `findAtomicTransaction` is undefined for a txid-only one
/// (`TransactionEvidence.ts:120-121`). Here `Transaction::from_beef` picks
/// the same entry and finds no transaction, so the resolver's dedup drops
/// the output before any parser, as the reference's resolver drops an
/// output whose `Transaction.fromBEEF` throws: GREEN on `0d8546c0` at this
/// door. The parsers' own skip, RED on `0d8546c0` (`beef.txs.first()` read
/// the token's transaction), is the unit test
/// `src/identity/client_beef_subject_728_tests.rs`.
#[tokio::test]
async fn a_txid_only_entry_written_last_is_skipped_by_both_parsers_728() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let beef = txid_only_last(&t)
        .to_binary()
        .expect("the BEEF is writable");
    let (index, outcome, refused_at) = recorded(&v, "txid_only_last", &beef);
    assert_eq!((index, outcome.as_str()), (0, "skipped"));
    assert_eq!(
        refused_at,
        format!(
            "TransactionEvidence.ts:120-121: findAtomicTransaction({}) is undefined",
            t.parent.id()
        )
    );
    let parsed = Beef::from_binary(&beef).unwrap();
    let order: Vec<String> = parsed.txs.iter().map(|tx| tx.txid()).collect();
    assert_eq!(order, [t.alone.id(), t.parent.id()]);
    assert!(parsed.atomic_txid.is_none());
    assert!(Transaction::from_beef(&beef, None).is_err());
    assert_eq!(read(beef, index, &subject).await, (0, 0));
}

/// 3. An Atomic BEEF header naming the txid-only entry as its subject:
/// written by both atomic writers (`to_binary_atomic`, the reference's
/// `Beef.toBinaryAtomic`, which keep the subject alone), and by hand before
/// shape 2's bytes, so the token's transaction is the entry a wrong pick
/// would read. The reference's `findAtomicTransaction(atomicTxid)` is
/// undefined (`TransactionEvidence.ts:120-121`); here
/// `Transaction::from_beef` finds no transaction for the header's txid and
/// the resolver drops the output, GREEN on `0d8546c0` at this door; the
/// parsers' own skip of the hand shape is RED there in the unit test
/// (`beef.txs.first()` the token's transaction), the atomic writer's shape
/// GREEN on both (its one entry holds no transaction).
#[tokio::test]
async fn an_atomic_header_naming_a_txid_only_entry_is_skipped_by_both_parsers_728() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let atomic = txid_only_last(&t).to_binary_atomic(&t.parent.id()).unwrap();
    for (name, beef) in [
        ("atomic_txid_only_subject", atomic),
        ("atomic_txid_only_subject_beside_token", beside_token(&t)),
    ] {
        let (index, outcome, refused_at) = recorded(&v, name, &beef);
        assert_eq!((index, outcome.as_str()), (0, "skipped"), "{name}");
        assert_eq!(
            refused_at,
            format!(
                "TransactionEvidence.ts:120-121: findAtomicTransaction({}) is undefined",
                t.parent.id()
            ),
            "{name}"
        );
        let parsed = Beef::from_binary(&beef).unwrap();
        assert_eq!(parsed.atomic_txid.as_deref(), Some(t.parent.id().as_str()));
        assert!(Transaction::from_beef(&beef, None).is_err(), "{name}");
        assert_eq!(read(beef, index, &subject).await, (0, 0), "{name}");
    }
}

/// 4. A raw parent merged with the index of a BUMP whose one leaf names
/// another txid, and the raw unproven subject spending it, by both writers
/// (`merge_raw_tx` with the index, `to_binary`; the reference's
/// `mergeRawTx`, `Beef.toBinary`). The reference reads the BEEF
/// (`fromBinaryStrict` checks no BUMP index), finds no BUMP carrying the
/// parent's txid (`findBump`, `Beef.ts:570-574`), so the parent is
/// unproven and its input has no source transaction
/// (`TransactionEvidence.ts:143`): skipped. Since #730 both parsers run that
/// walk (`src/identity/evidence.rs`) and skip it at the same node; the
/// check is the walk and not `Beef::verify_structure`, whose `TxidNotInBump`
/// (the streaming reader's `check_bump_index` raises it too) neither side
/// asks here (`tests/identity_evidence_730.rs` reads this BEEF with the
/// grandparent proven). RED on `11bb04ce`, which read the subject's token
/// (`(1, 1)`), the stated residue #730 closes; RED on `0d8546c0` too, whose
/// `beef.txs.first()`, the parent (`OP_TRUE`), skipped it by accident, so
/// the pin read the residue then.
#[tokio::test]
async fn a_parent_whose_bump_names_another_txid_is_skipped_as_the_reference_skips_it_728() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let t = txs(&v, &token);
    let another = v["another_txid"].as_str().unwrap();
    let beef = another_bump(&t, another);
    let (index, outcome, refused_at) = recorded(&v, "bump_names_another_txid", &beef);
    assert_eq!((index, outcome.as_str()), (0, "skipped"));
    assert_eq!(
        refused_at,
        format!(
            "TransactionEvidence.ts:143: {} input {}.0 has no source transaction",
            t.parent.id(),
            "11".repeat(32)
        )
    );
    let mut parsed = Beef::from_binary(&beef).unwrap();
    assert_eq!(parsed.verify_structure(), Err(Kind::TxidNotInBump));
    let selected = Transaction::from_beef(&beef, None).unwrap();
    assert_eq!(selected.id(), t.subject.id());
    let parent = selected.inputs[0].source_transaction.as_ref().unwrap();
    assert!(parent.merkle_path.is_none(), "the parent unproven");
    assert_eq!(read(beef, index, &subject).await, (0, 0), "this crate");
}
