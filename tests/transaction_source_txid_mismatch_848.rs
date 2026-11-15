//! #848: `Transaction::sign` and `Transaction::verify` refuse an input whose
//! `source_txid` differs from its linked source's id, as the reference does
//! (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`: sign
//! `:964-984`, over a complete or anchored source, a no-input descriptor
//! exempt; verify `:1423-1432`, whatever the source holds). Until #848 `sign`
//! committed a signature to the named outpoint with the linked source's
//! amount and script, and `verify` found each source by the named txid alone:
//! a named txid that was another reachable transaction's id was judged
//! against that transaction's output and could answer `Ok(true)`.
//!
//! The expected answers are the reference's, recorded by
//! `support/source_txid_mismatch_848.mjs` into
//! `vectors/source_txid_mismatch_848.json` (Node v22.18.0): twelve cells, each
//! with `sign`, `verify` with a tracker, `verify('scripts only')` and
//! `preimage(0)`. Every fixture is built here with this crate's own writers,
//! its bytes the recording's (`built.hex`, `built.ef`), and every recorded
//! `sign` and tracker `verify` answer is asserted.
//!
//! Stated, not followed (both sides refuse; the words or the order differ):
//! `verify('scripts only')` and `preimage` have no twin here; an input with a
//! mismatch and a missing source output is refused by this crate's `sign` in
//! the mismatch's words, where the reference names the output; one with a
//! mismatch and no unlocking script is refused by this crate's `verify` in the
//! mismatch's words, where the reference says `unlockingScript is undefined`;
//! and `verify` here reads every input's source before it runs a script, so a
//! mismatch at input 1 is named ahead of input 0's failing script, which the
//! reference names.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bsv_rs::script::{LockingScript, ScriptTemplateUnlock, UnlockingScript};
use bsv_rs::transaction::{
    AlwaysValidChainTracker, MerklePath, MerklePathLeaf, Transaction, TransactionInput,
    TransactionOutput, Utxo,
};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/source_txid_mismatch_848.json");
const SIGN_WORDS: &str = "sourceTXID does not reference its supplied source transaction.";
const VERIFY_WORDS: &str = "does not reference its supplied source transaction.";

fn reference(cell: &str) -> Value {
    let doc: Value = serde_json::from_str(VECTOR).unwrap();
    doc["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cell"] == cell)
        .cloned()
        .unwrap_or_else(|| panic!("cell {cell} recorded"))
}

fn other() -> String {
    "ab".repeat(32)
}

fn unlock(bytes: &[u8]) -> Option<UnlockingScript> {
    Some(UnlockingScript::from_binary(bytes).unwrap())
}

fn one(sats: u64) -> TransactionOutput {
    TransactionOutput::new(sats, LockingScript::from_binary(&[0x51]).unwrap())
}

fn bump(txid: &str) -> MerklePath {
    MerklePath::new(
        100,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// The recorder's `root`: one input naming `fill` repeated, `outs` outputs,
/// proven by a path of its own.
fn root(fill: &str, sats: u64, outs: usize) -> Transaction {
    let mut t = Transaction::new();
    let mut i = TransactionInput::new(fill.repeat(32).parse().unwrap(), 0);
    i.unlocking_script = unlock(&[]);
    t.add_input(i).unwrap();
    for _ in 0..outs {
        t.add_output(one(sats)).unwrap();
    }
    t.merkle_path = Some(bump(&t.id()));
    t
}

/// The recorder's `middle`: a complete unproven source spending `src`'s
/// output 0.
fn middle(src: Transaction, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    t.add_input(link(src, None, 0, Some(&[]))).unwrap();
    t.add_output(one(sats)).unwrap();
    t
}

/// The recorder's `descriptor`: no inputs, the one output, as `from_ef`
/// builds it.
fn descriptor(sats: u64) -> Transaction {
    Transaction::with_params(1, vec![], vec![one(sats)], 0)
}

/// An input linking `src` and naming `named` (its id when `None`).
fn link(
    src: Transaction,
    named: Option<String>,
    vout: u32,
    unlocking: Option<&[u8]>,
) -> TransactionInput {
    let named = named.unwrap_or_else(|| src.id());
    let mut i = TransactionInput::with_source_transaction(src, vout);
    i.source_txid = Some(named.parse().unwrap());
    i.unlocking_script = unlocking.and_then(unlock);
    i
}

fn child(inputs: Vec<TransactionInput>) -> Transaction {
    let mut t = Transaction::new();
    for i in inputs {
        t.add_input(i).unwrap();
    }
    t.add_output(one(5)).unwrap();
    t
}

/// The recorder's cells, by name.
fn build(cell: &str) -> Transaction {
    let complete = || middle(root("11", 1000, 1), 900);
    match cell {
        "matching" => child(vec![link(complete(), None, 0, Some(&[]))]),
        "mismatch_complete" => child(vec![link(complete(), Some(other()), 0, Some(&[]))]),
        "mismatch_proven" => child(vec![link(root("11", 1000, 1), Some(other()), 0, Some(&[]))]),
        "mismatch_anchored_no_inputs" => {
            let mut d = descriptor(900);
            d.merkle_path = Some(bump(&d.id()));
            child(vec![link(d, Some(other()), 0, Some(&[]))])
        }
        "mismatch_descriptor" => child(vec![link(descriptor(900), Some(other()), 0, Some(&[]))]),
        "from_ef" => Transaction::from_ef(&build("matching").to_ef().unwrap()).unwrap(),
        "upper_matching" => {
            let s = complete();
            let upper = s.id().to_uppercase();
            child(vec![link(s, Some(upper), 0, Some(&[]))])
        }
        "upper_matching_proven" => {
            let s = root("11", 1000, 1);
            let upper = s.id().to_uppercase();
            child(vec![link(s, Some(upper), 0, Some(&[]))])
        }
        "named_other_inputs_source" => {
            let b = root("22", 1000, 2);
            child(vec![
                link(root("11", 1000, 1), Some(b.id()), 0, Some(&[])),
                link(b, None, 1, Some(&[])),
            ])
        }
        "mismatch_and_output_missing" => {
            child(vec![link(root("11", 1000, 1), Some(other()), 5, Some(&[]))])
        }
        "mismatch_and_no_unlocking_script" => {
            child(vec![link(root("11", 1000, 1), Some(other()), 0, None)])
        }
        "failing_script_before_mismatch" => child(vec![
            link(root("11", 1000, 1), None, 0, Some(&[0x00])),
            link(root("22", 1000, 1), Some(other()), 0, Some(&[])),
        ]),
        _ => panic!("cell {cell}"),
    }
}

/// Every input given a template that counts its calls and answers the empty
/// script, as the recorder's; then `sign`. The answer, the calls made, the
/// transaction after, and its id as `sign` was handed it.
async fn sign(mut tx: Transaction) -> (Result<(), Error>, usize, Transaction, String) {
    let calls = Arc::new(AtomicUsize::new(0));
    for input in tx.inputs_mut() {
        input.unlocking_script = None;
        let calls = calls.clone();
        input.set_unlocking_script_template(ScriptTemplateUnlock::new(
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                UnlockingScript::from_binary(&[])
            },
            || 0,
        ));
    }
    let handed = tx.id();
    let answer = tx.sign().await;
    (answer, calls.load(Ordering::SeqCst), tx, handed)
}

async fn verify(tx: &Transaction) -> Result<bool, Error> {
    tx.verify(&AlwaysValidChainTracker::new(1000), None, None)
        .await
}

fn words(answer: &Result<impl std::fmt::Debug, Error>) -> String {
    match answer {
        Err(Error::TransactionError(words)) => words.clone(),
        other => panic!("a TransactionError, got {other:?}"),
    }
}

const CELLS: [&str; 12] = [
    "matching",
    "mismatch_complete",
    "mismatch_proven",
    "mismatch_anchored_no_inputs",
    "mismatch_descriptor",
    "from_ef",
    "upper_matching",
    "upper_matching_proven",
    "named_other_inputs_source",
    "mismatch_and_output_missing",
    "mismatch_and_no_unlocking_script",
    "failing_script_before_mismatch",
];

/// Cells where both sides refuse and the words or the order differ (the
/// header): asserted apart, by name.
const SIGN_STATED: [&str; 1] = ["mismatch_and_output_missing"];
const VERIFY_STATED: [&str; 2] = [
    "mismatch_and_no_unlocking_script",
    "failing_script_before_mismatch",
];

#[test]
fn every_fixture_is_the_recordings_bytes_848() {
    let doc: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(doc["cells"].as_array().unwrap().len(), CELLS.len());
    for cell in CELLS {
        let r = reference(cell);
        let tx = build(cell);
        if let Some(hex) = r["built"]["hex"].as_str() {
            assert_eq!(tx.to_hex(), hex, "{cell}");
        }
        if let Some(ef) = r["built"]["ef"].as_str() {
            assert_eq!(tx.to_hex_ef().unwrap(), ef, "{cell}");
        }
        for (input, recorded) in tx
            .inputs()
            .iter()
            .zip(r["built"]["inputs"].as_array().unwrap())
        {
            let source = input.source_transaction.as_ref().unwrap();
            assert_eq!(
                source.id(),
                recorded["source"]["id"].as_str().unwrap(),
                "{cell}"
            );
            assert_eq!(
                source.inputs().len() as u64,
                recorded["source"]["inputs"].as_u64().unwrap(),
                "{cell}"
            );
            assert_eq!(
                source.merkle_path.is_some(),
                recorded["source"]["path"].as_bool().unwrap(),
                "{cell}"
            );
        }
    }
}

#[tokio::test]
async fn every_recorded_sign_answer_is_this_crates_848() {
    for cell in CELLS {
        let r = reference(cell);
        let (answer, calls, after, handed) = sign(build(cell)).await;
        match r["sign"]["error"].as_str() {
            None => {
                assert_eq!(answer, Ok(()), "{cell}");
                assert_eq!(
                    calls as u64,
                    r["sign"]["template_calls"].as_u64().unwrap(),
                    "{cell}"
                );
            }
            Some(recorded) => {
                assert_eq!(r["sign"]["template_calls"], 0, "{cell}");
                assert_eq!(calls, 0, "{cell}: no template runs on a refusal");
                assert!(
                    after.inputs().iter().all(|i| i.unlocking_script.is_none()),
                    "{cell}: no input signed"
                );
                assert_eq!(after.id(), handed, "{cell}: no field moved");
                if SIGN_STATED.contains(&cell) {
                    assert_ne!(
                        words(&answer),
                        recorded,
                        "{cell}: stated, no longer different"
                    );
                    assert!(words(&answer).ends_with(SIGN_WORDS), "{cell}");
                } else {
                    assert_eq!(words(&answer), recorded, "{cell}");
                }
            }
        }
    }
}

#[tokio::test]
async fn every_recorded_verify_answer_is_this_crates_848() {
    for cell in CELLS {
        let r = reference(cell);
        let answer = verify(&build(cell)).await;
        match r["verify_tracker"]["error"].as_str() {
            None => assert_eq!(answer, Ok(true), "{cell}"),
            Some(recorded) if VERIFY_STATED.contains(&cell) => {
                assert_ne!(
                    words(&answer),
                    recorded,
                    "{cell}: stated, no longer different"
                );
                assert!(words(&answer).ends_with(VERIFY_WORDS), "{cell}");
            }
            Some(recorded) if recorded.ends_with(VERIFY_WORDS) => {
                assert_eq!(words(&answer), recorded, "{cell}");
            }
            // The one other recorded refusal: the missing source output, in
            // this crate's words, ahead of the mismatch on both sides.
            Some(recorded) => {
                assert!(recorded.ends_with("references a source output that does not exist."));
                assert_eq!(
                    words(&answer),
                    "Input 0 source output index out of bounds",
                    "{cell}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_complete_source_under_another_txid_is_refused_at_sign_848() {
    for cell in [
        "mismatch_complete",
        "mismatch_proven",
        "mismatch_anchored_no_inputs",
    ] {
        let (answer, calls, _, _) = sign(build(cell)).await;
        assert_eq!(
            answer,
            Err(Error::TransactionError(format!("Input 0 {SIGN_WORDS}"))),
            "{cell}"
        );
        assert_eq!(calls, 0, "{cell}");
    }
    // Every input is read, a template or not: the mismatch at input 1, which
    // carries no template, refuses the whole call.
    let mut tx = build("failing_script_before_mismatch");
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    tx.inputs_mut()[0].set_unlocking_script_template(ScriptTemplateUnlock::new(
        move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            UnlockingScript::from_binary(&[])
        },
        || 0,
    ));
    assert_eq!(
        tx.sign().await,
        Err(Error::TransactionError(format!("Input 1 {SIGN_WORDS}")))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_complete_source_under_another_txid_is_refused_at_verify_848() {
    for cell in [
        "mismatch_complete",
        "mismatch_proven",
        "mismatch_anchored_no_inputs",
        "mismatch_descriptor",
    ] {
        let tx = build(cell);
        assert_eq!(
            verify(&tx).await,
            Err(Error::TransactionError(format!(
                "Verification failed because input 0 of transaction {} {VERIFY_WORDS}",
                tx.id()
            ))),
            "{cell}"
        );
    }
}

/// The mismatch in an unproven ancestor is refused too, naming the ancestor:
/// the check is the walk's, not the root's.
#[tokio::test]
async fn a_mismatch_in_an_unproven_ancestor_is_refused_at_verify_848() {
    let ancestor = build("mismatch_proven");
    let ancestor_id = ancestor.id();
    let tx = child(vec![link(ancestor, None, 0, Some(&[]))]);
    assert_eq!(
        verify(&tx).await,
        Err(Error::TransactionError(format!(
            "Verification failed because input 0 of transaction {ancestor_id} {VERIFY_WORDS}"
        )))
    );
}

#[tokio::test]
async fn a_named_txid_of_another_reachable_transaction_is_refused_at_verify_848() {
    let tx = build("named_other_inputs_source");
    // The bytes spend B:0 and B:1, and B is reachable through input 1: judged
    // by the named txid alone, both scripts run against B's outputs and pass.
    assert_eq!(
        tx.inputs()[0].source_txid,
        tx.inputs()[1].source_txid,
        "both inputs name B"
    );
    assert_eq!(
        verify(&tx).await,
        Err(Error::TransactionError(format!(
            "Verification failed because input 0 of transaction {} {VERIFY_WORDS}",
            tx.id()
        )))
    );
    let (answer, calls, _, _) = sign(tx).await;
    assert_eq!(
        answer,
        Err(Error::TransactionError(format!("Input 0 {SIGN_WORDS}")))
    );
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn a_txid_text_in_upper_case_over_its_own_source_is_signed_and_verified_848() {
    for cell in ["upper_matching", "upper_matching_proven"] {
        let tx = build(cell);
        // Held as a `Txid` since #845 (as given, in upper case, until then):
        // the same id as its source's.
        let named = tx.inputs()[0].source_txid.unwrap();
        let source = tx.inputs()[0].source_transaction.as_ref().unwrap();
        assert_eq!(named, source.txid(), "{cell}: the source's id");
        assert_eq!(verify(&tx).await, Ok(true), "{cell}");
        let (answer, calls, _, _) = sign(tx).await;
        assert_eq!((answer, calls), (Ok(()), 1), "{cell}");
    }
}

/// The three descriptor doors build a source with no input and no path, whose
/// id is never the txid named: each keeps signing (the reference's exemption,
/// `Transaction.ts:970-972`), and each is refused by `verify` in the
/// reference's words (`has no source transaction` until #848).
#[tokio::test]
async fn a_descriptor_source_is_still_signed_848() {
    let lock = LockingScript::from_binary(&[0x51]).unwrap();
    let template = || ScriptTemplateUnlock::new(|_| UnlockingScript::from_binary(&[]), || 0);

    let mut from_ef = build("from_ef");
    let mut add_input_from = Transaction::new();
    add_input_from
        .add_input_from(&other(), 1, &lock, 900, template())
        .unwrap();
    add_input_from.add_output(one(5)).unwrap();
    let mut from_utxos = Transaction::new();
    from_utxos
        .add_inputs_from_utxos(&[Utxo {
            txid: other(),
            vout: 2,
            satoshis: 900,
            locking_script: lock.clone(),
        }])
        .unwrap();
    from_utxos.add_output(one(5)).unwrap();
    for input in from_ef
        .inputs_mut()
        .iter_mut()
        .chain(from_utxos.inputs_mut())
    {
        input.unlocking_script = None;
        input.set_unlocking_script_template(template());
    }

    for (door, tx) in [
        ("from_ef", &mut from_ef),
        ("add_input_from", &mut add_input_from),
        ("add_inputs_from_utxos", &mut from_utxos),
    ] {
        let source = tx.inputs()[0].source_transaction.as_ref().unwrap();
        assert!(
            source.inputs().is_empty() && source.merkle_path.is_none(),
            "{door}"
        );
        assert_ne!(Some(source.txid()), tx.inputs()[0].source_txid, "{door}");
        assert_eq!(tx.sign().await, Ok(()), "{door}");
        assert!(tx.inputs()[0].unlocking_script.is_some(), "{door}");
        assert_eq!(
            verify(tx).await,
            Err(Error::TransactionError(format!(
                "Verification failed because input 0 of transaction {} {VERIFY_WORDS}",
                tx.id()
            ))),
            "{door}"
        );
    }
    // The reference's answers for its `fromEF` transaction, recorded.
    let r = reference("from_ef");
    assert_eq!(r["sign"]["ok"], true);
    assert!(r["verify_tracker"]["error"]
        .as_str()
        .unwrap()
        .ends_with(VERIFY_WORDS));
}

/// A text that is not 64 hex digits is outside #848, and since #845 it is
/// no `Txid`: refused where it enters, never held beside a source. The
/// input then names no txid, the serializer writes the linked source's
/// hash, nothing disagrees and `sign` runs.
#[tokio::test]
async fn a_txid_text_that_does_not_parse_is_not_a_mismatch_848() {
    assert!("zz".parse::<bsv_rs::transaction::Txid>().is_err());
    let mut input = link(root("11", 1000, 1), None, 0, Some(&[]));
    input.source_txid = None;
    let tx = child(vec![input]);
    let (answer, calls, _, _) = sign(tx).await;
    assert_eq!((answer, calls), (Ok(()), 1));
}

/// The survey's doors on the complete-source mismatch: `get_fee`, `fee` and
/// `to_ef` read the linked output beside the named txid and make no check, as
/// the reference's make none (recorded).
#[tokio::test]
async fn the_surveyed_doors_answer_as_the_reference_on_a_mismatch_848() {
    let doc: Value = serde_json::from_str(VECTOR).unwrap();
    let survey = &doc["survey"];
    let tx = build("mismatch_complete");
    assert_eq!(
        tx.get_fee().unwrap(),
        survey["getFee"]["ok"].as_u64().unwrap()
    );
    assert_eq!(tx.total_input_satoshis().unwrap(), 900);
    assert_eq!(
        tx.to_hex_ef().unwrap(),
        survey["toEF"]["ok"].as_str().unwrap()
    );
    let mut tx = tx;
    tx.fee(Some(1), bsv_rs::transaction::ChangeDistribution::Equal)
        .await
        .unwrap();
    assert_eq!(tx.get_fee().unwrap(), survey["fee"]["ok"].as_u64().unwrap());
}
