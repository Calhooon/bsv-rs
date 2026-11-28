//! `Transaction::sign` and `Transaction::verify` refuse an input whose
//! `source_txid` names a transaction other than the one it links as its
//! `source_transaction`, as the reference does (#848; `ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Transaction.ts`: sign `:964-984`, over a
//! complete or anchored source, a no-input descriptor exempt; verify
//! `:1423-1432`, whatever the source holds).
//!
//! Until this fix `sign` committed a signature to the named outpoint with the
//! linked source's amount and script, and `verify` resolved each input's
//! source BY THE NAMED TXID alone: a named txid that was another reachable
//! transaction's id was judged against that transaction's output and could
//! answer `Ok(true)`.
//!
//! This is the CORE comparison only. The 0.9 line's #848 commit folds in other
//! verdicts that do NOT travel to the stable line, each shown absent below:
//! the upper-case named-txid lowering in verify's lookup, the fold's
//! output/source amount bounds, and the fold's "an input that links no source
//! is refused" (which would break this line's linear-BEEF stub inputs). The
//! stock-template descriptor refusal is stated-only even on the 0.9 line.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bsv_rs::script::{LockingScript, ScriptTemplateUnlock, UnlockingScript};
use bsv_rs::transaction::{
    AlwaysValidChainTracker, MerklePath, MerklePathLeaf, Transaction, TransactionInput,
    TransactionOutput,
};
use bsv_rs::Error;

const SIGN_WORDS: &str = "sourceTXID does not reference its supplied source transaction.";
const VERIFY_WORDS: &str = "does not reference its supplied source transaction.";
const MISSING_WORDS: &str = "has no source transaction";

/// A txid of all `ab`, never a built fixture's id.
fn other() -> String {
    "ab".repeat(32)
}

fn empty_unlock() -> Option<UnlockingScript> {
    Some(UnlockingScript::from_binary(&[]).unwrap())
}

/// An output of `sats` locked by `OP_TRUE` (any empty unlocking script spends
/// it).
fn op_true(sats: u64) -> TransactionOutput {
    TransactionOutput::new(sats, LockingScript::from_binary(&[0x51]).unwrap())
}

/// A single-leaf path proving `txid` at offset 0, height 100.
fn bump(txid: &str) -> MerklePath {
    MerklePath::new(
        100,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// A proven source: one input naming `fill` repeated, `outs` `OP_TRUE`
/// outputs of `sats`, proven by a path of its own.
fn root(fill: &str, sats: u64, outs: usize) -> Transaction {
    let mut t = Transaction::new();
    let mut i = TransactionInput::new(fill.repeat(32), 0);
    i.unlocking_script = empty_unlock();
    t.add_input(i).unwrap();
    for _ in 0..outs {
        t.add_output(op_true(sats)).unwrap();
    }
    t.merkle_path = Some(bump(&t.id()));
    t
}

/// A complete unproven source spending `src`'s output 0.
fn middle(src: Transaction, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    t.add_input(link(src, None, 0)).unwrap();
    t.add_output(op_true(sats)).unwrap();
    t
}

/// A descriptor source: no inputs, one `OP_TRUE` output (the shape `from_ef`,
/// `add_input_from` and `add_inputs_from_utxos` build).
fn descriptor(sats: u64) -> Transaction {
    Transaction::with_params(1, vec![], vec![op_true(sats)], 0)
}

/// An input linking `src` and naming `named` (its id when `None`), with an
/// empty unlocking script.
fn link(src: Transaction, named: Option<String>, vout: u32) -> TransactionInput {
    let named = named.unwrap_or_else(|| src.id());
    let mut i = TransactionInput::with_source_transaction(src, vout);
    i.source_txid = Some(named);
    i.unlocking_script = empty_unlock();
    i
}

/// An unproven child spending the given inputs to one `OP_TRUE` output.
fn child(inputs: Vec<TransactionInput>) -> Transaction {
    let mut t = Transaction::new();
    for i in inputs {
        t.add_input(i).unwrap();
    }
    t.add_output(op_true(5)).unwrap();
    t
}

fn complete() -> Transaction {
    middle(root("11", 1000, 1), 900)
}

/// Replace every input's unlocking script with a counted template answering
/// the empty script, then `sign`. Returns the answer and the template calls.
async fn sign(mut tx: Transaction) -> (Result<(), Error>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    for input in &mut tx.inputs {
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
    let answer = tx.sign().await;
    (answer, calls.load(Ordering::SeqCst))
}

async fn verify(tx: &Transaction) -> Result<bool, Error> {
    tx.verify(&AlwaysValidChainTracker::new(1000), None).await
}

fn words(answer: &Result<impl std::fmt::Debug, Error>) -> String {
    match answer {
        Err(Error::TransactionError(words)) => words.clone(),
        other => panic!("expected a TransactionError, got {other:?}"),
    }
}

// --- The matter: a named txid of another reachable transaction ---

/// The witness. input0 LINKS A (a proven root) but NAMES B (another proven,
/// reachable root); input1 links B. Before the fix `verify` resolved input0 by
/// the NAMED B and judged it against B's output: `Ok(true)`. The fix refuses.
#[tokio::test]
async fn a_named_txid_of_another_reachable_transaction_is_refused_at_verify() {
    let b = root("22", 1000, 2);
    let tx = child(vec![
        link(root("11", 1000, 1), Some(b.id()), 0),
        link(b, None, 1),
    ]);
    let answer = verify(&tx).await;
    assert!(
        words(&answer).contains(VERIFY_WORDS),
        "a named txid of another reachable transaction must be refused, got {answer:?}"
    );
}

/// A complete source linked under another txid is refused at `sign` before any
/// template runs.
#[tokio::test]
async fn a_complete_source_linked_under_another_txid_is_refused_at_sign() {
    let tx = child(vec![link(complete(), Some(other()), 0)]);
    let (answer, calls) = sign(tx).await;
    assert!(
        words(&answer).contains(SIGN_WORDS),
        "a complete source under another txid must be refused at sign, got {answer:?}"
    );
    assert_eq!(calls, 0, "no template runs when the mismatch is refused");
}

/// A mismatch over a proven source is refused at `verify` whatever the source
/// holds (no descriptor exemption at verify).
#[tokio::test]
async fn a_mismatch_over_a_proven_source_is_refused_at_verify() {
    // input0 names B (reachable) but links a proven root; input1 links B so B
    // is in the map and the named lookup would otherwise succeed.
    let b = root("22", 1000, 2);
    let tx = child(vec![
        link(root("33", 1000, 1), Some(b.id()), 0),
        link(b, None, 1),
    ]);
    let answer = verify(&tx).await;
    assert!(
        words(&answer).contains(VERIFY_WORDS),
        "a mismatch over a proven source must be refused at verify, got {answer:?}"
    );
}

/// An EF / descriptor-sourced transaction (its input links a fabricated
/// descriptor whose id is not the named outpoint) is refused at `verify` in
/// the mismatch's words. On 0.8.13 the named-txid map lookup already failed
/// (the descriptor is keyed by its own fabricated id), so the VERDICT is
/// unchanged (`Err`); only the words move from "has no source transaction" to
/// the mismatch sentence. The reference's scripts-only mode (absent here)
/// would skip the comparison.
#[tokio::test]
async fn a_descriptor_sourced_transaction_from_ef_is_refused_at_verify() {
    let matching = child(vec![link(complete(), None, 0)]);
    let ef = Transaction::from_ef(&matching.to_ef().unwrap()).unwrap();
    let answer = verify(&ef).await;
    assert!(
        words(&answer).contains(VERIFY_WORDS),
        "an EF-sourced transaction is refused at verify in the mismatch's words, got {answer:?}"
    );
}

// --- Guards: the fix does not over-reach ---

/// A matching linked-and-named source signs and verifies, unchanged.
#[tokio::test]
async fn a_matching_linked_and_named_source_signs_and_verifies() {
    let signed = sign(child(vec![link(complete(), None, 0)])).await;
    assert!(signed.0.is_ok(), "a matching source signs: {:?}", signed.0);
    assert_eq!(signed.1, 1, "its one template runs");

    let verified = verify(&child(vec![link(complete(), None, 0)])).await;
    assert_eq!(
        verified.ok(),
        Some(true),
        "a matching source verifies to Ok(true)"
    );
}

/// A descriptor source (no input, no path) linked under another txid is still
/// signed: the sign-side refusal exempts a descriptor, as the reference does.
#[tokio::test]
async fn a_descriptor_source_under_another_txid_is_still_signed() {
    let tx = child(vec![link(descriptor(900), Some(other()), 0)]);
    let (answer, calls) = sign(tx).await;
    assert!(
        answer.is_ok(),
        "a descriptor source under another txid is exempt at sign: {answer:?}"
    );
    assert_eq!(calls, 1, "its one template runs");
}

// --- The 0.9 line's fold does NOT travel (each shown absent) ---

/// The 0.9 line's lowering of an upper-case named txid in verify's lookup is
/// NOT ported: an upper-case named txid over its OWN source stays refused as
/// on 0.8.13 ("has no source transaction"), not accepted.
#[tokio::test]
async fn an_upper_case_named_txid_over_its_own_source_stays_as_the_stable_line() {
    let s = complete();
    let upper = s.id().to_uppercase();
    let answer = verify(&child(vec![link(s, Some(upper), 0)])).await;
    assert!(
        words(&answer).contains(MISSING_WORDS),
        "an upper-case named txid stays refused as on the stable line, got {answer:?}"
    );
}

/// The 0.9 line's fold refusal of an input that links no source is NOT ported:
/// a linear-BEEF stub (names a reachable source, links nothing) still verifies,
/// as the stable line requires.
#[tokio::test]
async fn a_stub_input_naming_a_reachable_source_still_verifies() {
    let b = root("22", 1000, 2);
    // input0 is a stub: it names B and links nothing; input1 links B in full.
    let mut stub = TransactionInput::new(b.id(), 0);
    stub.unlocking_script = empty_unlock();
    let tx = child(vec![stub, link(b, None, 1)]);
    let answer = verify(&tx).await;
    assert_eq!(
        answer.as_ref().ok(),
        Some(&true),
        "a stub input naming a reachable source still verifies, got {answer:?}"
    );
}

/// The 0.9 line's fold bound on output/source amounts (past 21e14) is NOT
/// ported: a transaction whose amounts exceed the money bound is not refused
/// for the amount on the stable line.
#[tokio::test]
async fn an_amount_past_the_money_bound_is_not_refused_for_the_amount() {
    const OVER: u64 = 2_100_000_000_000_001; // 21e14 + 1
    let src = root("44", OVER, 1);
    let mut t = Transaction::new();
    t.add_input(link(src, None, 0)).unwrap();
    t.add_output(op_true(OVER)).unwrap();
    let answer = verify(&t).await;
    assert_eq!(
        answer.as_ref().ok(),
        Some(&true),
        "an amount past the money bound is not refused for the amount, got {answer:?}"
    );
}

// --- The 64-hex-digit gate (`names_32_bytes`) is pinned on both halves ---

/// The gate in `source_named_otherwise` is the difference between "the
/// serializer writes the NAMED txid" (64 hex digits, so a disagreement with the
/// linked source is possible) and "the serializer writes the SOURCE's hash" (a
/// text that is not 64 hex digits, so nothing can disagree). An input that
/// links a complete source under a `source_txid` that is NOT 64 hex digits — a
/// 63-digit text (the length half) or a 64-character text with a non-hex
/// character (the hex-digit half) — is resolved by the named-txid map, which
/// misses, so `verify` refuses it in the stable line's words (`has no source
/// transaction`), NOT the mismatch words: the comparison never fires. Dropping
/// either half of the gate would refuse these in the mismatch words instead.
#[tokio::test]
async fn a_named_txid_that_is_not_64_hex_digits_is_resolved_by_the_map_not_the_mismatch_check() {
    // 63 hex digits (one short): the length half of the gate.
    let short = "a".repeat(63);
    let answer = verify(&child(vec![link(complete(), Some(short), 0)])).await;
    let w = words(&answer);
    assert!(
        w.contains(MISSING_WORDS) && !w.contains(VERIFY_WORDS),
        "a 63-hex named txid is resolved by the map, not the mismatch check, got {answer:?}"
    );

    // 64 characters, not all hex digits: the hex-digit half of the gate.
    let non_hex = format!("z{}", "a".repeat(63));
    assert_eq!(non_hex.len(), 64);
    let answer = verify(&child(vec![link(complete(), Some(non_hex), 0)])).await;
    let w = words(&answer);
    assert!(
        w.contains(MISSING_WORDS) && !w.contains(VERIFY_WORDS),
        "a 64-char non-hex named txid is resolved by the map, not the mismatch check, got {answer:?}"
    );
}

/// The sign side of the upper-case reading: an input naming its OWN source's id
/// in upper case is NOT refused at `sign` (the comparison is case-insensitive,
/// so the helper reads a match), so it signs, where `verify` refuses it (`has
/// no source transaction`, the by-txid map being lower-case). The two doors
/// answer an upper-case own-id differently, as on 0.8.13 (the 0.9 line's
/// lowering of verify's lookup is not ported; the root `CLAUDE.md` row).
#[tokio::test]
async fn an_upper_case_named_txid_over_its_own_source_is_signed_as_the_stable_line() {
    let s = complete();
    let upper = s.id().to_uppercase();
    let (answer, calls) = sign(child(vec![link(s, Some(upper), 0)])).await;
    assert!(
        answer.is_ok(),
        "an upper-case named txid over its own source is signed (case-insensitive match), got {answer:?}"
    );
    assert_eq!(calls, 1, "its one template runs");
}
