//! The link bound (bsv-rs #749).
//!
//! Linking a BEEF hands every repeat input that spends an already-linked parent
//! a clone of that parent (its outputs are what the input spends), so a shared
//! parent of N outputs spent by M separate inputs re-materializes M×N output
//! bytes — a cost that grows with the PRODUCT, not the sum. A small answer well
//! within a resolver's byte bound can therefore force multi-gigabyte heap, an
//! out-of-memory kill or an uncatchable wasm32 abort, reached through the
//! overlay lookup resolver and every other door that parses a stranger's BEEF.
//!
//! So `Transaction::from_beef` / `find_atomic_transaction` cap, in ABSOLUTE
//! BYTES, how far linking may re-materialize a shared parent beyond the BEEF's
//! own bytes (closed by default at 32 MiB) and refuse an answer that would blow
//! past it — BEFORE the clone that would cross the budget — with a resource
//! error of its own class (`Error::BeefResourceLimit`), never a silent "not
//! found". A byte budget (not a count of output slots) charges a parent of a
//! few large outputs its true weight, so a sub-megabyte BEEF of few large
//! outputs cannot slip a Worker-OOM re-materialization past the bound. An
//! honest BEEF re-materializes a few hundred KiB at most, so the default
//! refuses none of them; a caller that trusts the source opts out with
//! `BeefLinkLimits::unbounded`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed expect is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLinkLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

const SATS: u64 = 1_000;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A locking script of `bytes` filler opcodes (`OP_0`), so an output can be
/// given a chosen wire weight — the byte budget charges its true size.
fn filler_script(bytes: usize) -> LockingScript {
    LockingScript::from_binary(&vec![0u8; bytes]).expect("filler locking script")
}

/// A transaction spending each `(txid, vout)` with an empty unlock and paying
/// `outputs` outputs of `SATS` each carrying `script`.
fn spend(spends: &[(String, u32)], outputs: usize, script: &LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in spends {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
    }
    for _ in 0..outputs {
        tx.outputs
            .push(TransactionOutput::new(SATS, script.clone()));
    }
    tx
}

/// A BEEF whose one proven parent carries `outputs` outputs each of
/// `output_script` bytes, the first `spends` of them each spent by a separate
/// input of one unproven child; the subject is the child. Built by this crate's
/// own writer, so it cannot drift from the wire format. This is the
/// shared-parent shape the bound guards, sized only to what a test needs to
/// cross or clear the bound — never a weaponized answer.
fn shared_parent_beef(
    outputs: usize,
    spends: usize,
    output_script: &LockingScript,
) -> (Vec<u8>, String) {
    assert!(spends <= outputs);
    let parent = spend(&[("aa".repeat(32), 0)], outputs, output_script);
    let parent_txid = parent.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump));
    let outpoints: Vec<(String, u32)> = (0..spends)
        .map(|i| (parent_txid.clone(), i as u32))
        .collect();
    let child = spend(&outpoints, 1, &op_true());
    let child_txid = child.id();
    beef.merge_raw_tx(child.to_binary(), None);
    (beef.to_binary(), child_txid)
}

/// How many of the subject's inputs linked to a source transaction.
fn linked_inputs(tx: &Transaction) -> usize {
    tx.inputs
        .iter()
        .filter(|i| i.source_transaction.is_some())
        .count()
}

#[test]
fn a_shared_parent_of_large_outputs_is_refused_by_the_default_byte_bound() {
    // 160 outputs of ~2 KiB each spent by 160 inputs re-materializes ~160×2 KiB
    // × 159 ≈ 50 MB of stub clones, past the default 32 MiB byte budget. The
    // default `from_beef` refuses it rather than let a ~330 KiB answer force
    // tens of megabytes of heap. (The slot bound this folds over admitted a
    // few-large-output shape — 1 slot per output regardless of its bytes.)
    let (bytes, _child) = shared_parent_beef(160, 160, &filler_script(2 * 1024));
    let err = Transaction::from_beef(&bytes, None)
        .expect_err("the default bound refuses a shared parent amplified past its byte budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "the refusal is a resource limit of its own class, not {err:?}"
    );
}

#[test]
fn the_refusal_is_a_resource_limit_not_an_absent_or_invalid_beef() {
    // A resource decline must read as neither "invalid BEEF" (`BeefError`) nor
    // "absent txid" (`Ok(None)`), on every door that can carry an error. An
    // explicit small budget keeps this fast.
    let small = BeefLinkLimits::default().with_max_link_bytes(Some(64 * 1024));
    let (bytes, child) = shared_parent_beef(20, 20, &filler_script(16 * 1024));

    let err =
        Transaction::from_beef_with_limits(&bytes, None, &small).expect_err("over the byte budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "named resource class, not {err:?}"
    );

    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    let trip = beef
        .find_atomic_transaction_limited(&child, &small)
        .unwrap_err();
    assert!(
        matches!(trip, Error::BeefResourceLimit(_)),
        "named resource class, not {trip:?}"
    );
    // An absent txid is a told-apart Ok(None), never the resource error.
    assert!(beef
        .find_atomic_transaction_limited("ab".repeat(32).as_str(), &small)
        .expect("an absent txid is Ok(None), not an error")
        .is_none());
}

#[test]
fn an_honest_full_sweep_consolidation_links_under_the_default_byte_bound() {
    // A child sweeping all 200 small outputs of one parent — an ordinary BSV
    // consolidation — links by default. The folded-over slot bound REFUSED a
    // full sweep at ≥105 outputs (64×N+4096 < N×N); the byte budget, charging
    // ~10 B per OP_TRUE output, admits this ~400 KiB of re-materialization with
    // room to spare, so a legitimate high-fan sweep is no longer refused.
    let (bytes, child) = shared_parent_beef(200, 200, &op_true());
    let tx = Transaction::from_beef(&bytes, None)
        .expect("an honest 200-output consolidation links under the default byte bound");
    assert_eq!(tx.id(), child);
    assert_eq!(
        linked_inputs(&tx),
        200,
        "every swept output linked to the parent"
    );
}

#[test]
fn a_few_large_outputs_the_slot_count_would_admit_are_refused_by_the_byte_budget() {
    // The strength read's byte-blind shape: a parent of a few large outputs
    // spent by a modest number of inputs. A SLOT count admits it (few slots,
    // under any floor); the BYTE budget charges each repeat its true weight and
    // refuses it. An explicit 256 KiB budget stands in for the proportionality
    // the default has at 32 MiB, kept small so the test is fast.
    let budget = BeefLinkLimits::default().with_max_link_bytes(Some(256 * 1024));
    // 8 outputs of 32 KiB spent by 8 inputs: 7 repeats × ~256 KiB ≈ 1.8 MiB of
    // re-materialization — far past 256 KiB — yet only 7 output slots.
    let (bytes, _child) = shared_parent_beef(8, 8, &filler_script(32 * 1024));
    let err = Transaction::from_beef_with_limits(&bytes, None, &budget)
        .expect_err("a few large outputs re-materialize past the byte budget");
    assert!(matches!(err, Error::BeefResourceLimit(_)), "not {err:?}");
}

#[test]
fn the_refused_shared_parent_links_when_the_bound_is_lifted() {
    // The same answer links in full for a caller that trusts its source and
    // opts out: the bound is a default, not a wall.
    let (bytes, child) = shared_parent_beef(20, 20, &filler_script(16 * 1024));
    let tx = Transaction::from_beef_with_limits(&bytes, None, &BeefLinkLimits::unbounded())
        .expect("an unbounded link accepts the shared parent");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 20, "every input linked to the parent");
}

#[test]
fn an_honest_two_input_covenant_plus_change_links_by_default() {
    // The ordinary wallet shape — a covenant output and that transaction's own
    // change, two inputs sourcing one parent — is far under the bound and links
    // by default, as it always has.
    let (bytes, child) = shared_parent_beef(2, 2, &op_true());
    let tx =
        Transaction::from_beef(&bytes, None).expect("an honest shared parent links by default");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 2);
}

#[test]
fn the_resolver_subject_door_links_nothing_and_is_never_refused() {
    // The overlay lookup resolver reads only a subject's txid / an output, never
    // the ancestry, so it takes `from_beef_subject` — which parses WITHOUT
    // linking. A shared-parent answer the default `from_beef` refuses is read
    // by the subject door at zero cost: the resolver links nothing on an
    // untrusted answer (the #749 door closed, not merely bounded).
    let (bytes, child) = shared_parent_beef(160, 160, &filler_script(2 * 1024));
    assert!(
        matches!(
            Transaction::from_beef(&bytes, None),
            Err(Error::BeefResourceLimit(_))
        ),
        "the linking door refuses the shared parent"
    );
    let subject = Transaction::from_beef_subject(&bytes, None)
        .expect("the subject door parses the same answer without linking");
    assert_eq!(subject.id(), child);
    assert_eq!(linked_inputs(&subject), 0, "the subject door links nothing");
}
