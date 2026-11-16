//! The link bound (bsv-rs #749).
//!
//! Linking a BEEF hands every repeat input that spends an already-linked parent
//! a clone of that parent (its outputs are what the input spends), so a shared
//! parent of N outputs spent by M separate inputs re-materializes M×N output
//! slots — a cost that grows with the PRODUCT, not the sum. A small answer well
//! within a resolver's byte bound can therefore force multi-gigabyte heap, an
//! out-of-memory kill or an uncatchable wasm32 abort, reached through the
//! overlay lookup resolver and every other door that parses a stranger's BEEF.
//!
//! So `Transaction::from_beef` / `find_atomic_transaction` cap the
//! re-materialized output count at a multiple of the BEEF's own output count
//! (closed by default) and refuse an answer that would blow past it. An honest
//! BEEF re-materializes far fewer slots than its own outputs, so the default
//! refuses none of them; a caller that trusts the source opts out with
//! `BeefLinkLimits::unbounded`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed expect is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLinkLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
};

const SATS: u64 = 1_000;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A transaction spending each `(txid, vout)` with an empty unlock and paying
/// `outputs` OP_TRUE outputs of `SATS` each.
fn spend(spends: &[(String, u32)], outputs: usize) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in spends {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
    }
    for _ in 0..outputs {
        tx.outputs.push(TransactionOutput::new(SATS, op_true()));
    }
    tx
}

/// A BEEF whose one proven parent carries `outputs` outputs, the first `spends`
/// of them each spent by a separate input of one unproven child; the subject is
/// the child. Built by this crate's own writer, so it cannot drift from the
/// wire format. This is the shared-parent shape the bound guards, sized only to
/// what a test needs to cross or clear the bound — never a weaponized answer.
fn shared_parent_beef(outputs: usize, spends: usize) -> (Vec<u8>, String) {
    assert!(spends <= outputs);
    let parent = spend(&[("aa".repeat(32), 0)], outputs);
    let parent_txid = parent.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump));
    let outpoints: Vec<(String, u32)> = (0..spends)
        .map(|i| (parent_txid.clone(), i as u32))
        .collect();
    let child = spend(&outpoints, 1);
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
fn a_shared_parent_spent_by_many_inputs_is_refused_by_the_default_link_bound() {
    // 160 outputs under a child of 160 inputs re-materializes 159×160 = 25,440
    // output slots, past the default budget (64 × 161 + 4,096 = 14,400). The
    // default `from_beef` refuses it rather than let a small answer force the
    // product's worth of heap.
    let (bytes, _child) = shared_parent_beef(160, 160);
    assert!(
        Transaction::from_beef(&bytes, None).is_err(),
        "the default bound refuses a shared parent amplified past its budget"
    );
}

#[test]
fn an_honest_shared_parent_within_the_bound_still_links_by_default() {
    // The ordinary wallet shape — a covenant output and that transaction's own
    // change, two inputs sourcing one parent — is far under the bound and links
    // by default, as it always has.
    let (bytes, child) = shared_parent_beef(2, 2);
    let tx =
        Transaction::from_beef(&bytes, None).expect("an honest shared parent links by default");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 2);
}

#[test]
fn the_refused_shared_parent_links_when_the_bound_is_lifted() {
    // The same answer links in full for a caller that trusts its source and
    // opts out: the bound is a default, not a wall.
    let (bytes, child) = shared_parent_beef(160, 160);
    let tx = Transaction::from_beef_with_limits(&bytes, None, &BeefLinkLimits::unbounded())
        .expect("an unbounded link accepts the shared parent");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 160, "every input linked to the parent");
}

#[test]
fn find_atomic_transaction_limited_tells_a_refusal_from_an_absent_txid() {
    let (bytes, child) = shared_parent_beef(160, 160);
    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    // Over budget is an error, not a silent miss.
    assert!(beef
        .find_atomic_transaction_limited(&child, &BeefLinkLimits::default())
        .is_err());
    // An absent txid is Ok(None), told apart from the refusal above.
    assert!(beef
        .find_atomic_transaction_limited("ab".repeat(32).as_str(), &BeefLinkLimits::default())
        .expect("an absent txid is Ok(None), not an error")
        .is_none());
    // Unbounded links it.
    assert!(beef
        .find_atomic_transaction_limited(&child, &BeefLinkLimits::unbounded())
        .expect("unbounded accepts it")
        .is_some());
}
