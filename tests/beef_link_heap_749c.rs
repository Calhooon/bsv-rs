//! The link bound must weigh the HEAP a repeat clone holds, not its wire bytes
//! alone (bsv-rs #749 fold-c — the declined-late / accepted sibling of the
//! shared-proof fold).
//!
//! Linking hands every repeat input a clone of the parent stub it spends and
//! meters the stub's weight against [`BeefLinkLimits`], refusing BEFORE the
//! clone. The #749 meter charged `stub.to_binary().len()` — a flat wire-byte
//! count. But a parsed stub's clone holds far more heap than its wire bytes: a
//! one-byte-locked output is ~10 wire bytes yet ~150 heap bytes once cloned
//! (its struct in the output `Vec`, its script's own container). So a child of
//! a parent of N one-byte outputs spent M ways re-materialized ~M*N*150 heap
//! while the wire meter saw only ~M*N*10 — a 16 MiB budget admitting hundreds
//! of MB of heap, past the 128 MB Worker isolate (the same out-of-memory kill /
//! wasm32 abort the #749 bound was shipped to refuse, reached through the
//! overlay lookup resolver and every door that parses a stranger's BEEF).
//!
//! These fixtures are built by this crate's own writer and reader, so they
//! cannot drift from the wire format, and are sized only to what each test needs
//! to cross or clear the bound, never a weaponized answer.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::Error;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A BEEF of one unproven parent of `n` one-byte outputs and an unproven child
/// spending `m` of them (one input per output, `m <= n`). No proof, so the
/// stub meter weighs only the parent's bytes each repeat input re-materializes.
/// Built by this crate's own writer; returns the BEEF bytes and the child txid.
fn fanin_beef(n: u32, m: u32) -> (Vec<u8>, String) {
    assert!(m <= n);
    let mut parent = Transaction::new();
    parent
        .add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    for _ in 0..n {
        parent
            .add_output(TransactionOutput::new(1, op_true()))
            .unwrap();
    }
    let pid = parent.id();

    let mut child = Transaction::new();
    for k in 0..m {
        child
            .add_input(TransactionInput::new(pid.clone(), k))
            .unwrap();
    }
    child
        .add_output(TransactionOutput::new(1, op_true()))
        .unwrap();
    let cid = child.id();

    let mut beef = Beef::new();
    beef.merge_raw_tx(parent.to_binary(), None)
        .expect("the parent is one transaction");
    beef.merge_raw_tx(child.to_binary(), None)
        .expect("the child is one transaction");
    (beef.to_binary().expect("the BEEF is writable"), cid)
}

#[test]
fn a_many_output_sweep_whose_heap_passes_the_budget_is_refused_under_the_default_749c() {
    // 600 outputs spent 600 ways: ~599 repeat clones. On the wire-only meter
    // each repeat weighs ~6 KB, ~3.6 MB total — well under the 16 MiB default,
    // so it LINKED while holding tens of MB of heap. Weighing the clone's heap
    // (its output/input struct backings) crosses the budget, so the default now
    // refuses it as a resource limit of its own class.
    let (bytes, subject) = fanin_beef(600, 600);
    let err = Transaction::from_beef(&bytes, Some(&subject))
        .expect_err("a 600-way sweep of one parent re-materializes past the default heap budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "the refusal is a resource limit of its own class, not {err:?}"
    );
    // The same answer links for a caller that trusts its source and opts out.
    let tx = Transaction::from_beef_with_limits(
        &bytes,
        Some(&subject),
        &bsv_rs::transaction::BeefLinkLimits::unbounded(),
    )
    .expect("an unbounded link accepts the sweep");
    assert_eq!(tx.id(), subject);
}

#[test]
fn an_honest_small_fan_in_sweep_still_links_under_the_default_749c() {
    // Fan-in 20 — the largest shared-parent fan any real dependent's BEEF
    // carries — links far under the default on both the wire and heap meters.
    let (bytes, subject) = fanin_beef(20, 20);
    let tx = Transaction::from_beef(&bytes, Some(&subject))
        .expect("an honest fan-in sweep links under the default bound");
    assert_eq!(tx.id(), subject);
}
