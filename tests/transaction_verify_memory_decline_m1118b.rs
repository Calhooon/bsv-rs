//! `Transaction::verify` carries a caller's memory budget and answers a
//! resource decline as its own class (bsv-rs#374 budget knob + bsv-rs#38 face,
//! ported to the stable line).
//!
//! The `verify` door hardcoded the interpreter's budget to the 32 MB default
//! and folded every script `Err` — a resource decline included — into
//! `Error::TransactionError`, so a caller could not bound the peak at this
//! door, nor tell "too expensive / out of memory" from "the peer's data is
//! invalid". `verify_with_memory_limit` is additive beside `verify` (whose
//! signature is unchanged) and a resource decline is `ScriptEvaluationDeclined`.
//!
//! Hermetic: a one-leaf-BUMP proven parent whose output a version-2 spend
//! duplicates (1,200 bytes on one stack). Under the 32 MB default the spend is
//! valid; under `Some(1_000)` it declines, as a distinct class, not a verdict.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::script::{LockingScript, Script, ScriptResource, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

const HEIGHT: u32 = 800_000;
const PUSHED: usize = 600;
const OP_DUP: u8 = 0x76;
const OP_2DROP: u8 = 0x6d;
const OP_1: u8 = 0x51;

/// `OP_DUP OP_2DROP OP_1`: holds `2 * PUSHED` bytes at its peak, then succeeds.
fn dup_lock() -> LockingScript {
    let mut lock = Script::new();
    lock.write_opcode(OP_DUP)
        .write_opcode(OP_2DROP)
        .write_opcode(OP_1);
    LockingScript::from_binary(&lock.to_binary()).unwrap()
}

fn push_unlock() -> UnlockingScript {
    let mut unlock = Script::new();
    unlock.write_bin(&[0x5a; PUSHED]);
    UnlockingScript::from_binary(&unlock.to_binary()).unwrap()
}

/// A parent proven by a one-leaf BUMP, output 0 locked by `dup_lock`.
fn proven_parent() -> Transaction {
    let mut parent = Transaction::new();
    let mut phantom = TransactionInput::new("aa".repeat(32), 0);
    phantom.set_unlocking_script(UnlockingScript::new());
    parent.add_input(phantom).unwrap();
    parent
        .add_output(TransactionOutput::new(1_000, dup_lock()))
        .unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), HEIGHT));
    parent
}

/// The subject: a version-2 spend of the parent's output 0, pushing `PUSHED`
/// bytes for its `dup_lock`.
fn subject(parent: Transaction) -> Transaction {
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.set_unlocking_script(push_unlock());
    let mut tx = Transaction::new();
    tx.version = 2;
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        900,
        LockingScript::from_binary(&[OP_1]).unwrap(),
    ))
    .unwrap();
    tx
}

fn tracker(root: [u8; 32]) -> MockChainTracker {
    let mut display = root;
    display.reverse();
    let mut t = MockChainTracker::new(HEIGHT + 100);
    t.add_root(HEIGHT, bsv_rs::primitives::to_hex(&display));
    t
}

#[tokio::test]
async fn verify_under_the_default_budget_accepts_the_spend() {
    let parent = proven_parent();
    let root = parent.hash();
    let subject = subject(parent);
    let t = tracker(root);
    assert!(
        subject.verify(&t, None).await.unwrap(),
        "the duplicating spend is valid under the 32 MB default budget"
    );
}

#[tokio::test]
async fn verify_with_a_small_budget_declines_as_its_own_class_not_a_verdict() {
    let parent = proven_parent();
    let root = parent.hash();
    let named_input = 0usize;
    let subject = subject(parent);
    let t = tracker(root);
    match subject
        .verify_with_memory_limit(&t, None, Some(1_000))
        .await
    {
        Err(Error::ScriptEvaluationDeclined { input_index, limit }) => {
            assert_eq!(input_index, named_input, "the decline names the input");
            assert_eq!(
                limit.resource,
                ScriptResource::Stack,
                "the per-stack budget's decline is a stack resource"
            );
            assert_eq!(limit.limit, 1_000, "the budget the caller set");
        }
        other => {
            panic!("expected a ScriptEvaluationDeclined decline (face bsv-rs#38), not {other:?}")
        }
    }
}
