//! `Transaction::verify` keeps a decline apart from an invalid script
//! (bsv-rs#38). The reference's `Transaction.verify` runs `Spend` per input and
//! lets its two exceptions propagate by class: `ScriptEvaluationError` for an
//! invalid script, `ScriptResourceLimitError` for an evaluation stopped at a
//! local budget (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts:1441-1458`,
//! `packages/sdk/src/script/Spend.ts:2020-2021`). Until #38 this crate's
//! `verify` mapped both to `TransactionError("Script validation failed for
//! input N: …")`, so a caller read a script nobody judged as invalid.
//!
//! The child spends a proven parent; its one input pushes 1,000,000 bytes and
//! the parent's lock `OP_DUP`s it. `verify` runs the default mode under the
//! caller's budget, 32,000,000 bytes on the main stack here (the budget that was
//! `verify`'s own until bsv-rs#331, whose default is now uncapped:
//! `tests/transaction_verify_budget_331.rs`): 32 copies reach it exactly, a 33rd
//! is the decline.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{OP_0, OP_DROP, OP_DUP, OP_EQUALVERIFY};
use bsv_rs::script::{LockingScript, Script, ScriptResource, ScriptResourceLimit, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

const ELEMENT: usize = 1_000_000;

/// The parent locked by `lock`, proven at height 800,000, and a child
/// spending its output 0 with a push of `ELEMENT` bytes of 0x01.
fn child_of(lock: &[u8]) -> Transaction {
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("aa".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs.push(funding);
    parent.outputs.push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(lock).unwrap(),
    ));
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));

    let mut unlock = Script::new();
    unlock.write_bin(&vec![0x01; ELEMENT]);
    let mut input = TransactionInput::new(parent.id(), 0);
    input.unlocking_script = Some(UnlockingScript::from_script(unlock));
    input.source_transaction = Some(Box::new(parent));
    let mut child = Transaction::new();
    child.inputs.push(input);
    child.outputs.push(TransactionOutput::new(
        900,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    child
}

/// `dups` copies of the pushed element, then `drops` of them dropped.
fn dup_lock(dups: usize, drops: usize) -> Vec<u8> {
    let mut lock = vec![OP_DUP; dups];
    lock.extend(std::iter::repeat_n(OP_DROP, drops));
    lock
}

/// The budget this file pins, passed as `verify`'s third parameter.
const BUDGET: Option<usize> = Some(32_000_000);

fn verify(tx: &Transaction) -> Result<bool, Error> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(tx.verify(&MockChainTracker::always_valid(800_010), None, BUDGET))
}

/// 32 copies on the stack are 32,000,000 bytes, the caller's budget exactly: valid.
#[test]
fn a_stack_at_the_callers_budget_verifies() {
    assert_eq!(verify(&child_of(&dup_lock(31, 31))), Ok(true));
}

/// The 33rd copy would take the main stack to 33,000,000 bytes: the evaluator
/// declines, and `verify` says so in its own class, the input and the figures
/// kept, never as `TransactionError`.
#[test]
fn a_decline_leaves_verify_as_its_own_class() {
    let err = verify(&child_of(&dup_lock(32, 32))).unwrap_err();
    assert_eq!(
        err,
        Error::ScriptEvaluationDeclined {
            input_index: 0,
            limit: ScriptResourceLimit {
                resource: ScriptResource::Stack,
                limit: 32_000_000,
                attempted: 33_000_000,
                work_spent: None,
            },
        }
    );
    assert!(!matches!(err, Error::TransactionError(_)));
    assert_eq!(
        err.to_string(),
        "script evaluation declined for input 0: Stack memory usage has exceeded 32000000 bytes"
    );
}

/// The same shape with an invalid script is still the verdict downstreams
/// match on: `TransactionError("Script validation failed for input 0: …")`.
#[test]
fn an_invalid_script_still_verifies_to_a_transaction_error() {
    let mut lock = dup_lock(4, 0);
    lock.extend([OP_0, OP_EQUALVERIFY]);
    assert_eq!(
        verify(&child_of(&lock)),
        Err(Error::TransactionError(
            "Script validation failed for input 0: OP_EQUALVERIFY requires the top two stack items to be equal."
                .to_string()
        ))
    );
}
