//! `Transaction::verify` takes the caller's memory budget as its third
//! parameter and, without one, runs uncapped, as the reference does
//! (bsv-rs#331). The reference's `verify(chainTracker, feeModel, memoryLimit?,
//! verifier?)` hands `memoryLimit` to `Spend`, whose default is
//! `Number.POSITIVE_INFINITY` (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Transaction.ts:1685-1697`,
//! `packages/sdk/src/script/Spend.ts:295-296`). Until #331 this crate's
//! `verify` took no budget and evaluated under the default mode's
//! 32,000,000 bytes, so it declined a script the network accepts.
//!
//! The shape is #38's (`tests/transaction_verify_decline_38.rs`): a child of a
//! proven parent pushes 1,000,000 bytes and the parent's lock `OP_DUP`s it 32
//! times: 33 copies, a main stack of 33,000,000 bytes, the 33rd copy past
//! 32,000,000.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{OP_0, OP_1, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_NOP7};
use bsv_rs::script::{LockingScript, Script, ScriptResource, ScriptResourceLimit, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

const ELEMENT: usize = 1_000_000;

/// The parent locked by `lock`, proven at height 800,000, and a child of
/// `version` spending its output 0 with `unlock`.
fn child_of(lock: &[u8], unlock: Script, version: u32) -> Transaction {
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("aa".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs.push(funding);
    parent.outputs.push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(lock).unwrap(),
    ));
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));

    let mut input = TransactionInput::new(parent.id(), 0);
    input.unlocking_script = Some(UnlockingScript::from_script(unlock));
    input.source_transaction = Some(Box::new(parent));
    let mut child = Transaction::new();
    child.version = version;
    child.inputs.push(input);
    child.outputs.push(TransactionOutput::new(
        900,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    child
}

/// A push of `ELEMENT` bytes of 0x01.
fn element_push() -> Script {
    let mut unlock = Script::new();
    unlock.write_bin(&vec![0x01; ELEMENT]);
    unlock
}

/// `dups` copies of the pushed element, then `drops` of them dropped.
fn dup_lock(dups: usize, drops: usize) -> Vec<u8> {
    let mut lock = vec![OP_DUP; dups];
    lock.extend(std::iter::repeat_n(OP_DROP, drops));
    lock
}

/// The #38 shape: 33 copies, 33,000,000 bytes, the 32 duplicates dropped.
fn the_38_shape() -> Transaction {
    child_of(&dup_lock(32, 32), element_push(), 1)
}

fn verify(tx: &Transaction, memory_limit: Option<usize>) -> Result<bool, Error> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(tx.verify(&MockChainTracker::always_valid(800_010), None, memory_limit))
}

/// Without a caller's budget nothing caps the stack: the shape #38 declined
/// verifies, as the reference's default verifies it.
#[test]
fn a_stack_past_32_000_000_bytes_verifies_without_a_callers_budget() {
    assert_eq!(verify(&the_38_shape(), None), Ok(true));
}

/// Under the caller's 32,000,000 bytes the 33rd copy is the decline, with the
/// budget's figures.
#[test]
fn a_callers_32_000_000_byte_budget_declines_the_33rd_copy() {
    assert_eq!(
        verify(&the_38_shape(), Some(32_000_000)),
        Err(Error::ScriptEvaluationDeclined {
            input_index: 0,
            limit: ScriptResourceLimit {
                resource: ScriptResource::Stack,
                limit: 32_000_000,
                attempted: 33_000_000,
                work_spent: None,
            },
        })
    );
}

/// The caller's budget is the budget: 40,000,000 bytes hold the 33 copies.
#[test]
fn a_callers_40_000_000_byte_budget_verifies_the_same_stack() {
    assert_eq!(verify(&the_38_shape(), Some(40_000_000)), Ok(true));
}

/// An invalid script is the same verdict under either reading.
#[test]
fn an_invalid_script_is_a_transaction_error_with_or_without_a_budget() {
    let mut lock = dup_lock(4, 0);
    lock.extend([OP_0, OP_EQUALVERIFY]);
    let tx = child_of(&lock, element_push(), 1);
    let verdict = Err(Error::TransactionError(
        "Script validation failed for input 0: OP_EQUALVERIFY requires the top two stack items to be equal."
            .to_string(),
    ));
    assert_eq!(verify(&tx, None), verdict);
    assert_eq!(verify(&tx, Some(32_000_000)), verdict);
}

/// Uncapped, the default mode's 1 GiB element bound still holds: a numeric
/// left shift of 1 by 2^40 bits (a result of 2^37 bytes) is refused before the
/// allocation, the verdict `OP_CAT` and `OP_NUM2BIN` give above the bound,
/// where without the bound it asked the allocator for 128 GiB. Under a budget
/// the budget declines it first, as before. A version-2 child: `OP_LSHIFTNUM`
/// is a post-Chronicle opcode, the default mode's for version > 1.
#[test]
fn an_uncapped_numeric_shift_past_the_element_bound_is_refused_before_it_allocates() {
    let mut lock = Script::new();
    lock.write_bin(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // 2^40, minimal
    let mut lock = lock.to_binary();
    lock.push(OP_NOP7);
    let mut unlock = Script::new();
    unlock.write_opcode(OP_1);
    let tx = child_of(&lock, unlock, 2);
    assert_eq!(
        verify(&tx, None),
        Err(Error::TransactionError(
            "Script validation failed for input 0: It's not currently possible to push data larger than 1073741824 bytes."
                .to_string()
        ))
    );
    assert!(matches!(
        verify(&tx, Some(32_000_000)),
        Err(Error::ScriptEvaluationDeclined {
            limit: ScriptResourceLimit {
                resource: ScriptResource::ElementSize,
                limit: 32_000_000,
                ..
            },
            ..
        })
    ));
}
