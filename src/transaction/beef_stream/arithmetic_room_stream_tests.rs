//! The arithmetic room guard (bsv-rs#374) reaches the streaming door that a
//! deployed Worker drives on a peer's BEEF.
//!
//! A spend the stream runs holds two operands that FIT the default 32 MB
//! budget (so they are not refused when pushed), then `OP_MUL`s them. Under the
//! modelled allocator's ceiling the product's room is refused, and the stream
//! answers [`Verdict::SpendRefused`] with [`SpendRefusal::Resource`]
//! (`element-size`) — the guard's decline carried to the door — not a process
//! abort and not a verdict on the script. On a scratch copy without the guard
//! the same spend allocates the product infallibly: no decline, the reader
//! finishes (red).
//!
//! The ceiling is the crate-internal model
//! ([`crate::script::spend::with_allocator_ceiling`]), so the test is hermetic
//! and holds only a few hundred kilobytes.

use std::collections::HashMap;

use crate::script::spend::with_allocator_ceiling;
use crate::script::{LockingScript, Script, ScriptResource, UnlockingScript};
use crate::transaction::beef_stream::{Hash32, SpendRefusal};
use crate::transaction::{
    MerklePath, MockChainTracker, StreamVerifier, Transaction, TransactionInput,
    TransactionOutput, Verdict,
};

const HEIGHT: u32 = 800_000;
/// Each operand: ~0.29 MiB, above the 64 KiB reservation floor and well within
/// the 32 MB default budget.
const OPERAND: usize = 300_000;
/// Below the `OP_MUL` step's peak (8 x 600 KB ≈ 4.8 MB), above the operands
/// and the interpreter's ordinary allocations.
const CEILING: usize = 1 << 20;
const OP_MUL: u8 = 0x95;
const OP_DROP: u8 = 0x75;
const OP_1: u8 = 0x51;

/// A minimally encoded positive number of `len` bytes.
fn widest(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xff; len];
    bytes[len - 1] = 0x7f;
    bytes
}

/// A parent proven by a one-leaf BUMP, one output locked by `OP_MUL OP_DROP
/// OP_1` (multiplies the two pushed operands, drops the product, succeeds).
fn proven_parent() -> Transaction {
    let mut lock = Script::new();
    lock.write_opcode(OP_MUL)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    let mut parent = Transaction::new();
    let mut phantom = TransactionInput::new("aa".repeat(32), 0);
    phantom.set_unlocking_script(UnlockingScript::new());
    parent.add_input(phantom).unwrap();
    parent
        .add_output(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&lock.to_binary()).unwrap(),
        ))
        .unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), HEIGHT));
    parent
}

/// A version-2 spend pushing two `OPERAND`-byte numbers for the parent's
/// `OP_MUL` lock.
fn subject(parent: Transaction) -> Transaction {
    let mut unlock = Script::new();
    unlock.write_bin(&widest(OPERAND));
    unlock.write_bin(&widest(OPERAND));
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.set_unlocking_script(UnlockingScript::from_binary(&unlock.to_binary()).unwrap());
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

#[test]
fn verify_stream_surfaces_the_arithmetic_rooms_decline_not_an_abort() {
    let parent = proven_parent();
    let root = parent.hash();
    let subject = subject(parent);
    let named = subject.hash();
    let beef = subject.to_beef(false).unwrap();

    let mut display = root;
    display.reverse();
    let mut tracker = MockChainTracker::new(HEIGHT);
    tracker.add_root(HEIGHT, crate::primitives::to_hex(&display));
    let headers: HashMap<u64, Hash32> = HashMap::from([(u64::from(HEIGHT), root)]);

    let verdict = with_allocator_ceiling(CEILING, || {
        StreamVerifier::new(beef.as_slice(), &headers, None)
            .run()
            .expect("the reader itself does not error; the spend declines")
    });

    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Resource(limit),
            ..
        } => {
            assert_eq!(txid, named, "the decline names the subject");
            assert_eq!(
                limit.resource,
                ScriptResource::ElementSize,
                "the arithmetic room's decline is element-size, not a stack-budget decline"
            );
        }
        other => panic!("expected the arithmetic room guard's decline at the stream door: {other:?}"),
    }
}
