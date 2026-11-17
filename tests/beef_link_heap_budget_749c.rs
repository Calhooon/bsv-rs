//! The default link bound holds the re-materialized HEAP to a small multiple of
//! its budget, not hundreds of MB (bsv-rs #749 fold-c — the declined-late /
//! accepted sibling of the shared-proof fold).
//!
//! A parent of 4,000 one-byte outputs spent 420 ways is a ~57 KB BEEF whose
//! child re-materializes ~419 clones of the parent. On the #749 wire-only meter
//! each repeat weighed ~40 KB (`stub.to_binary().len()`), ~17 MB total, so the
//! 16 MiB default refused it — but only AFTER holding ~248 MB of heap, because a
//! one-byte-locked output is ~10 wire bytes yet ~150 heap bytes once cloned.
//! 248 MB is past the 128 MB Worker isolate (a wasm32 abort). Weighing the
//! clone's struct backings brings the heap held down to a small multiple of the
//! budget.
//!
//! Measured with `dhat::Alloc` (a dev-dependency) as the global allocator, under
//! the NORMAL gate — the same relative-measurement idiom as
//! `beef_link_refuse_order.rs`. One test; `dhat`'s one profiler per process.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A BEEF of one unproven parent of `n` one-byte outputs and a child spending
/// `m` of them. Built by this crate's own writer; returns the bytes and child id.
fn fanin_beef(n: u32, m: u32) -> (Vec<u8>, String) {
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
    beef.merge_raw_tx(parent.to_binary(), None);
    beef.merge_raw_tx(child.to_binary(), None);
    (beef.to_binary(), cid)
}

/// Half the 128 MB Worker isolate: well above the small multiple of the 16 MiB
/// budget the fix holds, and far below the ~248 MB the wire-only meter held.
const HEAP_CEILING: usize = 64 * 1024 * 1024;

#[test]
fn the_default_bounds_the_heap_held_linking_a_wide_fan_in_749c() {
    let (bytes, subject) = fanin_beef(4_000, 420); // built before the profiler

    // Warm one-time initializers (hashers, lazily-built tables) before the
    // profiler so the measured peak is the link's own heap, not a first-call cost.
    let _ = Transaction::from_beef(&bytes, Some(&subject));

    let profiler = dhat::Profiler::builder().testing().build();
    let result = Transaction::from_beef(&bytes, Some(&subject));
    let peak = dhat::HeapStats::get().max_bytes;
    drop(result);
    drop(profiler);

    // The verdict (declined, or linked for a shape that just clears the budget)
    // is not the point; the point is the HEAP held while linking.
    println!("peak heap linking 4000x420 under the default: {peak} bytes");
    assert!(
        peak < HEAP_CEILING,
        "the default held {peak} bytes of heap linking a 4000x420 fan-in, past the \
         {HEAP_CEILING}-byte ceiling (half the 128 MB Worker isolate): the link meter weighs \
         wire bytes, not the heap each repeat clone holds"
    );
}
