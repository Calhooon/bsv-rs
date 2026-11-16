//! Ruling 2 (fold2): the refuse-BEFORE-the-allocation order, held by the NORMAL
//! gate (no `dhat-profiling` feature).
//!
//! Linking meters each repeat input's stub and refuses a BEEF past the budget
//! BEFORE the clone that would allocate it: in `src/transaction/beef/link.rs`
//! `meter.charge(*stub_bytes)?` precedes
//! `input.source_transaction = Some(Box::new(stub.clone()))`. The
//! `tests/memory_profiling.rs` dhat test pins this behind the `dhat-profiling`
//! feature and runs ALONE — outside the `full,http,websocket` integration gate
//! the lanes and CI's integration job use. This file pins the same order in that
//! ordinary gate with a counting global allocator — the `dhat::Alloc` dev-dep,
//! armed per test, exactly as `tests/script_budget_before_allocation_348.rs`
//! counts the interpreter's heap (the crate forbids `unsafe_code`, so the test
//! cannot roll its own allocator; dhat here is a plain dev-dep, not the
//! `dhat-profiling` feature).
//!
//! Two candidate designs were considered:
//!   A (chosen): count the CUMULATIVE bytes allocated during one refused link.
//!     The fixture's single over-budget repeat clones a multi-MiB parent stub if
//!     and only if the refusal is moved after the clone, so the cumulative total
//!     crosses a ceiling the correct order stays under. Byte accounting is exact
//!     and deterministic.
//!   B (rejected, weaker): a wall-clock bound (a refused link must return faster
//!     than materializing the stub). Rejected because timing is machine- and
//!     load-dependent and flaky on CI; a fast host can clone-then-refuse under
//!     any threshold, so it cannot reliably catch the reorder.
//!
//! CUMULATIVE (`total_bytes`), not peak: the stub's `to_binary()` size probe at
//! memoization is a transient of one stub's size that the correct order also
//! pays, so it can mask a one-stub gap in the PEAK; the cumulative total counts
//! the refused repeat's clone as a distinct allocation the correct order never
//! makes.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::sync::Mutex;

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLinkLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// The one dhat profiler of this process (a second one panics).
static PROFILER: Mutex<()> = Mutex::new(());

const SATS: u64 = 1_000;
const OUTPUT_BYTES: usize = 3 * 1024 * 1024; // one output ~3 MiB; a stub ~6 MiB

fn filler_script(bytes: usize) -> LockingScript {
    LockingScript::from_binary(&vec![0u8; bytes]).expect("filler locking script")
}

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A BEEF whose one proven parent has two ~3 MiB outputs (~6 MiB), both spent by
/// one child of two inputs. The child is the subject.
fn shared_parent_beef() -> Vec<u8> {
    let script = filler_script(OUTPUT_BYTES);
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("aa".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs_mut().push(funding);
    for _ in 0..2 {
        parent
            .outputs_mut()
            .push(TransactionOutput::new(SATS, script.clone()));
    }
    let parent_txid = parent.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump)).unwrap();
    let mut child = Transaction::new();
    for vout in 0..2u32 {
        let mut input = TransactionInput::new(parent_txid.clone(), vout);
        input.unlocking_script = Some(UnlockingScript::new());
        child.inputs_mut().push(input);
    }
    child
        .outputs_mut()
        .push(TransactionOutput::new(SATS, op_true()));
    beef.merge_raw_tx(child.to_binary(), None).unwrap();
    beef.to_binary().unwrap()
}

#[test]
fn a_refused_link_is_refused_before_it_clones_the_stub() {
    let _serial = PROFILER.lock().unwrap_or_else(|e| e.into_inner());

    // The first input links the ~6 MiB parent in full (its own bytes — parsed,
    // cloned into the memoized stub, probed with to_binary and hashed — always
    // materialized). The second input is a repeat whose ~6 MiB stub the meter
    // charges against an explicit 512 KiB budget. With the shipped order the
    // repeat is refused BEFORE its stub is cloned; if the refusal is moved AFTER
    // the clone, the second input's stub is cloned too — one extra parent copy,
    // past the ceiling.
    let bytes = shared_parent_beef(); // built before the profiler: not counted
    let budget = BeefLinkLimits::default().with_max_link_bytes(Some(512 * 1024));

    let profiler = dhat::Profiler::builder().testing().build();
    let err = Transaction::from_beef_with_limits(&bytes, None, &budget)
        .expect_err("the fixture is over the 512 KiB budget");
    let allocated = dhat::HeapStats::get().total_bytes;
    drop(profiler);

    assert!(matches!(err, Error::BeefResourceLimit(_)), "not {err:?}");

    // Measured on this box: the shipped (refuse-before) order allocates
    // ~51 MiB cumulatively during the refused link; the reordered
    // (clone-then-refuse) order allocates ~63 MiB. The ceiling is the midpoint
    // (~57 MiB); allocation is deterministic, so this is a pin, not a heuristic.
    const CEILING: u64 = 57 * 1024 * 1024;
    println!("refused link cumulative allocation: {allocated} bytes (ceiling {CEILING})");
    assert!(
        allocated < CEILING,
        "a refused link allocated {allocated} bytes (>= {CEILING}): the repeat's stub clone was \
         not refused before it allocated — the #749 refuse-before-the-allocation order (link.rs: \
         meter.charge(stub_bytes)? before stub.clone()) was reordered"
    );
}
