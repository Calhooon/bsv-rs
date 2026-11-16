//! Ruling 2 (fold2, strengthened fold4): the refuse-BEFORE-the-allocation
//! order, held by the NORMAL gate (no `dhat-profiling` feature).
//!
//! Linking meters each repeat input's stub and refuses a BEEF past the budget
//! BEFORE the clone that would allocate it: in `src/transaction/beef/link.rs`
//! `meter.charge(*stub_bytes)?` precedes
//! `input.source_transaction = Some(Box::new(stub.clone()))`. The
//! `tests/memory_profiling.rs` dhat test pins this behind the `dhat-profiling`
//! feature and runs ALONE — outside the `full,http,websocket` integration gate
//! the lanes and CI's integration job use. This file pins the same order in that
//! ordinary gate with a counting global allocator — the `dhat::Alloc` dev-dep,
//! armed per test (the crate forbids `unsafe_code`, so the test cannot roll its
//! own allocator; dhat here is a plain dev-dep, not the `dhat-profiling`
//! feature).
//!
//! The measure is RELATIVE, not an absolute byte ceiling (fold4, the strength
//! re-read's portability item). An absolute ceiling calibrated on one host can
//! red falsely on another CI platform whose correct-order allocation drifts past
//! it. Instead, in ONE process the test measures the SAME fixture down two
//! paths:
//!   * the REFUSING path (a 512 KiB budget): the repeat input's ~6 MiB stub is
//!     charged, and with the shipped order refused BEFORE it is cloned;
//!   * the ADMITTING path (an unbounded budget): the SAME parse and first-input
//!     link, plus exactly ONE extra stub clone, because the repeat is admitted.
//!
//! The admitting path therefore allocates AT LEAST one stub clone (>= the
//! fixture's own two ~3 MiB output scripts, ~6 MiB — data the test builds, so
//! byte-identical on every platform) MORE than the correctly-ordered refusing
//! path, which stops before that clone. Every other allocation — the BEEF parse,
//! the first input's full link, the stub memoization, the per-host std-library
//! scratch — happens in BOTH paths and CANCELS in the difference. Reordering the
//! refusal AFTER the clone makes the refusing path clone the repeat's stub and
//! do the same follow-on work too, so it allocates essentially what the
//! admitting path does and `admitted - refused` collapses to ~0. The judgment is
//! that difference against HALF a stub (`OUTPUT_BYTES`): the correct order clears
//! it by the whole clone (and the follow-on work besides), the reorder falls to
//! ~0, and no per-host drift crosses a margin that wide.
//!
//! Why this holds on each allocator CI meets (glibc/Linux, the macOS system
//! allocator, Windows' heap), stated by the design since they cannot be run
//! here:
//!   * `dhat::Alloc` is the `#[global_allocator]` on EVERY platform, so the
//!     allocator actually in effect under the measurement is the SAME (dhat,
//!     wrapping the system one); `total_bytes` counts the layout sizes the Rust
//!     code requests, which are produced by identical code on every platform.
//!   * The discriminator is one `Transaction::clone` of a stub holding two
//!     `OUTPUT_BYTES` scripts — data the test constructs, so its requested bytes
//!     are byte-identical on all three. Any per-platform difference in
//!     std-internal allocation sizes appears in both measured paths and cancels.
//!   * The margin is HALF the discriminator, so a generous per-platform residual
//!     cannot push the correct order below it nor the reordered order above it.
//!
//! CUMULATIVE (`total_bytes`), not peak: the stub's `to_binary()` size probe at
//! memoization is a transient of one stub's size that both paths pay, so it can
//! mask a one-stub gap in the PEAK; the cumulative total counts the admitted
//! repeat's clone as a distinct allocation the correct refusing order never
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
    parent.inputs.push(funding);
    for _ in 0..2 {
        parent
            .outputs
            .push(TransactionOutput::new(SATS, script.clone()));
    }
    let parent_txid = parent.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump));
    let mut child = Transaction::new();
    for vout in 0..2u32 {
        let mut input = TransactionInput::new(parent_txid.clone(), vout);
        input.unlocking_script = Some(UnlockingScript::new());
        child.inputs.push(input);
    }
    child.outputs.push(TransactionOutput::new(SATS, op_true()));
    beef.merge_raw_tx(child.to_binary(), None);
    beef.to_binary()
}

#[test]
fn a_refused_link_is_refused_before_it_clones_the_stub() {
    let _serial = PROFILER.lock().unwrap_or_else(|e| e.into_inner());

    // The first input links the ~6 MiB parent in full (its own bytes — parsed,
    // cloned into the memoized stub, probed with to_binary and hashed — always
    // materialized). The second input is a repeat of that parent. In the
    // refusing path its ~6 MiB stub is charged against a 512 KiB budget: the
    // shipped order refuses it BEFORE the clone; a reordered one clones it
    // first. In the admitting path the repeat is accepted, so its stub IS
    // cloned — the one allocation that distinguishes the two paths.
    let bytes = shared_parent_beef(); // built before the profiler: not counted
    let refuse = BeefLinkLimits::default().with_max_link_bytes(Some(512 * 1024));
    let admit = BeefLinkLimits::unbounded();

    // Warm one-time initializers (hashers, lazily-built tables) BEFORE the
    // profiler, so neither measured path pays a first-call cost the other skips.
    let _ = Transaction::from_beef_with_limits(&bytes, None, &admit);
    let _ = Transaction::from_beef_with_limits(&bytes, None, &refuse);

    let profiler = dhat::Profiler::builder().testing().build();

    // Refusing path first.
    let err = Transaction::from_beef_with_limits(&bytes, None, &refuse)
        .expect_err("the fixture is over the 512 KiB budget");
    let after_refused = dhat::HeapStats::get().total_bytes;

    // Admitting path second: same parse + first-input link, plus exactly one
    // extra stub clone for the admitted repeat.
    Transaction::from_beef_with_limits(&bytes, None, &admit)
        .expect("an unbounded budget links the same fixture");
    let after_admitted = dhat::HeapStats::get().total_bytes;

    drop(profiler);

    assert!(matches!(err, Error::BeefResourceLimit(_)), "not {err:?}");

    let refused = after_refused; // bytes allocated during the refusing link
    let admitted = after_admitted - after_refused; // bytes during the admitting link
    let saved = admitted.saturating_sub(refused); // ~one stub clone when ordered right

    // The clone the correctly-ordered refusing path skips is the fixture's own
    // stub: two ~3 MiB output scripts, >= 2 * OUTPUT_BYTES (~6 MiB), identical on
    // every platform. The margin is HALF that minimum; the correct order clears
    // it by the whole clone and the follow-on work besides (>= margin), the
    // reordered order collapses to ~0 (< margin) because it then does the same
    // work the admitting path does. Relative, so the per-host parse/hash baseline
    // cancels (see the module doc).
    let margin = OUTPUT_BYTES as u64; // ~3 MiB, half the ~6 MiB stub clone
    println!(
        "refusing link {refused} B, admitting link {admitted} B, saved {saved} B \
         (margin {margin} B, one stub ~{} B)",
        2 * OUTPUT_BYTES
    );
    assert!(
        saved >= margin,
        "the refusing link saved only {saved} B over the admitting link (< {margin} B, half one \
         ~{} B stub clone): the repeat's stub was cloned before the budget refused it — the #749 \
         refuse-before-the-allocation order (link.rs: meter.charge(stub_bytes)? before \
         stub.clone()) was reordered",
        2 * OUTPUT_BYTES
    );
}
