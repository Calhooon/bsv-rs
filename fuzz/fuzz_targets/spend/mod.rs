//! The two script-spend targets' evaluation (`fuzz_script_spend` under a
//! node word, `fuzz_script_spend_default` without one, bsv-rs#398): one
//! counting allocator and one pair of bounds for both. The assertion is no
//! panic and no allocation past the budget, never a verdict: while the
//! evaluation runs, the allocator holds the largest single request and the
//! peak of the bytes it added, and both must stay within a bound that is the
//! budget's, plus a term linear in the input (the parsed chunks and an
//! error's rendering of the scripts). The live bound adds
//! [`ARITHMETIC_WORKING_SET`] budgets for the big-number library's working
//! memory in one arithmetic opcode, which the budget leaves out by design: a
//! tolerance for what the accounting leaves out, not a budget miss
//! (bsv-rs#348, the keeper's word of 2026-10-27).
//!
//! Both reads leave out a reservation: an allocation freed before the
//! allocator's next call, nothing allocated, grown or freed in between
//! (bsv-rs#331, the keeper's pick of 2026-10-27). The interpreter's step
//! probe (`arithmetic_room.rs`, `reserve`: `try_reserve_exact` of the step's
//! peak, given back at once, #374) is one: it asks the allocator whether the
//! step can run, so that a refusal is a decline and not an abort. It is
//! sized by operands the budget has already charged and freed before the
//! step, so it is not the working set the live bound measures (counting it
//! would count the step's peak twice, the step's own allocations then going
//! through the same bound), nor the class the single-request rule stands
//! for (an allocation sized by the input before the budget is charged,
//! #349's). A reservation is still asked of the allocator, which must grant
//! it: under a tight ceiling it is refused there, the decline the probe
//! exists for.
#![allow(dead_code)]

use bsv_rs::primitives::bsv::sighash::TxOutput;
use bsv_rs::script::{LockingScript, ScriptFlags, Spend, SpendParams, UnlockingScript};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

/// The local memory budget of an evaluation, in bytes: the word target's
/// always, the default target's unless its input asks for [`READ_LIMIT_BUDGET`].
pub const MEMORY_LIMIT: usize = 1 << 20;
/// The default target's larger budget (byte 0, bit 3; bsv-rs#398): room for
/// one operand past the reference's read figure (67,108,863 bytes, the
/// 536,870,889th bit) and for a left shift's result past it, so the default
/// mode's `Invalid string length` (bsv-rs#331) is a verdict the fuzzer can
/// reach rather than the 1 MiB budget's decline. Not 2^30 bits' room: V8's
/// `BigInt` cap stays a decline here. Measured on an 8 MiB squaring chain
/// under this budget (`0x7fffffff` and 21 `OP_DUP OP_MUL`), a build without a
/// sanitizer peaks at a resident set of 133 MB; under AddressSanitizer the
/// same run reaches 2,247 MB, past libFuzzer's 2,048 MB RSS limit, its shadow
/// and quarantine and not the interpreter's, so the nightly builds this
/// target with `-s none` (`.github/workflows/nightly.yml`, pinned by
/// `tests/arch_fuzz_targets_dispatched.rs`).
pub const READ_LIMIT_BUDGET: usize = 1 << 27;
/// The work budget: one unit per opcode plus the bytes hashed.
pub const WORK_LIMIT: u64 = 50_000;
/// The budgets of live bytes allowed above the interpreter's four for one
/// arithmetic opcode's working memory (bsv-rs#348): a tolerance for what the
/// accounting leaves out by design (the keeper's word of 2026-10-27, under
/// the owner's ruling (c)). The budget means what the node's
/// `limitedstack.cpp` and the reference's `Spend.ts:1562-1573`
/// (`ts-stack@edf6e03`) make it mean, the bytes of the stack's elements: an
/// operand and a result are elements, charged; what num-bigint 0.4.8 holds
/// while it computes is not, and charging it would decline scripts both of
/// them judge valid. The abort path is guarded separately, by the step
/// probe's room check (`arithmetic_room.rs`, bsv-rs#374). Measured on operands of
/// 2^16 to 2^24 bytes: a quotient or a remainder peaks at 9.5 times its
/// operands (a divisor of 0.03 to 1 percent of the dividend), a product at
/// 5.2 times; a 68-byte script squaring to a 1,015,808-byte dividend held
/// 7,667,840 bytes live under this budget after the #348 fix (the corpus's
/// `3093a2154cceb4c44c01807a9cac0fadfef57ae1`). The operands
/// are on the budget, so the working set is at most 8.5 budgets, and the
/// stack it runs beside at most 1.5 (32 bytes charged per element against a
/// 24-byte slot in a doubling vector). The side effect: this bound no longer
/// catches #348's shape (a pushed number holding twice its charge, 4,815,906
/// bytes live, under ten budgets); `tests/script_budget_before_allocation_348.rs`
/// holds that input to one allocation site under the budget itself.
pub const ARITHMETIC_WORKING_SET: usize = 6;

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
/// The last allocation, its address and size, until the allocator's next
/// call decides it: freed then, a reservation, counted nowhere; anything
/// else, a request, counted in both reads.
static PENDING_PTR: AtomicUsize = AtomicUsize::new(0);
static PENDING_SIZE: AtomicUsize = AtomicUsize::new(0);

impl Counting {
    /// The pending allocation counted as a request.
    fn settle() {
        let size = PENDING_SIZE.swap(0, Ordering::Relaxed);
        PENDING_PTR.store(0, Ordering::Relaxed);
        Self::grew(size);
    }
    fn grew(size: usize) {
        LARGEST.fetch_max(size, Ordering::Relaxed);
        let size = size as isize;
        let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
    fn allocated(ptr: *mut u8, size: usize) {
        if ARMED.load(Ordering::Relaxed) {
            Self::settle();
            PENDING_PTR.store(ptr as usize, Ordering::Relaxed);
            PENDING_SIZE.store(size, Ordering::Relaxed);
        }
    }
    fn freed(ptr: *mut u8, size: usize) {
        if ARMED.load(Ordering::Relaxed) {
            if !ptr.is_null() && PENDING_PTR.load(Ordering::Relaxed) == ptr as usize {
                // freed before any other call: a reservation
                PENDING_SIZE.store(0, Ordering::Relaxed);
                PENDING_PTR.store(0, Ordering::Relaxed);
                return;
            }
            Self::settle();
            // Bytes allocated before the evaluation was armed may be freed
            // during it: the count is the net growth, and may go below zero.
            LIVE.fetch_sub(size as isize, Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        Self::allocated(ptr, layout.size());
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        Self::allocated(ptr, layout.size());
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Self::freed(ptr, layout.size());
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            // both blocks held at once, as before
            Self::settle();
            Self::grew(new_size);
        }
        Self::freed(std::ptr::null_mut(), layout.size());
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// `unlocking` then `locking` through `Spend` at `version` under `budget`,
/// under `word` if one is given, else in the default mode (no `set_flags`:
/// the reference's verdicts), the allocator armed for the evaluation alone.
pub fn evaluate(
    word: Option<ScriptFlags>,
    version: i32,
    budget: usize,
    unlocking: &[u8],
    locking: &[u8],
) {
    let (Ok(unlocking_script), Ok(locking_script)) = (
        UnlockingScript::from_binary(unlocking),
        LockingScript::from_binary(locking),
    ) else {
        return;
    };
    let mut spend = Spend::new(SpendParams {
        source_txid: [0x11; 32],
        source_output_index: 0,
        source_satoshis: 1_000,
        locking_script,
        transaction_version: version,
        other_inputs: Vec::new(),
        outputs: vec![TxOutput {
            satoshis: 900,
            script: vec![0x51],
        }],
        input_index: 0,
        unlocking_script,
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: Some(budget),
        work_limit: Some(WORK_LIMIT),
    });
    if let Some(word) = word {
        spend.set_flags(word);
    }
    assert_eq!(spend.memory_limit(), budget);

    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    PENDING_PTR.store(0, Ordering::Relaxed);
    PENDING_SIZE.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let verdict = spend.validate();
    drop(spend);
    Counting::settle();
    ARMED.store(false, Ordering::Relaxed);
    drop(verdict);

    let input = unlocking.len() + locking.len();
    let slack = 256 * input + (64 << 10);
    let largest = LARGEST.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed).max(0) as usize;
    assert!(
        largest <= 2 * budget + slack,
        "one allocation of {largest} bytes under a budget of {budget}"
    );
    assert!(
        peak <= (4 + ARITHMETIC_WORKING_SET) * budget + slack,
        "{peak} bytes live under a budget of {budget}"
    );
}
