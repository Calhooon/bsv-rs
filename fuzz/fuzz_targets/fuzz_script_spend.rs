#![no_main]
//! An arbitrary unlocking and locking script pair through `Spend` under the
//! node's block word and its standard word (CLAUDE.md, the contracts), with a
//! small work budget and the local memory budget set. The assertion is no
//! panic and no allocation past the budget, never a verdict: while the
//! evaluation runs, a counting allocator holds the largest single request
//! and the peak of the bytes it added, and both must stay within a bound
//! that is the budget's, plus a term linear in the input (the parsed chunks
//! and an error's rendering of the scripts). The live bound adds
//! [`ARITHMETIC_WORKING_SET`] budgets for the big-number library's working
//! memory in one arithmetic opcode, which the budget leaves out by design: a
//! tolerance for what the accounting leaves out, not a budget miss
//! (bsv-rs#348, the keeper's word of 2026-10-27).
//!
//! The input: byte 0 picks the word (bit 0: block or standard), the era
//! (bit 1: post-Genesis or post-Chronicle) and the spending transaction's
//! version (bit 2: 1 or 2); bytes 1 and 2 are the unlocking script's length
//! (little-endian); then the unlocking script, and the rest is the locking
//! script. `fuzz/corpus-gen` writes the sibling harness's seed rows in this
//! shape.
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
//!
use bsv_rs::primitives::bsv::sighash::TxOutput;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use libfuzzer_sys::fuzz_target;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

/// The local memory budget of every evaluation, in bytes.
const MEMORY_LIMIT: usize = 1 << 20;
/// The work budget: one unit per opcode plus the bytes hashed.
const WORK_LIMIT: u64 = 50_000;
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
const ARITHMETIC_WORKING_SET: usize = 6;

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

fn evaluate(word: ScriptFlags, version: i32, unlocking: &[u8], locking: &[u8]) {
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
        memory_limit: Some(MEMORY_LIMIT),
        work_limit: Some(WORK_LIMIT),
    });
    spend.set_flags(word);
    assert_eq!(spend.memory_limit(), MEMORY_LIMIT);

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
        largest <= 2 * MEMORY_LIMIT + slack,
        "one allocation of {largest} bytes under a budget of {MEMORY_LIMIT}"
    );
    assert!(
        peak <= (4 + ARITHMETIC_WORKING_SET) * MEMORY_LIMIT + slack,
        "{peak} bytes live under a budget of {MEMORY_LIMIT}"
    );
}

fuzz_target!(|data: &[u8]| {
    let [mode, low, high, rest @ ..] = data else {
        return;
    };
    let era = if mode & 2 == 0 {
        ProtocolEra::PostGenesis
    } else {
        ProtocolEra::PostChronicle
    };
    let word = if mode & 1 == 0 {
        ScriptFlags::block(era)
    } else {
        ScriptFlags::standard(era)
    };
    let version = if mode & 4 == 0 { 1 } else { 2 };
    let split = (u16::from_le_bytes([*low, *high]) as usize).min(rest.len());
    let (unlocking, locking) = rest.split_at(split);
    evaluate(word, version, unlocking, locking);
});
