#![no_main]
//! An arbitrary unlocking and locking script pair through `Spend` under the
//! node's block word and its standard word (CLAUDE.md, the contracts), with a
//! small work budget and the local memory budget set. The assertion is no
//! panic and no allocation past the budget, never a verdict: while the
//! evaluation runs, a counting allocator holds the largest single request
//! and the peak of the bytes it added, and both must stay within a bound
//! that is the budget's, plus a term linear in the input (the parsed chunks
//! and an error's rendering of the scripts).
//!
//! The input: byte 0 picks the word (bit 0: block or standard), the era
//! (bit 1: post-Genesis or post-Chronicle) and the spending transaction's
//! version (bit 2: 1 or 2); bytes 1 and 2 are the unlocking script's length
//! (little-endian); then the unlocking script, and the rest is the locking
//! script. `fuzz/corpus-gen` writes the sibling harness's seed rows in this
//! shape.
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

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

impl Counting {
    fn grew(size: usize) {
        if ARMED.load(Ordering::Relaxed) {
            LARGEST.fetch_max(size, Ordering::Relaxed);
            let size = size as isize;
            let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
    }
    fn shrank(size: usize) {
        if ARMED.load(Ordering::Relaxed) {
            // Bytes allocated before the evaluation was armed may be freed
            // during it: the count is the net growth, and may go below zero.
            LIVE.fetch_sub(size as isize, Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::grew(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::grew(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Self::shrank(layout.size());
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::grew(new_size);
        Self::shrank(layout.size());
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
    ARMED.store(true, Ordering::Relaxed);
    let verdict = spend.validate();
    drop(spend);
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
        peak <= 4 * MEMORY_LIMIT + slack,
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
