//! An arithmetic result at the default mode's 1 GiB element bound (bsv-rs#374,
//! by hand: it holds 1 GiB of operands). Uncapped (`memory_limit: None`, the
//! reference's `Spend`, bsv-rs#331) `OP_MUL` of two operands of 2^29 + 1
//! bytes needs at least 2^30 + 2 bytes; it is declined from the operands'
//! bytes before either is decoded, where `BigNumber`'s infallible allocations
//! would have asked about 2 GiB more and an allocator that refused them would
//! have aborted the process. With `dhat-profiling` the peak of the heap is
//! counted too: the operands, and no allocation of the product's size.
//!
//! `cargo test --test script_arithmetic_result_bound_374 -- --ignored`, or
//! with `--features dhat-profiling` for the count.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{OP_1, OP_DROP, OP_DUP, OP_INVERT, OP_MUL, OP_NUM2BIN};
use bsv_rs::script::{
    LockingScript, Script, ScriptResource, ScriptResourceLimit, Spend, SpendParams, UnlockingScript,
};

#[cfg(feature = "dhat-profiling")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Each operand's length: 2^29 + 1 bytes, so that the product's least length,
/// twice it, passes 2^30.
const OPERAND: usize = (1 << 29) + 1;

/// `OP_1 <OPERAND> OP_NUM2BIN OP_INVERT OP_DUP OP_MUL OP_DROP OP_1`: two
/// operands of `OPERAND` bytes whose magnitudes have `8 * OPERAND - 1` bits
/// each (`OP_INVERT` of `01 00 .. 00` is `fe ff .. ff`), multiplied.
fn lock() -> LockingScript {
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_bin(&(OPERAND as u32).to_le_bytes())
        .write_opcode(OP_NUM2BIN)
        .write_opcode(OP_INVERT)
        .write_opcode(OP_DUP)
        .write_opcode(OP_MUL)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    LockingScript::from_script(lock)
}

#[test]
#[ignore = "by hand: it holds 1 GiB of operands; its RED asks gigabytes more"]
fn an_uncapped_product_past_the_1_gib_element_bound_is_declined_before_it_allocates() {
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: lock(),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::new(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    #[cfg(feature = "dhat-profiling")]
    let profiler = dhat::Profiler::builder().testing().build();
    let error = spend.validate().expect_err("the element bound's decline");
    #[cfg(feature = "dhat-profiling")]
    {
        let peak = dhat::HeapStats::get().max_bytes as u64;
        drop(profiler);
        println!("peak heap: {peak} bytes");
        // the two operands, and nothing of the product's 2^30 + 2 bytes nor of
        // an operand's decoded copy
        assert!(
            peak < 2 * OPERAND as u64 + (1 << 20),
            "peak heap of {peak} bytes"
        );
    }
    assert_eq!(
        error.resource_limit,
        Some(ScriptResourceLimit {
            resource: ScriptResource::ElementSize,
            limit: 1 << 30,
            attempted: 2 * OPERAND as u64,
            work_spent: None,
        })
    );
    assert_eq!(
        error.message,
        "Script element allocation has exceeded 1073741824 bytes: OP_MUL needs at least 1073741826 bytes for its result, from operands of 536870913 and 536870913 bytes."
    );
}
