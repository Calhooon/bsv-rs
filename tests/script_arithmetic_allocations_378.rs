//! Arithmetic guard metadata stays off the heap (#378). For single-digit
//! operands num-bigint allocates the two decode buffers and ScriptNum the
//! one-byte result; the interpreter needs no additional allocation.
#![cfg(feature = "script")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions

use bsv_rs::script::{op::*, LockingScript, Script, Spend, SpendParams, UnlockingScript};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn arithmetic_guard_metadata_allocates_nothing() {
    let mut lock = Script::new();
    lock.write_opcode(OP_2)
        .write_opcode(OP_3)
        .write_opcode(OP_MUL);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::new(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    spend.step().unwrap();
    spend.step().unwrap();
    let _profiler = dhat::Profiler::builder().testing().build();
    assert!(spend.step().unwrap());
    let stats = dhat::HeapStats::get();
    assert!(stats.total_blocks <= 3, "{stats:?}");
    assert!(stats.total_bytes <= 17, "{stats:?}");
    assert_eq!(stats.curr_bytes, 1);
}
