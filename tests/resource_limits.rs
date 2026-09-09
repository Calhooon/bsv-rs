//! Reference parity (0.3.23): a LOCAL interpreter budget is reported as a
//! RESOURCE LIMIT (the TypeScript SDK's `ScriptResourceLimitError`), apart
//! from any verdict on the script, and `OP_NUM2BIN`'s size operand is refused
//! BEFORE it is allocated (the SDK's `element-size` check). A caller whose bar
//! is the network (an overlay door) must never read the evaluator's budget as
//! the network's verdict.
use bsv_rs::script::op::*;
use bsv_rs::script::{LockingScript, Script, ScriptResource, Spend, SpendParams, UnlockingScript};
use std::time::Instant;

fn spend(lock: Script, unlock: Script, memory_limit: usize) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0x11; 32],
        source_output_index: 0,
        source_satoshis: 1_000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: Some(memory_limit),
    })
}

#[test]
fn num2bin_refuses_an_oversized_element_before_allocating_it() {
    // `<1> <1_000_000_000> OP_NUM2BIN`: a 9-byte script asking for a 1 GB
    // element under a 64 KB budget. Refused as `element-size` BEFORE the
    // allocation — fast, and never a verdict on the script.
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_bin(&1_000_000_000i64.to_le_bytes()[..4])
        .write_opcode(OP_NUM2BIN);
    let mut s = spend(lock, Script::new(), 64 * 1024);
    let t0 = Instant::now();
    let err = s.validate().expect_err("a 1 GB element exceeds the budget");
    assert!(
        t0.elapsed().as_millis() < 500,
        "refused before allocating: {:?}",
        t0.elapsed()
    );
    let limit = err
        .resource_limit
        .expect("a resource limit, not a script verdict");
    assert_eq!(limit.resource, ScriptResource::ElementSize);
    assert_eq!(limit.limit, 64 * 1024);
    assert_eq!(limit.attempted, 1_000_000_000);
    assert!(err.is_resource_limit());
    assert!(
        err.message
            .starts_with("Script element allocation has exceeded 65536 bytes"),
        "the reference's label + shape: {}",
        err.message
    );
}

#[test]
fn num2bin_within_the_budget_still_pads() {
    // `OP_1 OP_16 OP_NUM2BIN OP_SIZE OP_16 OP_EQUAL`: a 16-byte pad of 1.
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_opcode(OP_16)
        .write_opcode(OP_NUM2BIN)
        .write_opcode(OP_SIZE)
        .write_opcode(OP_NIP)
        .write_opcode(OP_16)
        .write_opcode(OP_EQUAL);
    let mut s = spend(lock, Script::new(), 64 * 1024);
    assert!(s.validate().expect("a 16-byte pad is inside the budget"));
}

#[test]
fn the_stack_budget_trips_as_a_resource_limit_not_a_script_verdict() {
    // `<8 KB> OP_DUP OP_CAT ×12 OP_DROP OP_TRUE` doubles the element to 32 MB;
    // under a 128 KB budget the STACK limit trips mid-way.
    let mut lock = Script::new();
    for _ in 0..12 {
        lock.write_opcode(OP_DUP).write_opcode(OP_CAT);
    }
    lock.write_opcode(OP_DROP).write_opcode(OP_TRUE);
    let mut unlock = Script::new();
    unlock.write_bin(&vec![0x42u8; 8 * 1024]);
    let mut s = spend(lock, unlock, 128 * 1024);
    let err = s.validate().expect_err("the stack budget trips");
    let limit = err.resource_limit.expect("a resource limit");
    assert_eq!(limit.resource, ScriptResource::Stack);
    assert_eq!(limit.limit, 128 * 1024);
    assert!(limit.attempted > limit.limit);
    assert!(err
        .message
        .starts_with("Stack memory usage has exceeded 131072 bytes"));
}

#[test]
fn a_script_verdict_is_never_a_resource_limit() {
    // `OP_1 OP_2 OP_EQUAL`: evaluates to FALSE — the script's own verdict.
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_opcode(OP_2)
        .write_opcode(OP_EQUAL);
    let mut s = spend(lock, Script::new(), 32_000_000);
    let err = s.validate().expect_err("a false script is refused");
    assert!(
        !err.is_resource_limit(),
        "a verdict on the script: {}",
        err.message
    );
    assert!(err.resource_limit.is_none());
}
