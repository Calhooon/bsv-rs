#![cfg(test)]

//! The arithmetic result's room (bsv-rs#374) at a small scale: the element
//! bound and the allocator's ceiling are this file's models
//! (`ELEMENT_BOUND`, `ALLOCATOR_CEILING`), so a product past them costs
//! bytes, not gigabytes. The real bound is
//! `tests/script_arithmetic_result_bound_374.rs`'s, by hand.

use super::{ALLOCATOR_CEILING, ELEMENT_BOUND};
use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::flags::{ProtocolEra, ScriptFlags};
use crate::script::op::{OP_1, OP_1ADD, OP_DROP, OP_MUL, OP_NUMEQUALVERIFY, OP_SIZE};
use crate::script::spend::{Spend, SpendParams};
use crate::script::{LockingScript, Script, UnlockingScript};

/// A script number of `len` bytes with the largest positive magnitude it can
/// hold: `len * 8 - 1` bits.
fn widest(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xff; len];
    bytes[len - 1] = 0x7f;
    bytes
}

/// `operands` pushed, then `lock`, at `version`, under `word`.
fn run(
    operands: &[Vec<u8>],
    lock: &Script,
    version: i32,
    word: Option<ScriptFlags>,
) -> Result<bool, ScriptEvaluationError> {
    let mut unlock = Script::new();
    for operand in operands {
        unlock.write_bin(operand);
    }
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock.clone()),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(word) = word {
        spend.set_flags(word);
    }
    spend.validate()
}

/// `opcode OP_DROP OP_1`.
fn then_true(opcode: u8) -> Script {
    let mut lock = Script::new();
    lock.write_opcode(opcode)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    lock
}

fn with_bound<T>(bound: usize, f: impl FnOnce() -> T) -> T {
    ELEMENT_BOUND.with(|b| b.set(bound));
    let out = f();
    ELEMENT_BOUND.with(|b| b.set(super::MAX_SCRIPT_ELEMENT_SIZE));
    out
}

fn declined(result: Result<bool, ScriptEvaluationError>) -> (String, ScriptResourceLimit) {
    let error = result.expect_err("a decline");
    let limit = error.resource_limit.expect("a resource limit");
    (error.message, limit)
}

/// Two 600-byte operands under a bound of 1,000: the product has at least
/// 9,597 bits, 1,200 bytes, and is declined from the operands' bytes before
/// either is decoded.
#[test]
fn a_product_past_the_element_bound_is_declined_before_its_operands_are_decoded() {
    let (message, limit) = with_bound(1000, || {
        declined(run(
            &[widest(600), widest(600)],
            &then_true(OP_MUL),
            2,
            None,
        ))
    });
    assert_eq!(
        limit,
        ScriptResourceLimit {
            resource: ScriptResource::ElementSize,
            limit: 1000,
            attempted: 1200,
            work_spent: None,
        }
    );
    assert_eq!(
        message,
        "Script element allocation has exceeded 1000 bytes: OP_MUL needs at least 1200 bytes for its result, from operands of 600 and 600 bytes."
    );
}

/// Two 500-byte operands: a product of 7,998 bits, 1,000 bytes, at the bound
/// and pushed.
#[test]
fn a_product_at_the_element_bound_is_pushed() {
    let mut lock = Script::new();
    lock.write_opcode(OP_MUL)
        .write_opcode(OP_SIZE)
        .write_number(1000)
        .write_opcode(OP_NUMEQUALVERIFY)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    let verdict = with_bound(1000, || run(&[widest(500), widest(500)], &lock, 2, None));
    assert_eq!(verdict.map_err(|e| e.message), Ok(true));
}

/// `OP_1ADD` of 2^7999 - 1 (1,000 bytes) is 2^7999, 1,001 bytes: nothing
/// bounds it below its operand, so its exact length is judged at the push.
#[test]
fn a_sum_one_byte_past_the_element_bound_is_declined_by_its_length() {
    let (message, limit) = with_bound(1000, || {
        declined(run(&[widest(1000)], &then_true(OP_1ADD), 2, None))
    });
    assert_eq!((limit.limit, limit.attempted), (1000, 1001));
    assert_eq!(
        message,
        "Script element allocation has exceeded 1000 bytes: OP_1ADD needs 1001 bytes for its result, from an operand of 1000 bytes."
    );
}

/// Under a word the element bound does not apply: the number-length limit
/// bounds the operands at their read (32,000,000 bytes after Chronicle on the
/// block path) and the 1,200-byte product is pushed.
#[test]
fn under_a_word_the_element_bound_does_not_bound_a_product() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let verdict = with_bound(1000, || {
        run(
            &[widest(600), widest(600)],
            &then_true(OP_MUL),
            2,
            Some(word),
        )
    });
    assert_eq!(verdict.map_err(|e| e.message), Ok(true));
}

/// A non-minimal operand at version 1 is the read's verdict before the bound
/// is judged, as the reference reads both operands before its budget test.
#[test]
fn an_operands_encoding_verdict_precedes_the_bound() {
    let mut padded = widest(600);
    padded.push(0x00);
    let error = with_bound(1000, || {
        run(&[widest(600), padded], &then_true(OP_MUL), 1, None).expect_err("the read's verdict")
    });
    assert!(!error.is_resource_limit(), "{}", error.message);
    assert!(
        error.message.starts_with("Invalid script number:"),
        "{}",
        error.message
    );
}

/// An allocator that refuses the result's 80,000 bytes: the decline names
/// them and the operands, where the arithmetic would have aborted.
#[test]
fn an_allocator_that_refuses_the_results_room_is_a_decline() {
    ALLOCATOR_CEILING.with(|c| c.set(70_000));
    let result = run(
        &[widest(40_000), widest(40_000)],
        &then_true(OP_MUL),
        2,
        None,
    );
    ALLOCATOR_CEILING.with(|c| c.set(usize::MAX));
    let (message, limit) = declined(result);
    assert_eq!(
        limit,
        ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: 0,
            attempted: 80_000,
            work_spent: None,
        }
    );
    assert_eq!(
        message,
        "Stack memory usage has exceeded 0 bytes: the allocator refused the 80000 bytes OP_MUL's result may need, from operands of 40000 and 40000 bytes."
    );
}
