#![cfg(test)]

//! The arithmetic result's room (bsv-rs#374) at a small scale: the element
//! bound and the allocator's ceiling are this file's models
//! (`ELEMENT_BOUND`, `ALLOCATOR_CEILING`), so a product past them costs
//! bytes, not gigabytes. The real bound is
//! `tests/script_arithmetic_result_bound_374.rs`'s, by hand.

use super::{ALLOCATOR_CEILING, ELEMENT_BOUND};
use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::flags::{ProtocolEra, ScriptFlags};
use crate::script::op::{
    OP_1, OP_1ADD, OP_ADD, OP_DIV, OP_DROP, OP_DUP, OP_INVERT, OP_MOD, OP_MUL, OP_NOP7, OP_NUM2BIN,
    OP_NUMEQUALVERIFY, OP_SIZE, OP_WITHIN,
};
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

/// Runs `operands` then `lock` under a modelled allocator that refuses more
/// than `ceiling` bytes at once.
fn under_ceiling(
    ceiling: usize,
    operands: &[Vec<u8>],
    lock: &Script,
) -> Result<bool, ScriptEvaluationError> {
    ALLOCATOR_CEILING.with(|c| c.set(ceiling));
    let result = run(operands, lock, 2, None);
    ALLOCATOR_CEILING.with(|c| c.set(usize::MAX));
    result
}

/// The decline of a step the modelled allocator refused: no budget's limit,
/// the step's bytes attempted.
fn refused(result: Result<bool, ScriptEvaluationError>, attempted: u64) -> String {
    let (message, limit) = declined(result);
    assert_eq!(
        limit,
        ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: 0,
            attempted,
            work_spent: None,
        }
    );
    message
}

/// `OP_MUL` of two 40,000-byte operands: the product needs at most 80,000
/// bytes, which a ceiling of 100,000 grants, and the step six times the
/// operands' 80,000 (num-bigint's Toom-3 scratch), which it refuses: the
/// decline names the step's 480,000 bytes, where the arithmetic would have
/// asked past the ceiling (bsv-rs#374, the review of PR #370's fold 2).
#[test]
fn a_product_whose_step_passes_the_allocators_ceiling_is_declined() {
    let message = refused(
        under_ceiling(
            100_000,
            &[widest(40_000), widest(40_000)],
            &then_true(OP_MUL),
        ),
        480_000,
    );
    assert_eq!(
        message,
        "Stack memory usage has exceeded 0 bytes: the allocator refused the 480000 bytes OP_MUL's step may need, from operands of 40000 and 40000 bytes."
    );
}

/// `OP_DIV` and `OP_MOD` of a 40,000-byte dividend by a 600-byte divisor: a
/// quotient or remainder of at most 40,000 bytes, and a step twelve times the
/// operands' 40,600 (Burnikel-Ziegler's padded copies), refused.
#[test]
fn a_division_whose_step_passes_the_allocators_ceiling_is_declined() {
    for (opcode, name) in [(OP_DIV, "OP_DIV"), (OP_MOD, "OP_MOD")] {
        let message = refused(
            under_ceiling(100_000, &[widest(40_000), widest(600)], &then_true(opcode)),
            487_200,
        );
        assert_eq!(
            message,
            format!("Stack memory usage has exceeded 0 bytes: the allocator refused the 487200 bytes {name}'s step may need, from operands of 40000 and 600 bytes.")
        );
    }
}

/// `OP_ADD` of two 40,000-byte operands and `OP_1ADD` of one: results of
/// 40,001 bytes, under the 64 KiB a result was asked of the allocator from,
/// and steps twice the operands' bytes (their digits, the result's encoding
/// beside them), refused under a ceiling of 70,000.
#[test]
fn a_sum_whose_step_passes_the_allocators_ceiling_is_declined() {
    let message = refused(
        under_ceiling(
            70_000,
            &[widest(40_000), widest(40_000)],
            &then_true(OP_ADD),
        ),
        160_000,
    );
    assert!(message.ends_with("the allocator refused the 160000 bytes OP_ADD's step may need, from operands of 40000 and 40000 bytes."), "{message}");
    let message = refused(
        under_ceiling(70_000, &[widest(40_000)], &then_true(OP_1ADD)),
        80_000,
    );
    assert!(message.ends_with("the allocator refused the 80000 bytes OP_1ADD's step may need, from an operand of 40000 bytes."), "{message}");
}

/// The steps above under a ceiling that grants them: computed, not declined.
#[test]
fn a_step_the_allocator_grants_is_computed() {
    let operands = [widest(40_000), widest(40_000)];
    for opcode in [OP_MUL, OP_DIV, OP_MOD, OP_ADD] {
        let verdict = under_ceiling(1_000_000, &operands, &then_true(opcode));
        assert_eq!(verdict.map_err(|e| e.message), Ok(true));
    }
}

/// A number read outside the arithmetic opcodes (`OP_WITHIN`'s three) asks
/// the allocator for its digits first: 50,000 bytes read as 75,008, refused
/// under a ceiling of 70,000.
#[test]
fn a_number_read_the_allocator_refuses_is_a_decline() {
    let operand = widest(50_000);
    let message = refused(
        under_ceiling(
            70_000,
            &[operand.clone(), operand.clone(), operand],
            &then_true(OP_WITHIN),
        ),
        75_008,
    );
    assert_eq!(message, "Stack memory usage has exceeded 0 bytes");
}

/// `OP_LSHIFTNUM` of 1 by 320,000 bits: a result of 40,001 bytes, its digits
/// and its encoding asked first (80,020 bytes), refused under 70,000.
#[test]
fn a_left_shift_the_allocator_refuses_is_a_decline() {
    let message = refused(
        under_ceiling(70_000, &[vec![1], encode(320_000)], &then_true(OP_NOP7)),
        80_020,
    );
    assert_eq!(message, "Stack memory usage has exceeded 0 bytes");
}

/// `n` as a minimal script number.
fn encode(n: i64) -> Vec<u8> {
    crate::script::script_num::ScriptNum::to_bytes(&crate::primitives::BigNumber::from_i64(n))
}

/// The review's three scripts (PR #370, fold 2), by hand: an operand of `len`
/// bytes made by `OP_NUM2BIN` and `OP_INVERT` (`fe ff .. ff`), then `tail`,
/// under the modelled allocator at the review's 4 GiB less the operands the
/// stack holds at the step (the review's allocator counts everything held).
/// Without the step's probe each aborted under the review's allocator (exit
/// 134); the real ceiling's reproduction is the review's harness.
fn review_script(len: u32, tail: &[u8], held: usize) -> Result<bool, ScriptEvaluationError> {
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_bin(&len.to_le_bytes())
        .write_opcode(OP_NUM2BIN)
        .write_opcode(OP_INVERT);
    for &opcode in tail {
        lock.write_opcode(opcode);
    }
    lock.write_opcode(OP_DROP).write_opcode(OP_1);
    under_ceiling((4usize << 30) - held, &[], &lock)
}

/// `OP_1 <2^29> OP_NUM2BIN OP_INVERT OP_DUP OP_ADD`: 1 GiB held, the step's
/// 2 GiB granted, the sum computed (about 1.3 s, 2.1 GB resident).
#[test]
#[ignore = "by hand: about 2 GB resident"]
fn the_reviews_sum_of_two_half_gib_operands_is_computed_under_4_gib() {
    let verdict = review_script(1 << 29, &[OP_DUP, OP_ADD], 1 << 30);
    assert_eq!(verdict.map_err(|e| e.message), Ok(true));
}

/// `OP_MUL` of two 300 MiB operands: 600 MiB held, the step's 3,774,873,600
/// bytes refused, a decline before either operand is decoded.
#[test]
#[ignore = "by hand: about 630 MB resident"]
fn the_reviews_product_of_two_300_mib_operands_is_declined_under_4_gib() {
    let len = 300 << 20;
    let message = refused(
        review_script(len, &[OP_DUP, OP_MUL], 2 * len as usize),
        3_774_873_600,
    );
    assert!(message.ends_with("the allocator refused the 3774873600 bytes OP_MUL's step may need, from operands of 314572800 and 314572800 bytes."), "{message}");
}

/// `OP_1ADD` of an operand 16 bytes under 1 GiB: 1 GiB held, the step's
/// 2 GiB granted, computed (about 1.4 s, 2.1 GB resident).
#[test]
#[ignore = "by hand: about 2 GB resident"]
fn the_reviews_increment_near_1_gib_is_computed_under_4_gib() {
    let len = (1 << 30) - 16;
    let verdict = review_script(len, &[OP_1ADD], len as usize);
    assert_eq!(verdict.map_err(|e| e.message), Ok(true));
}
