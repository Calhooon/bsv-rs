//! The default mode's read limit, the reference's (bsv-rs#331, the keeper's
//! word of 2026-10-27): an operand whose magnitude passes 536,870,888 bits,
//! V8's longest string, fails at the reference's read under Node 22
//! (`ts-stack@edf6e03` `BigNumber.ts:450`, `toString(2)`), rethrown by
//! `#readScriptNumber` as a script error (`Spend.ts:525-535`), and is invalid
//! here in the default mode with its words; one at the figure is read. A
//! result past the figure is invalid at its push in the same words where the
//! reference builds it through `toString(2)` (the keeper's word of
//! 2026-10-27, 21:5xZ): `OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`
//! (`BigNumber.ts:771-781`, `#_setValueFromSigned`) and `OP_LSHIFTNUM`
//! (`Spend.ts:1066`), where the reference's `RangeError` escapes its
//! `verify`; `OP_2MUL`'s, which the reference's `mul` builds without a
//! string, is pushed. A shift's result past 2^30 bits is invalid in the
//! words of V8's `BigInt` cap, `Maximum BigInt size exceeded`, which the
//! reference's shift throws before its string. Under a word the node's number
//! length decides
//! (32,000,000 bytes after Chronicle). By hand: each operand is 64 MiB, the
//! file 0.63 s and 1.01 GB resident in release under `--test-threads=1`
//! (measured on the test binary alone; the figure holds one test at a time,
//! the sum's operands and their copies at the peak; before the results'
//! tests, four, 472 MB, and the default threads 1.68 GB in the re-review).
//! The shifts' refusals allocate nothing and run with the suite.
//!
//! `cargo test --release --test script_reference_read_limit_331 -- --ignored --test-threads=1`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{
    OP_1, OP_1ADD, OP_1SUB, OP_2MUL, OP_ADD, OP_DROP, OP_DUP, OP_NOP7, OP_SUB,
};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptEvaluationError, ScriptFlags, ScriptResource, Spend,
    SpendParams, UnlockingScript,
};

/// `operands` pushed, then `opcodes OP_DROP OP_1`, at version 2, under
/// `word` if given and the caller's `budget` (the error boxed: it carries
/// the stacks).
fn run(
    operands: &[&[u8]],
    opcodes: &[u8],
    word: Option<ScriptFlags>,
    budget: Option<usize>,
) -> Result<bool, Box<ScriptEvaluationError>> {
    let mut unlock = Script::new();
    for operand in operands {
        unlock.write_bin(operand);
    }
    let mut lock = Script::new();
    for &opcode in opcodes {
        lock.write_opcode(opcode);
    }
    lock.write_opcode(OP_DROP).write_opcode(OP_1);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: budget,
        work_limit: None,
    });
    if let Some(word) = word {
        spend.set_flags(word);
    }
    spend.validate().map_err(Box::new)
}

/// `operand OP_1ADD OP_DROP OP_1` in the default mode, or under `word`.
fn increment(
    operand: &[u8],
    word: Option<ScriptFlags>,
) -> Result<bool, Box<ScriptEvaluationError>> {
    run(&[operand], &[OP_1ADD], word, None)
}

/// 67,108,861 bytes of `ff` and a sign byte: 536,870,888 bits, read.
fn at_the_limit() -> Vec<u8> {
    let mut bytes = vec![0xff; 67_108_862];
    bytes[67_108_861] = 0x00;
    bytes
}

/// [`at_the_limit`] negated: the sign byte `80`.
fn at_the_negative_limit() -> Vec<u8> {
    let mut bytes = at_the_limit();
    bytes[67_108_861] = 0x80;
    bytes
}

/// The reference's verdict: its words, no resource limit.
fn invalid(result: Result<bool, Box<ScriptEvaluationError>>) {
    let error = result.expect_err("the reference's verdict");
    assert!(!error.is_resource_limit(), "a verdict, not a decline");
    assert_eq!(error.message, "Invalid string length");
}

/// `n` as a minimal script number.
fn encode(n: u32) -> Vec<u8> {
    let mut bytes = n.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(0);
    }
    bytes
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn an_operand_of_67_108_863_bytes_is_invalid_with_the_references_words() {
    let mut operand = vec![0xff; 67_108_863];
    operand[67_108_862] = 0x7f;
    invalid(increment(&operand, None));
}

/// The read at the figure: the negative operand's increment shrinks its
/// magnitude, `true` in the reference too (the re-review ran it).
#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn an_operand_of_67_108_862_bytes_at_536_870_888_bits_is_read() {
    assert_eq!(
        increment(&at_the_negative_limit(), None).map_err(|e| e.message),
        Ok(true)
    );
}

/// `OP_1ADD` of the operand at the figure is 2^536870888, a bit past it: the
/// reference's `add` throws (`BigNumber.ts:912-915`, `:771-781`), and the
/// push is invalid here in its words (`Ok(true)` before the keeper's word).
#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn an_increment_past_536_870_888_bits_is_invalid_at_its_push() {
    invalid(increment(&at_the_limit(), None));
}

/// `OP_ADD` and `OP_SUB` of two operands at the figure, and `OP_1SUB` of the
/// negative one: each result a bit past it, invalid at its push.
#[test]
#[ignore = "by hand: two 64 MiB operands"]
fn a_sum_or_difference_past_536_870_888_bits_is_invalid_at_its_push() {
    let (positive, negative) = (at_the_limit(), at_the_negative_limit());
    invalid(run(&[&positive], &[OP_DUP, OP_ADD], None, None));
    invalid(run(&[&negative, &positive], &[OP_SUB], None, None));
    invalid(run(&[&negative], &[OP_1SUB], None, None));
}

/// `OP_2MUL` of the operand at the figure: the reference's `mul` builds the
/// product without a string (`BigNumber.ts:926-933`) and pushes it, `true`
/// there (the re-review ran it), and here.
#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn a_doubling_past_536_870_888_bits_is_pushed_as_the_references_mul_pushes_it() {
    assert_eq!(
        run(&[&at_the_limit()], &[OP_2MUL], None, None).map_err(|e| e.message),
        Ok(true)
    );
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn a_536_870_889th_bit_in_67_108_862_bytes_is_invalid() {
    let mut operand = at_the_limit();
    operand[67_108_861] = 0x01;
    invalid(increment(&operand, None));
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn under_a_word_the_nodes_number_length_decides() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let error = increment(&at_the_limit(), Some(word)).expect_err("the node's overflow");
    assert_eq!(
        error.message,
        "Script number overflow: 67108862 bytes, the limit is 32000000 bytes."
    );
}

/// `1 <536,870,888> OP_LSHIFTNUM` is 2^536870888: the reference's
/// `new BigNumber(value << bits)` throws (`Spend.ts:1066`, 6 ms in the
/// re-review), and the shift is invalid here in its words before it
/// allocates.
#[test]
fn a_left_shift_past_536_870_888_bits_is_invalid_before_it_allocates() {
    invalid(run(&[&[1], &encode(536_870_888)], &[OP_NOP7], None, None));
}

/// `1 <536,870,887> OP_LSHIFTNUM`, at the figure: pushed.
#[test]
#[ignore = "by hand: a 64 MiB result"]
fn a_left_shift_to_536_870_888_bits_is_pushed() {
    assert_eq!(
        run(&[&[1], &encode(536_870_887)], &[OP_NOP7], None, None).map_err(|e| e.message),
        Ok(true)
    );
}

/// Under a caller's budget the budget's decline comes before the verdict: a
/// 100-byte element beside the 67,108,862-byte result passes a budget of
/// 67,108,870 bytes per stack, declined, never read as invalid (#38); the
/// same budget with nothing beside it admits the push, and the verdict is
/// the reference's.
#[test]
fn under_a_budget_the_budgets_decline_precedes_the_shifts_verdict() {
    let count = encode(536_870_888);
    let budget = Some(67_108_870);
    let error = run(&[&[7; 100], &[1], &count], &[OP_NOP7], None, budget)
        .expect_err("the budget's decline");
    let limit = error.resource_limit.expect("a decline");
    assert_eq!(
        (limit.resource, limit.limit, limit.attempted),
        (ScriptResource::Stack, 67_108_870, 67_108_962)
    );
    invalid(run(&[&[1], &count], &[OP_NOP7], None, budget));
}

/// The reference's other words for a shift: `value << bits` is a `BigInt`
/// before any string is written, and V8 caps a `BigInt` at 2^30 bits of
/// magnitude (`BigInt::kMaxLengthBits` on a 64-bit host); past it the shift
/// throws `RangeError: Maximum BigInt size exceeded`, at or under it the
/// constructor's `toString(2)` throws `Invalid string length` (`ts-stack@edf6e03`
/// `Spend.ts:1066`, Node 22.18.0).
fn invalid_bigint(result: Result<bool, Box<ScriptEvaluationError>>) {
    let error = result.expect_err("the reference's verdict");
    assert!(!error.is_resource_limit(), "a verdict, not a decline");
    assert_eq!(error.message, "Maximum BigInt size exceeded");
}

/// `1 <2^30 - 1> OP_LSHIFTNUM` is 2^30 bits of magnitude: the reference
/// builds the `BigInt` and its string throws, `Invalid string length`;
/// `-1` the same (sign and magnitude).
#[test]
fn a_left_shift_to_2_pow_30_bits_is_invalid_at_the_string() {
    let count = encode((1 << 30) - 1);
    invalid(run(&[&[1], &count], &[OP_NOP7], None, None));
    invalid(run(&[&[0x81], &count], &[OP_NOP7], None, None));
}

/// `1 <2^30> OP_LSHIFTNUM`, `-1 <2^30>`, `3 <2^30 - 1>` and `1 <INT_MAX>` pass
/// 2^30 bits: the reference's shift throws `Maximum BigInt size exceeded`
/// before any string, and the shift is invalid here in those words before
/// it allocates.
#[test]
fn a_left_shift_past_2_pow_30_bits_is_invalid_with_the_bigint_words() {
    invalid_bigint(run(&[&[1], &encode(1 << 30)], &[OP_NOP7], None, None));
    invalid_bigint(run(&[&[0x81], &encode(1 << 30)], &[OP_NOP7], None, None));
    invalid_bigint(run(&[&[3], &encode((1 << 30) - 1)], &[OP_NOP7], None, None));
    invalid_bigint(run(
        &[&[1], &encode(i32::MAX as u32)],
        &[OP_NOP7],
        None,
        None,
    ));
}

/// Past 2^30 bits too a caller's budget declines first: a 134,217,729-byte
/// result passes a budget of 100,000,000 bytes per stack, declined; under
/// 200,000,000 the verdict is the reference's.
#[test]
fn under_a_budget_the_budgets_decline_precedes_the_bigint_verdict() {
    let error = run(
        &[&[1], &encode(1 << 30)],
        &[OP_NOP7],
        None,
        Some(100_000_000),
    )
    .expect_err("the budget's decline");
    assert!(error.is_resource_limit(), "a decline: {}", error.message);
    invalid_bigint(run(
        &[&[1], &encode(1 << 30)],
        &[OP_NOP7],
        None,
        Some(200_000_000),
    ));
}
