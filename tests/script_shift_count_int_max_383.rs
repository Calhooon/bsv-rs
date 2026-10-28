//! The default mode's shift count, the reference's (bsv-rs#383, the owner's
//! ruling (c)): `OP_LSHIFTNUM` and `OP_RSHIFTNUM` read the count, refuse a
//! negative one, then refuse one above `INT_MAX` before the value is read,
//! `<name> shift count exceeds INT_MAX.` (`ts-stack@edf6e03`
//! `Spend.ts:1058-1060`, `1084-1086`; run under Node 22.18.0), a verdict in
//! every case and never a decline: no shift is computed, nothing is
//! allocated. Until #383 the default mode shifted by any count: `1 <2^31>
//! OP_RSHIFTNUM` was 0, a valid spend, and `1 <2^31> OP_LSHIFTNUM` was
//! refused in V8's `BigInt` words, or declined under a caller's budget.
//!
//! Under a word nothing moves: the node refuses the count in `bint`'s shift,
//! after the value's read and a left shift's size test (`big_int.cpp:359-369`,
//! `383-393`; `SCRIPT_ERR_BIG_INT`, `interpreter.cpp:1819-1821` at v1.2.2),
//! pinned by `tests/script_shift_count_witness.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{OP_1, OP_DROP, OP_NOP7, OP_NOP8};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptEvaluationError, ScriptFlags, Spend, SpendParams,
    UnlockingScript,
};

/// `operands` pushed, then `opcode OP_DROP OP_1`, at version 2 (a coin
/// after Chronicle in the default mode), under `word` if given and the
/// caller's `budget`.
fn run(
    operands: &[&[u8]],
    opcode: u8,
    word: Option<ScriptFlags>,
    budget: Option<usize>,
) -> Result<bool, Box<ScriptEvaluationError>> {
    let mut unlock = Script::new();
    for operand in operands {
        unlock.write_bin(operand);
    }
    let mut lock = Script::new();
    lock.write_opcode(opcode)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
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

/// The reference's verdict in its words, not a decline.
fn exceeds_int_max(result: Result<bool, Box<ScriptEvaluationError>>, name: &str) {
    let error = result.expect_err("the reference's verdict");
    assert!(!error.is_resource_limit(), "a verdict, not a decline");
    assert_eq!(
        error.message,
        format!("{name} shift count exceeds INT_MAX.")
    );
}

/// 2^31, `INT_MAX + 1`, as a minimal script number.
const INT_MAX_PLUS_ONE: &[u8] = &[0x00, 0x00, 0x00, 0x80, 0x00];
/// `INT_MAX` as a minimal script number.
const INT_MAX: &[u8] = &[0xff, 0xff, 0xff, 0x7f];

/// `1 <2^31> OP_RSHIFTNUM`: the issue's example, valid here until #383
/// (the shift was 0), invalid in the reference.
#[test]
fn a_right_shift_by_a_count_above_int_max_is_invalid_as_the_reference_reads_it() {
    exceeds_int_max(
        run(&[&[1], INT_MAX_PLUS_ONE], OP_NOP8, None, None),
        "OP_RSHIFTNUM",
    );
    exceeds_int_max(
        run(&[&[], INT_MAX_PLUS_ONE], OP_NOP8, None, None),
        "OP_RSHIFTNUM",
    );
    exceeds_int_max(
        run(&[&[0x81], INT_MAX_PLUS_ONE], OP_NOP8, None, None),
        "OP_RSHIFTNUM",
    );
}

/// `1 <2^31> OP_LSHIFTNUM` and `0 <2^31>`: the count's refusal comes before
/// the value is read, so a zero value (valid here until #383) and a nonzero
/// one (V8's `BigInt` words here until #383) are refused alike.
#[test]
fn a_left_shift_by_a_count_above_int_max_is_invalid() {
    exceeds_int_max(
        run(&[&[1], INT_MAX_PLUS_ONE], OP_NOP7, None, None),
        "OP_LSHIFTNUM",
    );
    exceeds_int_max(
        run(&[&[], INT_MAX_PLUS_ONE], OP_NOP7, None, None),
        "OP_LSHIFTNUM",
    );
}

/// The order: a value of 67,108,863 bytes (its magnitude 536,870,897 bits,
/// past the reference's read, `Invalid string length` with a count of 1)
/// and a count above `INT_MAX`: the count's refusal comes first, in its
/// words, as the reference checks the count before it pops the value
/// (`Spend.ts:1058-1061`, `1084-1087`). With the check after the read the
/// value's words would win.
#[test]
fn a_count_above_int_max_is_refused_before_an_unreadable_value_is_read() {
    let mut value = vec![0u8; 67_108_862];
    value.push(1);
    for (opcode, name) in [(OP_NOP7, "OP_LSHIFTNUM"), (OP_NOP8, "OP_RSHIFTNUM")] {
        let error = run(&[&value, &[1]], opcode, None, None).expect_err("the value unreadable");
        assert_eq!(error.message, "Invalid string length", "{name}");
        exceeds_int_max(run(&[&value, INT_MAX_PLUS_ONE], opcode, None, None), name);
    }
}

/// A caller's budget does not turn the count's refusal into a decline: the
/// reference's check is before any shift, so nothing is sized (a 268 MB
/// result declined under 1,000 bytes until #383).
#[test]
fn under_a_budget_a_count_above_int_max_is_a_verdict_not_a_decline() {
    exceeds_int_max(
        run(&[&[1], INT_MAX_PLUS_ONE], OP_NOP7, None, Some(1000)),
        "OP_LSHIFTNUM",
    );
    exceeds_int_max(
        run(&[&[1], INT_MAX_PLUS_ONE], OP_NOP8, None, Some(1000)),
        "OP_RSHIFTNUM",
    );
}

/// A count of 2^64 and one of 100 bytes: the same words, the count's value
/// written nowhere.
#[test]
fn a_count_of_any_size_above_int_max_is_refused_in_the_same_words() {
    let two_pow_64: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut hundred = vec![0xff; 99];
    hundred.push(0x7f);
    exceeds_int_max(
        run(&[&[1], two_pow_64], OP_NOP8, None, None),
        "OP_RSHIFTNUM",
    );
    exceeds_int_max(run(&[&[1], &hundred], OP_NOP7, None, None), "OP_LSHIFTNUM");
}

/// At `INT_MAX` the count is read on: `1 >> INT_MAX` is 0, valid, as the
/// reference answers.
#[test]
fn a_right_shift_by_int_max_is_still_valid() {
    assert_eq!(
        run(&[&[1], INT_MAX], OP_NOP8, None, None).map_err(|e| e.message),
        Ok(true)
    );
}

/// Under a word the node's reading is unchanged: the right shift's count is
/// `bint`'s `big_int_error`, in this crate's words.
#[test]
fn under_a_word_the_count_is_the_nodes_big_int_error() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let error =
        run(&[&[1], INT_MAX_PLUS_ONE], OP_NOP8, Some(word), None).expect_err("the node's verdict");
    assert!(!error.is_resource_limit());
    assert_eq!(
        error.message,
        "OP_RSHIFTNUM count (2147483648) does not fit an int."
    );
}
