#![cfg(test)]

//! The arithmetic step's room (bsv-rs#374) at a small scale: the allocator's
//! ceiling is this file's model ([`with_allocator_ceiling`]), so a step past it
//! declines on operands of a few hundred kilobytes, not gigabytes. The real
//! ceilings' safety (each measured peak below its declared room) is
//! `tests/memory_profiling.rs`'s, by hand.
//!
//! Each test drives the public `Spend` door and asserts that a step whose room
//! the modelled allocator refuses is a RESOURCE DECLINE
//! ([`ScriptResource::ElementSize`], `resource_limit` `Some`), never a verdict
//! and never an abort; and that an operand below the reservation floor is not
//! probed at all, so no honest script is touched.

use super::with_allocator_ceiling;
use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource};
use crate::script::op::{OP_1, OP_1ADD, OP_ADD, OP_BIN2NUM, OP_DIV, OP_DROP, OP_MOD, OP_MUL};
use crate::script::spend::{Spend, SpendParams};
use crate::script::{LockingScript, Script, UnlockingScript};

/// A script number of `len` bytes with the largest positive magnitude it can
/// hold (minimally encoded): `len * 8 - 1` bits.
fn widest(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xff; len];
    bytes[len - 1] = 0x7f;
    bytes
}

/// `operands` pushed by the unlocking script, then `lock` run under the
/// default mode with the modelled allocator refusing any reservation above
/// `ceiling`.
fn run(operands: &[Vec<u8>], lock: &Script, ceiling: usize) -> Result<bool, ScriptEvaluationError> {
    let mut unlock = Script::new();
    for operand in operands {
        unlock.write_bin(operand);
    }
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock.clone()),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    with_allocator_ceiling(ceiling, || spend.validate())
}

/// `opcode OP_DROP OP_1`.
fn then_true(opcode: u8) -> Script {
    let mut lock = Script::new();
    lock.write_opcode(opcode)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    lock
}

/// The decline a result is: a resource limit on `element-size`, never a
/// verdict (`resource_limit` `None`) and never a panic.
fn declined(result: Result<bool, ScriptEvaluationError>) -> ScriptEvaluationError {
    let error = result.expect_err("a decline, not a verdict or an abort");
    let limit = error
        .resource_limit
        .expect("a resource limit, not a verdict");
    assert_eq!(
        limit.resource,
        ScriptResource::ElementSize,
        "an arithmetic step's room is an element-size decline"
    );
    error
}

/// A ceiling well below any guarded step's peak but above the interpreter's
/// ordinary allocations, and operands far above [`RESERVATION_FLOOR`] so the
/// probe fires.
const CEILING: usize = 1 << 20; // 1 MiB
const BIG: usize = 300_000; // ~0.29 MiB, above the 64 KiB floor

#[test]
fn op_mul_declines_before_its_product_is_allocated() {
    // sum 600 KB, peak 8x = ~4.8 MB, above the 1 MiB ceiling.
    declined(run(
        &[widest(BIG), widest(BIG)],
        &then_true(OP_MUL),
        CEILING,
    ));
}

#[test]
fn op_div_declines_before_its_quotient_is_allocated() {
    // dividend big, divisor small; peak 12x the sum, above the ceiling.
    declined(run(&[widest(BIG), widest(64)], &then_true(OP_DIV), CEILING));
}

#[test]
fn op_mod_declines_before_its_remainder_is_allocated() {
    declined(run(&[widest(BIG), widest(64)], &then_true(OP_MOD), CEILING));
}

#[test]
fn op_add_declines_before_its_sum_is_allocated() {
    declined(run(
        &[widest(BIG), widest(BIG)],
        &then_true(OP_ADD),
        CEILING,
    ));
}

#[test]
fn op_1add_declines_before_its_result_is_allocated() {
    // unary: peak 6x the operand (~1.8 MB), above the ceiling.
    declined(run(&[widest(BIG)], &then_true(OP_1ADD), CEILING));
}

#[test]
fn op_bin2num_declines_before_its_re_encoding_is_allocated() {
    declined(run(&[widest(BIG)], &then_true(OP_BIN2NUM), CEILING));
}

#[test]
fn a_decline_carries_the_sizes_and_the_budget_not_a_script_verdict() {
    let error = declined(run(
        &[widest(BIG), widest(BIG)],
        &then_true(OP_MUL),
        CEILING,
    ));
    assert!(
        error.message.contains("allocation declined") && error.message.contains("OP_MUL"),
        "the decline names the step and that it is an allocation refusal: {}",
        error.message
    );
    // The default-mode budget, not a configured small one.
    assert_eq!(error.resource_limit.unwrap().limit, 32_000_000);
}

/// Ruling 2 (fold-m1118b): each `STEP_PEAK_*` ceiling is pinned so a reduction
/// turns this RED by name. The modelled allocator refuses one byte below the
/// room the SHIPPED multiple reserves (`shipped * operands - 1`), so the step
/// declines only while the ceiling reserves at or above the shipped multiple.
/// A reduction of `STEP_PEAK_*` (e.g. the suite-passing `OP_MUL` 8->2,
/// `OP_DIV` 12->4, the linear 6->4 a read showed reintroduced the uncatchable
/// abort) drops the probe below this ceiling: the step then proceeds and the
/// real arithmetic completes with a verdict, where this asserts a decline. The
/// shipped multiples are proven at or above the measured true peak (worst-case
/// operands, probe disabled) by `tests/memory_profiling.rs`, so the pin holds
/// the ceiling between the true cost and the shipped value, both ways.
fn pinned_at_shipped(opcode: u8, operands: &[Vec<u8>], shipped: usize) {
    let sum: usize = operands.iter().map(Vec::len).sum();
    declined(run(operands, &then_true(opcode), shipped * sum - 1));
}

#[test]
fn op_mul_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_MUL, &[widest(BIG), widest(BIG)], 8);
}

#[test]
fn op_div_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_DIV, &[widest(BIG), widest(64)], 12);
}

#[test]
fn op_mod_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_MOD, &[widest(BIG), widest(64)], 12);
}

#[test]
fn op_add_linear_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_ADD, &[widest(BIG), widest(BIG)], 6);
}

#[test]
fn op_1add_linear_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_1ADD, &[widest(BIG)], 6);
}

#[test]
fn op_bin2num_linear_ceiling_is_pinned_a_reduction_turns_this_red() {
    pinned_at_shipped(OP_BIN2NUM, &[widest(BIG)], 6);
}

#[test]
fn an_operand_below_the_floor_is_not_probed_so_an_honest_script_is_untouched() {
    // Two tiny operands multiplied: step peak far below the reservation floor,
    // so the probe is skipped even under a ceiling of zero bytes. 7 * 6 = 42.
    let out = run(
        &[vec![7], vec![6]],
        &{
            let mut lock = Script::new();
            lock.write_opcode(OP_MUL);
            lock.write_bin(&[42]);
            lock.write_opcode(crate::script::op::OP_EQUAL);
            lock
        },
        0,
    );
    assert!(
        out.expect("an honest multiply is never probed"),
        "an honest multiply must validate"
    );
}
