//! The default mode runs uncapped without a caller's budget, as the
//! reference's `Spend` does (bsv-rs#331, the keeper's ruling of 2026-10-27):
//! `SpendParams::memory_limit: None` is `Number.POSITIVE_INFINITY` there
//! (`ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts:295-296`,
//! `hasExplicitMemoryLimit`). Until #331 this crate's `None` read 32,000,000
//! bytes per stack in the default mode (the reference's `Spend` default until
//! `ts-stack@30210fe`), so a stack past it was a decline; a caller that wants
//! that figure passes `Some(32_000_000)`.
//!
//! Every row names what it allocates; the largest is 40 MB plus the script.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::evaluation_error::ScriptEvaluationError;
use bsv_rs::script::op::{OP_0, OP_1, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_NOP7, OP_NUM2BIN};
use bsv_rs::script::{
    LockingScript, Script, ScriptResource, ScriptResourceLimit, Spend, SpendParams, UnlockingScript,
};

const ELEMENT: usize = 1_000_000;

/// The figure the default mode's `None` read until bsv-rs#331, here a
/// caller's budget.
const BUDGET_32_000_000: Option<usize> = Some(32_000_000);

/// `unlock` then `lock` in the default mode (no flag word) at `version`,
/// under `memory_limit`.
fn spend(
    lock: &[u8],
    unlock: Script,
    version: i32,
    memory_limit: Option<usize>,
) -> Result<bool, Box<ScriptEvaluationError>> {
    let mut s = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_binary(lock).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit,
        work_limit: None,
    });
    s.validate().map_err(Box::new)
}

/// The decline a caller's budget gives, as `(resource, limit, attempted)`.
fn declined(result: Result<bool, Box<ScriptEvaluationError>>) -> ScriptResourceLimit {
    let error = result.expect_err("a decline");
    assert!(error.is_resource_limit(), "{}", error.message);
    error.resource_limit.unwrap()
}

/// A push of `ELEMENT` bytes of 0x01.
fn element_push() -> Script {
    let mut unlock = Script::new();
    unlock.write_bin(&vec![0x01; ELEMENT]);
    unlock
}

/// #38's shape: the element `OP_DUP`ed 32 times (33 copies, a main stack of
/// 33,000,000 bytes), the 32 duplicates dropped, then `tail`.
fn dup_lock(tail: &[u8]) -> Vec<u8> {
    let mut lock = vec![OP_DUP; 32];
    lock.extend(std::iter::repeat_n(OP_DROP, 32));
    lock.extend_from_slice(tail);
    lock
}

/// `OP_1 <40,000,000> OP_NUM2BIN OP_DROP OP_1`: one 40,000,000-byte element.
fn num2bin_40m_lock() -> Vec<u8> {
    let mut lock = Script::new();
    lock.write_opcode(OP_1)
        .write_bin(&40_000_000u32.to_le_bytes())
        .write_opcode(OP_NUM2BIN)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    lock.to_binary()
}

/// A stack grown past 32,000,000 bytes evaluates under `None`: the script
/// decides, valid here. Allocates 33 MB.
#[test]
fn a_default_mode_stack_past_32_000_000_bytes_is_valid_without_a_budget() {
    assert_eq!(
        spend(&dup_lock(&[]), element_push(), 1, None).map_err(|e| e.message),
        Ok(true)
    );
}

/// The same growth before an invalid tail is the script's verdict under
/// `None`, never a decline. Allocates 33 MB.
#[test]
fn a_default_mode_stack_past_32_000_000_bytes_is_judged_invalid_without_a_budget() {
    let error = spend(&dup_lock(&[OP_0, OP_EQUALVERIFY]), element_push(), 1, None)
        .expect_err("the script's verdict");
    assert!(!error.is_resource_limit(), "{}", error.message);
    assert_eq!(
        error.message,
        "OP_EQUALVERIFY requires the top two stack items to be equal."
    );
}

/// Under a caller's 32,000,000 bytes the 33rd copy declines, as `None` did
/// before bsv-rs#331. Allocates 32 MB.
#[test]
fn a_callers_32_000_000_bytes_decline_the_33rd_copy() {
    assert_eq!(
        declined(spend(&dup_lock(&[]), element_push(), 1, BUDGET_32_000_000)),
        ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: 32_000_000,
            attempted: 33_000_000,
            work_spent: None,
        }
    );
}

/// One 40,000,000-byte element (stack-00227's): valid under `None`, refused
/// before its allocation under a caller's 32,000,000 bytes. Allocates 40 MB.
#[test]
fn a_40_000_000_byte_element_is_valid_without_a_budget_and_declined_under_one() {
    assert_eq!(
        spend(&num2bin_40m_lock(), Script::new(), 2, None).map_err(|e| e.message),
        Ok(true)
    );
    assert_eq!(
        declined(spend(
            &num2bin_40m_lock(),
            Script::new(),
            2,
            BUDGET_32_000_000
        )),
        ScriptResourceLimit {
            resource: ScriptResource::ElementSize,
            limit: 32_000_000,
            attempted: 40_000_000,
            work_spent: None,
        }
    );
}

/// The review of PR #370 (review-331, its fourth note): uncapped, the numeric
/// left shift's 1 GiB element bound alone refuses a shift of 1 by 2^33 + 8
/// bits, a result of 2^30 + 2 bytes, before it allocates (about 0.01 s).
/// Without the bound (9df2f72's) the shift is computed and the script is
/// valid: about 1 GiB asked, 1.9 GB RSS and 63 s on the studio under lane
/// load (3.2 GB and 6.6 s on the review's host), so it runs by hand: `cargo test --test script_default_mode_uncapped_331 --
/// --ignored`. A version-2 spend: `OP_LSHIFTNUM` is a post-Chronicle opcode.
/// Since bsv-rs#383 the count, above `INT_MAX`, is refused first in the
/// reference's words (`Spend.ts:1058-1060`), before anything is sized: the
/// element bound is out of a shift's reach (536,870,888 bits read plus
/// `INT_MAX` is 335 MB).
#[test]
#[ignore = "by hand: its RED allocates about 3 GB"]
fn an_uncapped_left_shift_just_past_the_1_gib_element_bound_is_refused_before_it_allocates() {
    let mut lock = Script::new();
    lock.write_bin(&[0x08, 0x00, 0x00, 0x00, 0x02]); // 2^33 + 8, minimal
    let mut lock = lock.to_binary();
    lock.push(OP_NOP7);
    let mut unlock = Script::new();
    unlock.write_opcode(OP_1);
    let error = spend(&lock, unlock, 2, None).expect_err("the count's refusal");
    assert!(!error.is_resource_limit(), "{}", error.message);
    assert_eq!(error.message, "OP_LSHIFTNUM shift count exceeds INT_MAX.");
}
