//! The room an arithmetic step needs, asked of the allocator before the step
//! (bsv-rs#374).
//!
//! `BigNumber`'s operations allocate infallibly (num-bigint has no fallible
//! form), so a real out-of-memory at the arithmetic site is an uncatchable
//! process abort — on `wasm32` one nobody catches (`CLAUDE.md` rule 5). Before
//! an arithmetic step the allocator is asked with `try_reserve_exact`, then
//! released, for the most the step holds past its operands' own bytes
//! ([`step_peak`], a multiple of their lengths: the operands decoded, the
//! arithmetic's scratch, the result and its encoding). Its refusal is a decline
//! ([`ScriptResource::ElementSize`]), never an abort, and never read as a
//! verdict on the script ([`Error::ScriptEvaluationDeclined`](crate::Error);
//! bsv-rs#38). An honest (policy-valid, ≤10 KB-operand) script's heaviest
//! two-operand step reaches a few hundred kilobytes, above
//! [`RESERVATION_FLOOR`]: the probe may fire, but its reservation is a fraction
//! of a megabyte and is granted on any viable host, so no honest answer moves.
//!
//! The multiples ([`STEP_PEAK_MUL`], [`STEP_PEAK_DIV`], [`STEP_PEAK_LINEAR`])
//! are ceilings measured on this line's `BigNumber` arithmetic by
//! `tests/memory_profiling.rs`
//! (`test_each_arithmetic_steps_peak_is_within_the_room_its_guard_asks`): over
//! the operands' combined bytes `OP_MUL` holds at most ~4.9 times (num-bigint's
//! Toom/Karatsuba scratch, the product and its encoding), `OP_DIV`/`OP_MOD`
//! ~7.6 (Burnikel-Ziegler padding), and the linear kinds ~3.5 (the operands
//! decoded, the result and its encoding). Each ceiling sits above its measured
//! peak with margin, so the probe refuses before the step's own allocation
//! would abort; a ceiling above the true peak only ever declines earlier, never
//! aborts later.
//!
//! This is the 0.9 line's guard (bsv-rs#374/#348) ported to the stable line's
//! single interpreter file, probe only: the 0.9 line's reference-read verdict
//! (a magnitude past 536,870,888 bits judged invalid, bsv-rs#331) does not
//! travel with it, so a result this line cannot hold stays a decline where that
//! line reports a verdict.

use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::op::{opcode_to_name, OP_DIV, OP_MOD, OP_MUL};

use super::Spend;
#[cfg(test)]
use std::cell::Cell;
use std::collections::TryReserveError;

/// A step of fewer bytes than this is not asked of the allocator ahead of the
/// arithmetic: the interpreter's other allocations are of its order. The unary
/// kinds and a single small operand stay below the floor; a policy-valid
/// two-operand step can reach a few hundred kilobytes, above it, so the probe
/// fires there but its reservation is always granted, and no honest answer
/// moves.
pub(super) const RESERVATION_FLOOR: u64 = 1 << 16;

/// `OP_MUL`, `OP_2MUL`: the product's digits (both operands' length together)
/// and num-bigint's Toom/Karatsuba scratch, the result and its encoding;
/// measured at most ~4.9 times the operands' combined bytes on this line.
pub(super) const STEP_PEAK_MUL: u64 = 8;
/// `OP_DIV`, `OP_MOD`: num-bigint's Burnikel-Ziegler division, which pads the
/// dividend to a power of two of digits and recurses on copies of those
/// blocks; measured at most ~7.6 times the operands' combined bytes.
pub(super) const STEP_PEAK_DIV: u64 = 12;
/// Every other guarded step (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`,
/// `OP_2DIV`, `OP_NEGATE`, `OP_ABS`, the comparisons and `OP_BIN2NUM`): the
/// operands decoded, a result at most one byte longer than the longest, and
/// its encoding; measured at most ~3.5 times the operands' combined bytes.
pub(super) const STEP_PEAK_LINEAR: u64 = 6;

impl Spend {
    /// Asks the allocator for the room `opcode`'s step needs past `operands`
    /// (in stack order), before any is decoded, and gives it back at once; its
    /// refusal is [`room_refused`](Self::room_refused), a decline, where the
    /// step's own infallible `BigNumber` allocation would abort. A step below
    /// [`RESERVATION_FLOOR`] is not probed.
    pub(super) fn arithmetic_room(
        &self,
        opcode: u8,
        operands: &[&[u8]],
    ) -> Result<(), ScriptEvaluationError> {
        let lens: Vec<usize> = operands.iter().map(|o| o.len()).collect();
        let peak = step_peak(opcode, &lens);
        if peak >= RESERVATION_FLOOR {
            let room = usize::try_from(peak).unwrap_or(usize::MAX);
            reserve(room).map_err(|_| self.room_refused(opcode, &lens, peak))?;
        }
        Ok(())
    }

    /// The allocator's refusal of the `peak` bytes `opcode`'s step may need: a
    /// resource decline ([`ScriptResource::ElementSize`]) carrying the budget
    /// in force and the sizes, so a caller tells it from a verdict and knows
    /// what to bound ([`memory_limit`](Self::memory_limit)).
    fn room_refused(&self, opcode: u8, operands: &[usize], peak: u64) -> ScriptEvaluationError {
        let name = opcode_to_name(opcode).unwrap_or("OP");
        let limit = self.memory_limit();
        self.error(&format!(
            "Script element allocation declined: {name}'s step may need {peak} bytes the \
             allocator could not provide, from {}; the memory budget is {limit} bytes.",
            describe(operands)
        ))
        .with_resource_limit(ScriptResourceLimit {
            resource: ScriptResource::ElementSize,
            limit: limit as u64,
            attempted: peak,
            work_spent: None,
        })
    }
}

/// `operands of A and B bytes`, or `an operand of A bytes`.
fn describe(operands: &[usize]) -> String {
    match operands {
        [one] => format!("an operand of {one} bytes"),
        _ => {
            let lens: Vec<String> = operands.iter().map(usize::to_string).collect();
            format!("operands of {} bytes", lens.join(" and "))
        }
    }
}

/// The most bytes `opcode`'s step holds past its operands' own, from their
/// lengths: a multiple of their sum (`STEP_PEAK_*`), saturating.
fn step_peak(opcode: u8, lens: &[usize]) -> u64 {
    let total: u64 = lens.iter().map(|&len| len as u64).sum();
    let multiple = match opcode {
        OP_MUL | crate::script::op::OP_2MUL => STEP_PEAK_MUL,
        OP_DIV | OP_MOD => STEP_PEAK_DIV,
        _ => STEP_PEAK_LINEAR,
    };
    total.saturating_mul(multiple)
}

/// Asks the allocator for `len` bytes and gives them back: num-bigint's own
/// allocations are infallible, so the room is asked of the allocator first,
/// and its refusal is a decline where the arithmetic's would be an abort.
/// Never inlined, so the frame keeps its name in the symbol table.
#[cfg(not(test))]
#[inline(never)]
fn reserve(len: usize) -> Result<(), TryReserveError> {
    Vec::<u8>::new().try_reserve_exact(len)
}

#[cfg(test)]
thread_local! {
    /// The unit tests' model of an allocator that refuses more than this, so a
    /// step past it declines without the test holding gigabytes.
    static ALLOCATOR_CEILING: Cell<usize> = const { Cell::new(usize::MAX) };
}

#[cfg(test)]
fn reserve(len: usize) -> Result<(), TryReserveError> {
    let asked = if len > ALLOCATOR_CEILING.with(Cell::get) {
        usize::MAX
    } else {
        len
    };
    Vec::<u8>::new().try_reserve_exact(asked)
}

/// Test-only (crate-internal): runs `f` with the modelled allocator refusing
/// any single reservation above `ceiling` bytes, so a door test can see a
/// step's reservation decline without a host-wide memory limit. The ceiling is
/// restored to [`usize::MAX`] after `f` returns.
#[cfg(test)]
pub(crate) fn with_allocator_ceiling<T>(ceiling: usize, f: impl FnOnce() -> T) -> T {
    ALLOCATOR_CEILING.with(|c| c.set(ceiling));
    let out = f();
    ALLOCATOR_CEILING.with(|c| c.set(usize::MAX));
    out
}

#[cfg(test)]
#[path = "arithmetic_room_tests.rs"]
mod tests;
