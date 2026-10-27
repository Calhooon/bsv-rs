//! The room an arithmetic result needs, judged before it is allocated
//! (bsv-rs#374). `BigNumber`'s operations allocate infallibly (num-bigint has
//! no fallible form), and `OP_MUL`'s result is as long as its two operands
//! together: uncapped (the default mode's `memory_limit: None`, bsv-rs#331)
//! two operands near the 1 GiB element bound ask about 2 GiB, which an
//! allocator that refuses it turns into an abort (on `wasm32` one nobody
//! catches). Every other arithmetic result is at most one byte longer than
//! its longest operand (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`, `OP_2MUL`)
//! or no longer (`OP_DIV`, `OP_MOD`, `OP_2DIV`, `OP_NEGATE`, `OP_ABS`,
//! `OP_MIN`, `OP_MAX`, the booleans and comparisons).
//!
//! Before an operand is decoded: the operands' encodings are judged as the
//! reads judge them (their verdicts first), then, in the default mode, a
//! result whose least possible length passes the element bound is declined
//! from the operands' bytes alone, and in every mode the allocator is asked
//! for the result's greatest possible length with `try_reserve_exact`, its
//! refusal a decline. After the arithmetic the default mode declines a result
//! longer than the bound by its exact length (at most two bytes past it).
//! Under a word the element bound does not apply (an element after Genesis is
//! bounded by the stack memory budget alone, `src/consensus/consensus.h:81-82`):
//! the number-length limit bounds every operand at its read and the node's
//! overflow test follows the arithmetic (`script_num.cpp:164`, `194`, `214`).

use crate::primitives::BigNumber;
use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::op::{opcode_to_name, OP_1ADD, OP_1SUB, OP_2MUL, OP_ADD, OP_MUL, OP_SUB};
use crate::script::script_num::ScriptNum;

use super::limits::MAX_SCRIPT_ELEMENT_SIZE;
use super::Spend;
#[cfg(test)]
use std::cell::Cell;
use std::collections::TryReserveError;

/// A result of fewer bytes than this is not asked of the allocator ahead of
/// the arithmetic: the step's other allocations are of its order.
const RESERVATION_FLOOR: u64 = 1 << 16;

impl Spend {
    /// Room for `opcode`'s result on `operands` (in the order the opcode reads
    /// them), before any is decoded.
    pub(super) fn arithmetic_room(
        &self,
        opcode: u8,
        operands: &[&[u8]],
    ) -> Result<(), ScriptEvaluationError> {
        for operand in operands {
            self.check_number(operand)?;
        }
        let bits: Vec<u64> = operands.iter().map(|o| magnitude_bits(o)).collect();
        if self.flags.is_none() {
            let least = encoded_len(least_result_bits(opcode, &bits));
            if least > element_bound() as u64 {
                return Err(self.result_declined(opcode, operands, least, "at least "));
            }
        }
        let most = encoded_len(most_result_bits(opcode, &bits));
        if most >= RESERVATION_FLOOR {
            let room = usize::try_from(most).unwrap_or(usize::MAX);
            reserve(room).map_err(|_| self.room_refused(opcode, operands, most))?;
        }
        Ok(())
    }

    /// Pushes `opcode`'s result: in the default mode a result longer than the
    /// element bound declined by its length, then
    /// [`push_number`](Self::push_number)'s limit and charge.
    pub(super) fn push_arithmetic_result(
        &mut self,
        opcode: u8,
        operands: &[&[u8]],
        value: &BigNumber,
    ) -> Result<(), ScriptEvaluationError> {
        let bytes = ScriptNum::to_bytes(value);
        if self.flags.is_none() && bytes.len() > element_bound() {
            let len = bytes.len() as u64;
            return Err(self.result_declined(opcode, operands, len, ""));
        }
        self.push_encoded_number(bytes)
    }

    /// The element bound's decline of a result of `len` bytes (`qualifier`
    /// "at least " when judged before the arithmetic): `Script element
    /// allocation has exceeded 1073741824 bytes: OP_MUL needs at least N bytes
    /// for its result, from operands of A and B bytes.`
    fn result_declined(
        &self,
        opcode: u8,
        operands: &[&[u8]],
        len: u64,
        qualifier: &str,
    ) -> ScriptEvaluationError {
        let limit = ScriptResourceLimit {
            resource: ScriptResource::ElementSize,
            limit: element_bound() as u64,
            attempted: len,
            work_spent: None,
        };
        let name = opcode_to_name(opcode).unwrap_or("OP");
        self.error(&format!(
            "{limit}: {name} needs {qualifier}{len} bytes for its result, from {}.",
            describe(operands)
        ))
        .with_resource_limit(limit)
    }

    /// The allocator's refusal of `len` bytes for `opcode`'s result:
    /// [`allocation_declined`](Self::allocation_declined)'s limit, with the
    /// opcode and the sizes.
    fn room_refused(&self, opcode: u8, operands: &[&[u8]], len: u64) -> ScriptEvaluationError {
        let declined = self.allocation_declined(usize::try_from(len).unwrap_or(usize::MAX));
        let name = opcode_to_name(opcode).unwrap_or("OP");
        let message = format!(
            "{}: the allocator refused the {len} bytes {name}'s result may need, from {}.",
            declined.message,
            describe(operands)
        );
        ScriptEvaluationError {
            message,
            ..declined
        }
    }
}

/// `operands of A and B bytes`, or `an operand of A bytes`.
fn describe(operands: &[&[u8]]) -> String {
    match operands {
        [one] => format!("an operand of {} bytes", one.len()),
        _ => {
            let lens: Vec<String> = operands.iter().map(|o| o.len().to_string()).collect();
            format!("operands of {} bytes", lens.join(" and "))
        }
    }
}

/// The bits of a script number's magnitude, read from its bytes without
/// decoding them (a non-minimal encoding's padding counts nothing).
fn magnitude_bits(bytes: &[u8]) -> u64 {
    let last = bytes.len().saturating_sub(1);
    for (i, &byte) in bytes.iter().enumerate().rev() {
        let byte = if i == last { byte & 0x7f } else { byte };
        if byte != 0 {
            return 8 * i as u64 + u64::from(8 - byte.leading_zeros());
        }
    }
    0
}

/// The minimal encoding's length for a magnitude of `bits` bits: one byte for
/// each 8 bits and the sign's room.
fn encoded_len(bits: u64) -> u64 {
    if bits == 0 {
        0
    } else {
        bits / 8 + 1
    }
}

/// The fewest bits `opcode`'s result can have: a product of nonzero operands
/// has at least `a + b - 1`; no other result is bounded below by its operands.
fn least_result_bits(opcode: u8, bits: &[u64]) -> u64 {
    match (opcode, bits) {
        (OP_MUL, &[a, b]) if a > 0 && b > 0 => a + b - 1,
        _ => 0,
    }
}

/// The most bits `opcode`'s result can have.
fn most_result_bits(opcode: u8, bits: &[u64]) -> u64 {
    let longest = bits.iter().copied().max().unwrap_or(0);
    match opcode {
        OP_MUL => bits.iter().sum(),
        OP_ADD | OP_SUB | OP_2MUL => longest + 1,
        OP_1ADD | OP_1SUB => longest.max(1) + 1,
        _ => longest,
    }
}

/// The default mode's element bound on an arithmetic result.
#[cfg(not(test))]
fn element_bound() -> usize {
    MAX_SCRIPT_ELEMENT_SIZE
}

/// Asks the allocator for `len` bytes and gives them back: num-bigint's own
/// allocations are infallible, so the room is asked of the allocator first,
/// and its refusal is a decline where the arithmetic's would be an abort.
#[cfg(not(test))]
fn reserve(len: usize) -> Result<(), TryReserveError> {
    Vec::<u8>::new().try_reserve_exact(len)
}

#[cfg(test)]
thread_local! {
    /// The unit tests' model of the bound, so a product past it costs bytes.
    static ELEMENT_BOUND: Cell<usize> = const { Cell::new(MAX_SCRIPT_ELEMENT_SIZE) };
    /// The unit tests' model of an allocator that refuses more than this.
    static ALLOCATOR_CEILING: Cell<usize> = const { Cell::new(usize::MAX) };
}

#[cfg(test)]
fn element_bound() -> usize {
    ELEMENT_BOUND.with(Cell::get)
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

#[cfg(test)]
#[path = "arithmetic_room_tests.rs"]
mod tests;
