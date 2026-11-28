//! Fallible element allocation for the interpreter (bsv-rs#331, ported from the
//! 0.9 line, where it lives in `spend/limits.rs` + `spend/stack.rs`).
//!
//! The interpreter allocates a stack element outright on a push, a copy
//! (`OP_DUP`, `OP_PICK`, `OP_TUCK`, the multi-dups), `OP_CAT`, `OP_SPLIT`,
//! `OP_NUM2BIN`'s padding, the byte shifts and the Chronicle splices. An element
//! within the local budget can still be more than a memory-tight host (a
//! Cloudflare Worker isolate, a capped container) can give; with no fallible
//! form the raw `Vec` allocation would abort — on `wasm32` one nobody catches
//! (`CLAUDE.md` rule 5). These helpers ask the allocator with
//! `try_reserve`/`try_reserve_exact` first; the refusal is an
//! [`allocation_declined`](Spend::allocation_declined) decline
//! (`ScriptResource::Stack`, the same resource class, never read as invalid),
//! carrying the bytes both stacks held and the size asked. The error's snapshot
//! of the stacks is made the same way ([`snapshot`]), so building the error
//! never aborts when the evaluation stopped on an exhausted allocator.

use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::op::OP_LSHIFT;

use super::Spend;

impl Spend {
    /// The decline of an element the allocator refused: its limit the bytes both
    /// stacks held, its attempt those and the `len` asked for.
    pub(super) fn allocation_declined(&self, len: usize) -> ScriptEvaluationError {
        let held = (self.stack_mem as u64).saturating_add(self.alt_stack_mem as u64);
        self.error(&format!(
            "Script element allocation declined: the allocator could not provide {len} bytes \
             for an element; the stacks hold {held} bytes."
        ))
        .with_resource_limit(ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: held,
            attempted: held.saturating_add(len as u64),
            work_spent: None,
        })
    }

    /// Room for an element of `len` bytes, empty, or the allocator's decline.
    pub(super) fn element_with_capacity(
        &self,
        len: usize,
    ) -> Result<Vec<u8>, ScriptEvaluationError> {
        let mut element = Vec::new();
        element
            .try_reserve_exact(len)
            .map_err(|_| self.allocation_declined(len))?;
        Ok(element)
    }

    /// A copy of `bytes` for the stack, or the allocator's decline.
    pub(super) fn copy_element(&self, bytes: &[u8]) -> Result<Vec<u8>, ScriptEvaluationError> {
        let mut element = self.element_with_capacity(bytes.len())?;
        element.extend_from_slice(bytes);
        Ok(element)
    }

    /// `len` zero bytes for the stack, or the allocator's decline.
    pub(super) fn zeroed_element(&self, len: usize) -> Result<Vec<u8>, ScriptEvaluationError> {
        let mut element = self.element_with_capacity(len)?;
        element.resize(len, 0);
        Ok(element)
    }
}

/// A copy of `stack` for an error's context, or an empty one when the allocator
/// refuses any part of it (bsv-rs#331): building the error must not itself abort
/// when the evaluation stopped because the allocator was exhausted.
pub(super) fn snapshot(stack: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut copy = Vec::new();
    if copy.try_reserve_exact(stack.len()).is_err() {
        return Vec::new();
    }
    for item in stack {
        let mut element = Vec::new();
        if element.try_reserve_exact(item.len()).is_err() {
            return Vec::new();
        }
        element.extend_from_slice(item);
        copy.push(element);
    }
    copy
}

/// `OP_LSHIFT` / `OP_RSHIFT` on the raw bytes: a width-preserving shift of
/// `buf` by `n` bits (`n` not negative) into `out`, which the caller allocated
/// fallibly as `buf.len()` zero bytes. A shift past the width leaves the zeros.
pub(super) fn shift_into(buf: &[u8], n: i64, opcode: u8, out: &mut [u8]) {
    let len = buf.len();
    if (n as u128) >= (len as u128) * 8 {
        return;
    }
    let byte_shift = (n as usize) / 8;
    let bit_shift = (n as usize) % 8;
    #[allow(clippy::needless_range_loop)]
    for i in 0..len {
        if opcode == OP_LSHIFT {
            let src = i + byte_shift;
            let hi = if src < len { buf[src] } else { 0 };
            let lo = if bit_shift > 0 && src + 1 < len {
                buf[src + 1]
            } else {
                0
            };
            out[i] = if bit_shift == 0 {
                hi
            } else {
                (hi << bit_shift) | (lo >> (8 - bit_shift))
            };
        } else if i >= byte_shift {
            // OP_RSHIFT
            let src = i - byte_shift;
            let hi = buf[src];
            let carry = if bit_shift > 0 && src >= 1 {
                buf[src - 1]
            } else {
                0
            };
            out[i] = if bit_shift == 0 {
                hi
            } else {
                (hi >> bit_shift) | (carry << (8 - bit_shift))
            };
        }
    }
}

/// `OP_NUM2BIN`'s result: `minimal` written into `result` (the caller allocated
/// it fallibly as `size` zero bytes), its sign bit moved to the last byte.
pub(super) fn pad_into(minimal: &[u8], result: &mut [u8]) {
    let size = result.len();
    let mut signbit = 0u8;
    if let Some(&last) = minimal.last() {
        signbit = last & 0x80;
        result[..minimal.len()].copy_from_slice(minimal);
        result[minimal.len() - 1] &= 0x7f;
    }
    if signbit != 0 {
        result[size - 1] |= 0x80;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Spend, SpendParams};
    use super::snapshot;
    use crate::script::evaluation_error::{ScriptResource, ScriptResourceLimit};
    use crate::script::{LockingScript, UnlockingScript};

    /// bsv-rs#331 (ported): an element the allocator cannot give is a decline,
    /// never an abort (on wasm32 one nobody catches). No script reaches the
    /// allocator's refusal on a 64-bit host (the default mode bounds an element
    /// at 1 GiB), so the helper is asked for more than `isize::MAX` bytes, which
    /// every allocator refuses. The decline names the bytes both stacks held and
    /// the size asked, as a `ScriptResource::Stack` resource limit (never read
    /// as invalid), and a small copy still succeeds after it.
    #[test]
    fn an_allocation_the_allocator_refuses_is_a_decline_not_an_abort() {
        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: LockingScript::from_asm("OP_DROP OP_1").unwrap(),
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: Some(usize::MAX),
            work_limit: None,
        });
        spend.push_stack(vec![0x01; 7]).unwrap();
        let asked = isize::MAX as usize + 1;
        let declined = spend.zeroed_element(asked).unwrap_err();
        assert_eq!(
            declined.resource_limit,
            Some(ScriptResourceLimit {
                resource: ScriptResource::Stack,
                limit: 7,
                attempted: 7 + asked as u64,
                work_spent: None,
            })
        );
        assert!(declined.is_resource_limit());
        assert!(
            declined
                .message
                .starts_with("Script element allocation declined"),
            "message was {:?}",
            declined.message
        );
        // A small copy still works after the refusal.
        assert!(spend.copy_element(&[1, 2, 3]).is_ok());
    }

    /// An error's copy of the stacks, made fallibly since bsv-rs#331 (left empty
    /// when the allocator refuses it), is the stacks' copy.
    #[test]
    fn an_error_snapshot_copies_the_stack() {
        assert_eq!(snapshot(&[vec![1], vec![2, 3]]), vec![vec![1], vec![2, 3]]);
        assert!(snapshot(&[]).is_empty());
    }
}
