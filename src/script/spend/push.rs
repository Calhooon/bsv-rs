//! The push opcodes: the small-integer constants (`OP_1NEGATE`, `OP_0`,
//! `OP_1`-`OP_16`) from their precomputed encodings, the data pushes, and the
//! minimal-push rule.

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::*;
use crate::script::script_num::ScriptNum;
use crate::script::ScriptChunk;

use super::Spend;

// ============================================================================
// Pre-computed Script Numbers
// ============================================================================

lazy_static::lazy_static! {
    /// Pre-computed script number for -1
    static ref SCRIPTNUM_NEG_1: Vec<u8> = ScriptNum::to_bytes(&BigNumber::from_i64(-1));

    /// Pre-computed script numbers for 0-16
    static ref SCRIPTNUMS_0_TO_16: Vec<Vec<u8>> = (0..=16)
        .map(|i| ScriptNum::to_bytes(&BigNumber::from_i64(i)))
        .collect();
}

/// Checks if a chunk uses minimal push encoding.
pub(super) fn is_chunk_minimal_push(chunk: &ScriptChunk) -> bool {
    let data = match &chunk.data {
        Some(d) => d,
        None => return true,
    };
    let op = chunk.op;

    if data.is_empty() {
        return op == OP_0;
    }

    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        return op == OP_1 + (data[0] - 1);
    }

    if data.len() == 1 && data[0] == 0x81 {
        return op == OP_1NEGATE;
    }

    if data.len() <= 75 {
        return op as usize == data.len();
    }

    if data.len() <= 255 {
        return op == OP_PUSHDATA1;
    }

    if data.len() <= 65535 {
        return op == OP_PUSHDATA2;
    }

    true
}

impl Spend {
    pub(super) fn op_1negate(&mut self) -> Result<(), ScriptEvaluationError> {
        self.push_stack_copy(&SCRIPTNUM_NEG_1)?;
        Ok(())
    }

    pub(super) fn op_0(&mut self) -> Result<(), ScriptEvaluationError> {
        self.push_stack_copy(&SCRIPTNUMS_0_TO_16[0])?;
        Ok(())
    }

    pub(super) fn op_small_integer(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        let n = (opcode - OP_1 + 1) as usize;
        self.push_stack_copy(&SCRIPTNUMS_0_TO_16[n])?;
        Ok(())
    }

    pub(super) fn op_push_data(
        &mut self,
        chunk: &ScriptChunk,
    ) -> Result<(), ScriptEvaluationError> {
        // Direct push opcodes - should have data
        let data = chunk.data.clone().unwrap_or_default();
        self.push_stack(data)?;
        Ok(())
    }
}
