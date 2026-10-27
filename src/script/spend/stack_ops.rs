//! The stack opcodes: the alt stack moves and the main stack's drops, dups,
//! overs, rotations, swaps, picks and rolls.

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::{opcode_to_name, OP_ROLL};
use crate::script::script_num::ScriptNum;

use super::Spend;

impl Spend {
    pub(super) fn op_toaltstack(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_TOALTSTACK requires at least one item to be on the stack."));
        }
        let item = self.pop_stack()?;
        self.push_alt_stack(item)?;
        Ok(())
    }

    pub(super) fn op_fromaltstack(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.alt_stack.is_empty() {
            return Err(
                self.error("OP_FROMALTSTACK requires at least one item to be on the alt stack.")
            );
        }
        let item = self.pop_alt_stack()?;
        self.push_stack(item)?;
        Ok(())
    }

    pub(super) fn op_2drop(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_2DROP requires at least two items to be on the stack."));
        }
        self.pop_stack()?;
        self.pop_stack()?;
        Ok(())
    }

    pub(super) fn op_2dup(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_2DUP requires at least two items to be on the stack."));
        }
        let buf1 = self.copy_element(self.stack_top_n(2)?)?;
        let buf2 = self.copy_element(self.stack_top()?)?;
        self.push_stack(buf1)?;
        self.push_stack(buf2)?;
        Ok(())
    }

    pub(super) fn op_3dup(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 3 {
            return Err(self.error("OP_3DUP requires at least three items to be on the stack."));
        }
        let buf1 = self.copy_element(self.stack_top_n(3)?)?;
        let buf2 = self.copy_element(self.stack_top_n(2)?)?;
        let buf3 = self.copy_element(self.stack_top()?)?;
        self.push_stack(buf1)?;
        self.push_stack(buf2)?;
        self.push_stack(buf3)?;
        Ok(())
    }

    pub(super) fn op_2over(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 4 {
            return Err(self.error("OP_2OVER requires at least four items to be on the stack."));
        }
        let buf1 = self.copy_element(self.stack_top_n(4)?)?;
        let buf2 = self.copy_element(self.stack_top_n(3)?)?;
        self.push_stack(buf1)?;
        self.push_stack(buf2)?;
        Ok(())
    }

    pub(super) fn op_2rot(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 6 {
            return Err(self.error("OP_2ROT requires at least six items to be on the stack."));
        }
        let x6 = self.pop_stack()?;
        let x5 = self.pop_stack()?;
        let x4 = self.pop_stack()?;
        let x3 = self.pop_stack()?;
        let x2 = self.pop_stack()?;
        let x1 = self.pop_stack()?;
        self.push_stack(x3)?;
        self.push_stack(x4)?;
        self.push_stack(x5)?;
        self.push_stack(x6)?;
        self.push_stack(x1)?;
        self.push_stack(x2)?;
        Ok(())
    }

    pub(super) fn op_2swap(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 4 {
            return Err(self.error("OP_2SWAP requires at least four items to be on the stack."));
        }
        let x4 = self.pop_stack()?;
        let x3 = self.pop_stack()?;
        let x2 = self.pop_stack()?;
        let x1 = self.pop_stack()?;
        self.push_stack(x3)?;
        self.push_stack(x4)?;
        self.push_stack(x1)?;
        self.push_stack(x2)?;
        Ok(())
    }

    pub(super) fn op_ifdup(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_IFDUP requires at least one item to be on the stack."));
        }
        let top = self.copy_element(self.stack_top()?)?;
        if ScriptNum::cast_to_bool(&top) {
            self.push_stack(top)?;
        }
        Ok(())
    }

    pub(super) fn op_depth(&mut self) -> Result<(), ScriptEvaluationError> {
        let depth = BigNumber::from_u64(self.stack.len() as u64);
        self.push_stack(ScriptNum::to_bytes(&depth))?;
        Ok(())
    }

    pub(super) fn op_drop(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_DROP requires at least one item to be on the stack."));
        }
        self.pop_stack()?;
        Ok(())
    }

    pub(super) fn op_dup(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_DUP requires at least one item to be on the stack."));
        }
        let top = self.copy_element(self.stack_top()?)?;
        self.push_stack(top)?;
        Ok(())
    }

    pub(super) fn op_nip(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_NIP requires at least two items to be on the stack."));
        }
        let top = self.pop_stack()?;
        self.pop_stack()?;
        self.push_stack(top)?;
        Ok(())
    }

    pub(super) fn op_over(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_OVER requires at least two items to be on the stack."));
        }
        let second = self.copy_element(self.stack_top_n(2)?)?;
        self.push_stack(second)?;
        Ok(())
    }

    pub(super) fn op_pick_roll(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        self.require_two_items(opcode, "OP_PICK/ROLL")?;
        let n_bytes = self.pop_stack()?;
        let bn = self.read_number(&n_bytes)?;

        let n = bn.to_i64().unwrap_or(i64::MAX);
        if n < 0 || n >= self.stack.len() as i64 {
            return Err(self.error(&format!(
                "{} requires the top stack element to be 0 or a positive number less than the current size of the stack.",
                opcode_to_name(opcode).unwrap_or("OP_PICK/ROLL")
            )));
        }

        let n_idx = n as usize;
        let item = self.copy_element(&self.stack[self.stack.len() - 1 - n_idx])?;

        if opcode == OP_ROLL {
            let remove_idx = self.stack.len() - 1 - n_idx;
            let removed = self.stack.remove(remove_idx);
            self.stack_mem -= removed.len();
            self.release(removed.len());
            self.push_stack(item)?;
        } else {
            // OP_PICK
            self.push_stack(item)?;
        }
        Ok(())
    }

    pub(super) fn op_rot(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 3 {
            return Err(self.error("OP_ROT requires at least three items to be on the stack."));
        }
        let x3 = self.pop_stack()?;
        let x2 = self.pop_stack()?;
        let x1 = self.pop_stack()?;
        self.push_stack(x2)?;
        self.push_stack(x3)?;
        self.push_stack(x1)?;
        Ok(())
    }

    pub(super) fn op_swap(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_SWAP requires at least two items to be on the stack."));
        }
        let x2 = self.pop_stack()?;
        let x1 = self.pop_stack()?;
        self.push_stack(x2)?;
        self.push_stack(x1)?;
        Ok(())
    }

    pub(super) fn op_tuck(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_TUCK requires at least two items to be on the stack."));
        }
        let top = self.copy_element(self.stack_top()?)?;
        let len = top.len();
        self.stack
            .try_reserve(1)
            .map_err(|_| self.allocation_declined(len))?;
        self.reserve_stack(len)?;
        let insert_idx = self.stack.len() - 2;
        self.stack.insert(insert_idx, top);
        self.stack_mem += len;
        Ok(())
    }
}
