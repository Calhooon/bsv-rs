//! The flow opcodes: the NOPs and their discouragement, `OP_VER`, the
//! conditionals (`OP_IF`, `OP_NOTIF`, `OP_VERIF`, `OP_VERNOTIF`, `OP_ELSE`,
//! `OP_ENDIF`), `OP_VERIFY` and `OP_RETURN`; the disabled-opcode rule.

use crate::script::evaluation_error::{ExecutionContext, ScriptEvaluationError};
use crate::script::op::*;
use crate::script::script_num::ScriptNum;

use super::Spend;

/// `IsOpcodeDisabled` (interpreter.cpp:360-375): `OP_2MUL` and `OP_2DIV`
/// unless the UTXO was created after Chronicle. `OP_VER`, `OP_VERIF` and
/// `OP_VERNOTIF` are not "disabled" there but `BAD_OPCODE` when executed
/// before Chronicle, handled in their arms.
pub(super) fn is_opcode_disabled(op: u8, utxo_after_chronicle: bool) -> bool {
    !utxo_after_chronicle && matches!(op, OP_2MUL | OP_2DIV)
}

impl Spend {
    // The upgradable NOPs 0xb0-0xb9. Under DISCOURAGE_UPGRADABLE_NOPS an
    // executed one fails the script (interpreter.cpp:765-771 for NOP1,
    // NOP9, NOP10; 520-523 and 563-566 for CHECKLOCKTIMEVERIFY and
    // CHECKSEQUENCEVERIFY, NOPs for a post-Genesis UTXO; 606-700 for
    // NOP4-NOP8 before their Chronicle meanings). ts-sdk: "is
    // discouraged by verification flags".
    pub(super) fn op_upgradable_nop(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if self.discourage_upgradable_nops {
            return Err(self.error(&format!(
                "{} is discouraged by verification flags.",
                opcode_to_name(opcode).unwrap_or("OP_NOP")
            )));
        }
        Ok(())
    }

    // 0xb3-0xb7: NOP4-NOP8 before Chronicle; OP_SUBSTR, OP_LEFT, OP_RIGHT,
    // OP_LSHIFTNUM, OP_RSHIFTNUM for a UTXO created after it
    // (interpreter.cpp:609-764; the NOP branch with the discouragement at
    // each arm's head).
    pub(super) fn op_nop4_to_nop8(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if !self.utxo_after_chronicle {
            if self.discourage_upgradable_nops {
                return Err(self.error(&format!(
                    "{} is discouraged by verification flags.",
                    opcode_to_name(opcode).unwrap_or("OP_NOP")
                )));
            }
        } else {
            self.op_chronicle_splice(opcode)?;
        }
        Ok(())
    }

    // OP_VER: the transaction version as 4 little-endian bytes for a UTXO
    // created after Chronicle (interpreter.cpp:598-608); BAD_OPCODE before.
    pub(super) fn op_ver(&mut self) -> Result<(), ScriptEvaluationError> {
        if !self.utxo_after_chronicle {
            return Err(self.error("OP_VER is disabled until Chronicle."));
        }
        self.push_stack(self.transaction_version.to_le_bytes().to_vec())?;
        Ok(())
    }

    pub(super) fn op_if(
        &mut self,
        opcode: u8,
        is_executing: bool,
    ) -> Result<(), ScriptEvaluationError> {
        let mut f_value = false;
        if is_executing {
            if self.stack.is_empty() {
                return Err(self.error(
                    "OP_IF and OP_NOTIF require at least one item on the stack when they are used!",
                ));
            }
            let buf = self.pop_stack()?;
            // MINIMALIF (interpreter.cpp:795-803, under the version
            // gate): the argument must be empty or exactly 0x01.
            if self.require_minimal_if && !(buf.is_empty() || buf == [1]) {
                return Err(self.error("OP_IF and OP_NOTIF require minimal truth values."));
            }
            f_value = ScriptNum::cast_to_bool(&buf);
            if opcode == OP_NOTIF {
                f_value = !f_value;
            }
        }
        self.if_stack.push(f_value);
        self.else_stack.push(false);
        Ok(())
    }

    // OP_VERIF / OP_VERNOTIF (interpreter.cpp:773-812): for a UTXO created
    // after Chronicle, a conditional on "the top element is exactly the
    // transaction version as 4 little-endian bytes"; before Chronicle,
    // skipped when not executing (post-Genesis) and BAD_OPCODE when
    // executed. This arm runs whether or not the branch executes (the
    // opcodes sit in the OP_IF..OP_ENDIF range).
    pub(super) fn op_verif(
        &mut self,
        opcode: u8,
        is_executing: bool,
    ) -> Result<(), ScriptEvaluationError> {
        if !self.utxo_after_chronicle {
            if !is_executing {
                return Ok(());
            }
            return Err(self.error(&format!(
                "{} is disabled until Chronicle.",
                opcode_to_name(opcode).unwrap_or("OP_VERIF")
            )));
        }
        let mut f_value = false;
        if is_executing {
            if self.stack.is_empty() {
                return Err(self.error(
                    "OP_VERIF and OP_VERNOTIF require at least one item on the stack when they are used!",
                ));
            }
            let buf = self.pop_stack()?;
            if buf.len() == 4 {
                f_value = buf == self.transaction_version.to_le_bytes();
            }
            if opcode == OP_VERNOTIF {
                f_value = !f_value;
            }
        }
        self.if_stack.push(f_value);
        self.else_stack.push(false);
        Ok(())
    }

    pub(super) fn op_else(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.if_stack.is_empty() {
            return Err(self.error("OP_ELSE requires a preceeding OP_IF."));
        }
        // One OP_ELSE per OP_IF after Genesis (conditional_tracker.cpp:51-55,
        // interpreter.cpp:829-831); every UTXO here is post-Genesis.
        if self.else_stack.last() == Some(&true) {
            return Err(self
                .error("OP_ELSE may only be used once for each OP_IF or OP_NOTIF after Genesis."));
        }
        if let Some(seen) = self.else_stack.last_mut() {
            *seen = true;
        }
        let last = self.if_stack.len() - 1;
        self.if_stack[last] = !self.if_stack[last];
        Ok(())
    }

    pub(super) fn op_endif(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.if_stack.is_empty() {
            return Err(self.error("OP_ENDIF requires a preceeding OP_IF."));
        }
        self.if_stack.pop();
        self.else_stack.pop();
        Ok(())
    }

    pub(super) fn op_verify(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_VERIFY requires at least one item to be on the stack."));
        }
        let f_value = ScriptNum::cast_to_bool(self.stack_top()?);
        if !f_value {
            return Err(self.error("OP_VERIFY requires the top stack value to be truthy."));
        }
        self.pop_stack()?;
        Ok(())
    }

    pub(super) fn op_return(&mut self) -> Result<(), ScriptEvaluationError> {
        // After Genesis (interpreter.cpp:856-871): at the top level the
        // script ends successfully, whatever follows; inside a conditional,
        // execution stops but the walk continues, so the conditionals must
        // still balance and every later opcode must still parse (`482`).
        if self.if_stack.is_empty() {
            let end = match self.context {
                ExecutionContext::UnlockingScript => self.unlocking_chunks.len(),
                ExecutionContext::LockingScript => self.locking_chunks.len(),
            };
            self.program_counter = end;
            // Counteract the final increment
            if self.program_counter > 0 {
                self.program_counter -= 1;
            }
        } else {
            self.returning = true;
        }
        Ok(())
    }
}
