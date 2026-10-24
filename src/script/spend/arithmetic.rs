//! The arithmetic opcodes on script numbers: the unary ones, the binary ones
//! and comparisons, and `OP_WITHIN`.

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::*;
use crate::script::script_num::ScriptNum;

use super::Spend;

impl Spend {
    // OP_2MUL / OP_2DIV run only for a UTXO created after Chronicle
    // (interpreter.cpp:1247-1254; disabled before it, `360-375`, refused
    // above in `step`).
    pub(super) fn op_unary_number(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires at least one item to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }
        let buf = self.pop_stack()?;
        let mut bn = self.read_number(&buf)?;

        bn = match opcode {
            OP_1ADD => bn.add(&BigNumber::one()),
            OP_1SUB => bn.sub(&BigNumber::one()),
            OP_2MUL => bn.add(&bn),
            OP_2DIV => bn.div(&BigNumber::from_i64(2)),
            OP_NEGATE => bn.neg(),
            OP_ABS => bn.abs(),
            OP_NOT => {
                if bn.is_zero() {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_0NOTEQUAL => {
                if bn.is_zero() {
                    BigNumber::zero()
                } else {
                    BigNumber::one()
                }
            }
            _ => bn,
        };
        self.push_number(&bn)?;
        Ok(())
    }

    pub(super) fn op_binary_number(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error(&format!(
                "{} requires at least two items to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }
        let buf2 = self.pop_stack()?;
        let buf1 = self.pop_stack()?;
        let bn1 = self.read_number(&buf1)?;
        let bn2 = self.read_number(&buf2)?;

        let result = match opcode {
            OP_ADD => bn1.add(&bn2),
            OP_SUB => bn1.sub(&bn2),
            OP_MUL => bn1.mul(&bn2),
            OP_DIV => {
                if bn2.is_zero() {
                    return Err(self.error("OP_DIV cannot divide by zero!"));
                }
                bn1.div(&bn2)
            }
            OP_MOD => {
                if bn2.is_zero() {
                    return Err(self.error("OP_MOD cannot divide by zero!"));
                }
                bn1.mod_floor(&bn2)
            }
            OP_BOOLAND => {
                if !bn1.is_zero() && !bn2.is_zero() {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_BOOLOR => {
                if !bn1.is_zero() || !bn2.is_zero() {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                if bn1 == bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_NUMNOTEQUAL => {
                if bn1 != bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_LESSTHAN => {
                if bn1 < bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_GREATERTHAN => {
                if bn1 > bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_LESSTHANOREQUAL => {
                if bn1 <= bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_GREATERTHANOREQUAL => {
                if bn1 >= bn2 {
                    BigNumber::one()
                } else {
                    BigNumber::zero()
                }
            }
            OP_MIN => {
                if bn1 < bn2 {
                    bn1
                } else {
                    bn2
                }
            }
            OP_MAX => {
                if bn1 > bn2 {
                    bn1
                } else {
                    bn2
                }
            }
            _ => BigNumber::zero(),
        };

        self.push_number(&result)?;

        if opcode == OP_NUMEQUALVERIFY {
            if !ScriptNum::cast_to_bool(self.stack_top()?) {
                return Err(
                    self.error("OP_NUMEQUALVERIFY requires the top stack item to be truthy.")
                );
            }
            self.pop_stack()?;
        }
        Ok(())
    }

    pub(super) fn op_within(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 3 {
            return Err(self.error("OP_WITHIN requires at least three items to be on the stack."));
        }
        let max_bytes = self.pop_stack()?;
        let min_bytes = self.pop_stack()?;
        let x_bytes = self.pop_stack()?;
        let max_bn = self.read_number(&max_bytes)?;
        let min_bn = self.read_number(&min_bytes)?;
        let x_bn = self.read_number(&x_bytes)?;

        let in_range = x_bn >= min_bn && x_bn < max_bn;
        self.push_stack(if in_range { vec![1] } else { vec![] })?;
        Ok(())
    }
}
