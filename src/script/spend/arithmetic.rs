//! The arithmetic opcodes on script numbers: the unary ones, the binary ones
//! and comparisons, and `OP_WITHIN`.

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::{
    opcode_to_name, OP_0NOTEQUAL, OP_1ADD, OP_1SUB, OP_2DIV, OP_2MUL, OP_ABS, OP_ADD, OP_BOOLAND,
    OP_BOOLOR, OP_DIV, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_LESSTHAN, OP_LESSTHANOREQUAL,
    OP_MAX, OP_MIN, OP_MOD, OP_MUL, OP_NEGATE, OP_NOT, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL, OP_SUB,
};
use crate::script::script_num::ScriptNum;
use num_bigint::BigInt;
use num_traits::Zero;

use super::Spend;

impl Spend {
    // OP_2MUL / OP_2DIV run at every version by default (Spend.ts:828,
    // :1494-1536). Under a word the UTXO's era gates them in `step`
    // (interpreter.cpp:1247-1254, :360-375).
    pub(super) fn op_unary_number(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires at least one item to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }
        let buf = self.pop_stack()?;
        let lens = [buf.len()];
        self.arithmetic_room(opcode, &[&buf])?;
        let n = BigInt::from(self.read_number(&buf)?);
        drop(buf);

        // Owned arithmetic: the result takes the operand's digits, whose
        // capacity holds the one bit `OP_1ADD`, `OP_1SUB` and `OP_2MUL` may
        // add (bsv-rs#374).
        let n = match opcode {
            OP_1ADD => n + 1u32,
            OP_1SUB => n - 1u32,
            OP_2MUL => n << 1u32,
            OP_2DIV => n / 2u32,
            OP_NEGATE => -n,
            OP_ABS => BigInt::from(n.into_parts().1),
            OP_NOT => BigInt::from(u8::from(n.is_zero())),
            OP_0NOTEQUAL => BigInt::from(u8::from(!n.is_zero())),
            _ => n,
        };
        self.push_arithmetic_result(opcode, &lens, BigNumber::from_bigint(n))
    }

    pub(super) fn op_binary_number(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        self.require_two_items(opcode, "OP")?;
        let buf2 = self.pop_stack()?;
        let buf1 = self.pop_stack()?;
        let lens = [buf1.len(), buf2.len()];
        self.arithmetic_room(opcode, &[&buf1, &buf2])?;
        // The top operand read first, as the reference reads `bn2` first
        // (`Spend.ts:1560-1561`); each operand's bytes leave as its number
        // arrives (bsv-rs#374), the number held in their place.
        let bn2 = BigInt::from(self.read_number_holding(&buf2, lens[0] as u64)?);
        drop(buf2);
        let bn1 = BigInt::from(self.read_number_holding(&buf1, lens[1] as u64)?);
        drop(buf1);

        // Owned where num-bigint reuses an operand's digits for the result.
        let result = match opcode {
            OP_ADD => bn1 + bn2,
            OP_SUB => bn1 - bn2,
            OP_MUL => bn1 * bn2,
            OP_DIV => {
                if bn2.is_zero() {
                    return Err(self.error("OP_DIV cannot divide by zero!"));
                }
                bn1 / bn2
            }
            OP_MOD => {
                if bn2.is_zero() {
                    return Err(self.error("OP_MOD cannot divide by zero!"));
                }
                bn1 % bn2
            }
            OP_BOOLAND => truth(!bn1.is_zero() && !bn2.is_zero()),
            OP_BOOLOR => truth(!bn1.is_zero() || !bn2.is_zero()),
            OP_NUMEQUAL | OP_NUMEQUALVERIFY => truth(bn1 == bn2),
            OP_NUMNOTEQUAL => truth(bn1 != bn2),
            OP_LESSTHAN => truth(bn1 < bn2),
            OP_GREATERTHAN => truth(bn1 > bn2),
            OP_LESSTHANOREQUAL => truth(bn1 <= bn2),
            OP_GREATERTHANOREQUAL => truth(bn1 >= bn2),
            OP_MIN => bn1.min(bn2),
            OP_MAX => bn1.max(bn2),
            _ => BigInt::zero(),
        };

        self.push_arithmetic_result(opcode, &lens, BigNumber::from_bigint(result))?;

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
        // Each operand read as it is popped, as the reference reads them
        // (`Spend.ts:1628-1630`): the verdicts in the same order, the others
        // still on the stack while one is read.
        let max_bn = self.pop_number()?;
        let min_bn = self.pop_number()?;
        let x_bn = self.pop_number()?;

        let in_range = x_bn >= min_bn && x_bn < max_bn;
        self.push_stack(if in_range { vec![1] } else { vec![] })?;
        Ok(())
    }
}

impl Spend {
    /// The top element popped and read as a script number.
    fn pop_number(&mut self) -> Result<BigNumber, ScriptEvaluationError> {
        let bytes = self.pop_stack()?;
        self.read_number(&bytes)
    }
}

/// A comparison's result as a script number: 1 when it holds, 0 otherwise.
fn truth(holds: bool) -> BigInt {
    BigInt::from(u8::from(holds))
}
