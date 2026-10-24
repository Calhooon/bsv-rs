//! The bitwise opcodes on byte strings: `OP_INVERT`, `OP_AND`, `OP_OR`,
//! `OP_XOR`, `OP_EQUAL`/`OP_EQUALVERIFY`, and the width-preserving `OP_LSHIFT`
//! and `OP_RSHIFT`.

use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::{opcode_to_name, OP_AND, OP_EQUALVERIFY, OP_LSHIFT, OP_OR};

use super::Spend;

impl Spend {
    pub(super) fn op_invert(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_INVERT requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        let result: Vec<u8> = buf.iter().map(|&b| !b).collect();
        self.push_stack(result)?;
        Ok(())
    }

    pub(super) fn op_bitwise_logic(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error(&format!(
                "{} requires at least two items on the stack.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }
        let buf2 = self.pop_stack()?;
        let buf1 = self.pop_stack()?;
        if buf1.len() != buf2.len() {
            return Err(self.error(&format!(
                "{} requires the top two stack items to be the same size.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }
        let result: Vec<u8> = buf1
            .iter()
            .zip(buf2.iter())
            .map(|(&a, &b)| match opcode {
                OP_AND => a & b,
                OP_OR => a | b,
                _ => a ^ b, // OP_XOR
            })
            .collect();
        self.push_stack(result)?;
        Ok(())
    }

    pub(super) fn op_equal(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        self.require_two_items(opcode, "OP_EQUAL")?;
        let buf2 = self.pop_stack()?;
        let buf1 = self.pop_stack()?;
        let equal = buf1 == buf2;
        self.push_stack(if equal { vec![1] } else { vec![] })?;

        if opcode == OP_EQUALVERIFY {
            if !equal {
                return Err(
                    self.error("OP_EQUALVERIFY requires the top two stack items to be equal.")
                );
            }
            self.pop_stack()?;
        }
        Ok(())
    }

    pub(super) fn op_shift(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        self.require_two_items(opcode, "OP")?;
        let n_bytes = self.pop_stack()?;
        let buf = self.pop_stack()?;

        let n_bn = self.read_number(&n_bytes)?;
        let n = n_bn.to_i64().unwrap_or(-1);

        if n < 0 {
            return Err(self.error(&format!(
                "{} requires the top item on the stack not to be negative.",
                opcode_to_name(opcode).unwrap_or("OP")
            )));
        }

        if buf.is_empty() {
            self.push_stack(vec![])?;
        } else {
            // Node semantics (and ts-sdk post-#493): LSHIFT/RSHIFT are
            // WIDTH-PRESERVING bitwise shifts on the raw byte buffer —
            // bits shifted past the end are discarded, the result is
            // exactly buf.len() bytes. The previous BigNumber
            // mul/to_bytes_be(buf.len()) implementation PANICKED on
            // overflow ("BigNumber requires N bytes") and clamped the
            // shift count to 63 bits (conformance vectors
            // lshift-truncation.0001/.0003).
            let len = buf.len();
            let result: Vec<u8> = if (n as u128) >= (len as u128) * 8 {
                vec![0u8; len]
            } else {
                let byte_shift = (n as usize) / 8;
                let bit_shift = (n as usize) % 8;
                let mut out = vec![0u8; len];
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
                    } else {
                        // OP_RSHIFT
                        if i >= byte_shift {
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
                out
            };
            self.push_stack(result)?;
        }
        Ok(())
    }
}
