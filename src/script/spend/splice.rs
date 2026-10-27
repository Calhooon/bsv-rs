//! The splice opcodes: `OP_SIZE`, `OP_CAT`, `OP_SPLIT`, `OP_NUM2BIN`,
//! `OP_BIN2NUM`, and the Chronicle opcodes at `0xb3`-`0xb7` (`OP_SUBSTR`,
//! `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM`) with their operand
//! reads.

use crate::primitives::BigNumber;
use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource};
use crate::script::flags::STACK_ELEMENT_OVERHEAD;
use crate::script::op::{OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7};
use crate::script::script_num::ScriptNum;

use super::limits::MAX_SCRIPT_ELEMENT_SIZE;
use super::num::number_text;
use super::reference_read;
use super::Spend;

impl Spend {
    pub(super) fn op_size(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_SIZE requires at least one item to be on the stack."));
        }
        let size = self.stack_top()?.len();
        let bn = BigNumber::from_u64(size as u64);
        self.push_stack(ScriptNum::to_bytes(&bn))?;
        Ok(())
    }

    pub(super) fn op_cat(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_CAT requires at least two items to be on the stack."));
        }
        let buf2 = self.pop_stack()?;
        let mut result = self.pop_stack()?;
        result.try_reserve_exact(buf2.len()).map_err(|_| {
            let in_hand = (result.len() + buf2.len()) as u64;
            self.allocation_declined_holding(in_hand, buf2.len())
        })?;
        result.extend(buf2);
        // The default mode's 1 GiB element bound; under a word an element
        // after Genesis is bounded by the stack memory budget alone
        // (`src/consensus/consensus.h:81-82`), which the push charges.
        if self.flags.is_none() && result.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(self.error(&format!(
                "It's not currently possible to push data larger than {} bytes.",
                MAX_SCRIPT_ELEMENT_SIZE
            )));
        }
        self.push_stack(result)?;
        Ok(())
    }

    pub(super) fn op_split(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_SPLIT requires at least two items to be on the stack."));
        }
        let pos_bytes = self.pop_stack()?;
        let data = self.pop_stack()?;

        let pos_bn = self.read_number(&pos_bytes)?;
        let split_idx = self.split_position(&pos_bn, data.len())?;
        let in_hand = (data.len() + pos_bytes.len()) as u64;
        let left = self.copy_element_holding(in_hand, &data[..split_idx])?;
        let right = self.copy_element_holding(in_hand + split_idx as u64, &data[split_idx..])?;
        self.push_stack(left)?;
        self.push_stack(right)?;
        Ok(())
    }

    pub(super) fn op_num2bin(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error("OP_NUM2BIN requires at least two items to be on the stack."));
        }
        let size_bytes = self.pop_stack()?;
        let size_bn = self.read_number(&size_bytes)?;
        let size = self.num2bin_size(&size_bn)?;

        let rawnum = self.pop_stack()?;
        let minimal = ScriptNum::minimally_encode(&rawnum);

        if minimal.len() > size {
            return Err(self.error(
                "OP_NUM2BIN requires that the size expressed in the top stack item is large enough to hold the value expressed in the second-from-top stack item.",
            ));
        }

        // Under a word the growth is charged before the element is
        // resized (`LimitedVector::padRight`, `limitedstack.cpp:60-71`:
        // the charge at `:66`, the resize at `:68`), so a size the budget
        // refuses is refused before it is allocated. The node's count
        // after the pad equals the count of the padded element pushed
        // here (the value's minimal encoding is never longer than it).
        if self.flags.is_some() && minimal.len() < size {
            self.check_node_budget(self.node_mem + size as u64 + STACK_ELEMENT_OVERHEAD as u64)?;
        }

        if minimal.len() == size {
            self.push_stack(minimal)?;
        } else {
            let mut result = self.zeroed_element(minimal.len() as u64, size)?;
            pad_into(&minimal, &mut result);
            self.push_stack(result)?;
        }
        Ok(())
    }

    /// `OP_NUM2BIN`'s size operand, bounded before anything is allocated:
    /// under a word by `INT32_MAX`, in the default mode by the element bound
    /// and the local memory budget.
    fn num2bin_size(&self, size_bn: &BigNumber) -> Result<usize, ScriptEvaluationError> {
        let size = size_bn.to_i64().unwrap_or(-1);

        if self.flags.is_some() {
            // Under a word the reference's bound: a size below 0 or above
            // INT32_MAX is SCRIPT_ERR_PUSH_SIZE before anything is
            // allocated, on every path (`interpreter.cpp:1747-1749`); an
            // element after Genesis is otherwise bounded by the stack
            // memory budget alone (`src/consensus/consensus.h:81-82`),
            // charged below.
            if size < 0 || size > i64::from(i32::MAX) {
                return Err(self.error(&format!(
                    "OP_NUM2BIN requires a size from 0 to 2147483647, found {}.",
                    number_text(size_bn)
                )));
            }
            Ok(size as usize)
        } else {
            if size < 0 || size > MAX_SCRIPT_ELEMENT_SIZE as i64 {
                return Err(self.error(&format!(
                    "It's not currently possible to push data larger than {} bytes or negative size.",
                    MAX_SCRIPT_ELEMENT_SIZE
                )));
            }
            let size = size as usize;
            // Reference parity (0.3.23): the element the script asks for is
            // refused BEFORE it is allocated when it alone exceeds the
            // local memory budget — the TypeScript SDK's `element-size`
            // resource check. Without this a 9-byte script could make the
            // evaluator allocate up to MAX_SCRIPT_ELEMENT_SIZE (1 GB) and
            // only then trip the stack budget on the push.
            if size > self.memory_limit() {
                return Err(self.resource_error(ScriptResource::ElementSize, size));
            }
            Ok(size)
        }
    }

    pub(super) fn op_bin2num(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_BIN2NUM requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        let result = ScriptNum::minimally_encode(&buf);
        // A result longer than the limit in force is refused as the
        // reference refuses it (`IsMinimallyEncoded(max)`,
        // `interpreter.cpp:1789-1790`: `SCRIPT_ERR_INVALID_NUMBER_RANGE`).
        let over = matches!(self.max_script_num_length(), Some(max) if result.len() > max);
        if over || !ScriptNum::is_minimally_encoded(&result) {
            return Err(self.error("OP_BIN2NUM requires that the resulting number is valid."));
        }
        self.push_stack(result)?;
        Ok(())
    }

    /// `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM` at
    /// `0xb3`-`0xb7` for a UTXO created after Chronicle (`interpreter.cpp:609-764`).
    /// The splice operands are read by [`read_splice_operand`](Self::read_splice_operand)
    /// (the reference's `int64` path under a word). The two shifts act on
    /// script NUMBERS (not on bytes, unlike `OP_LSHIFT`). Under a word the
    /// reference's two bounds come first (Calhooon/bsv-rs#21): a left shift's
    /// result size against the era's maximum number length before the shift
    /// (`script_num.cpp:305-308`, `SCRIPTNUM_OVERFLOW`), then on both shifts a
    /// count above `INT_MAX` as the big-integer error (`big_int.cpp:359-369`,
    /// `383-393`; `SCRIPT_ERR_BIG_INT`, `interpreter.cpp:1819-1821`). After
    /// them, a left shift's result is sized exactly before it is computed: over
    /// the era's number length it is the reference's size test after the shift
    /// (`script_num.cpp:315-316`), and its charge to the node's stack memory
    /// count is tested as the push will charge it. The default mode shifts by
    /// any count, as the TypeScript SDK does, and refuses a result that alone
    /// would exceed the local budget before computing it (a resource limit).
    pub(super) fn op_chronicle_splice(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        let name = match opcode {
            OP_NOP4 => "OP_SUBSTR",
            OP_NOP5 => "OP_LEFT",
            OP_NOP6 => "OP_RIGHT",
            OP_NOP7 => "OP_LSHIFTNUM",
            _ => "OP_RSHIFTNUM",
        };
        let need = if opcode == OP_NOP4 { 3 } else { 2 };
        if self.stack.len() < need {
            return Err(self.error(&format!(
                "{name} requires at least {} items to be on the stack.",
                if need == 3 { "three" } else { "two" }
            )));
        }
        let num = |s: &Self, bytes: &[u8]| -> Result<BigNumber, ScriptEvaluationError> {
            s.read_number(bytes)
        };
        match opcode {
            OP_NOP4 => {
                // (data offset len -- data[offset..offset+len])
                let len_bytes = self.pop_stack()?;
                let off_bytes = self.pop_stack()?;
                let len = self.read_splice_operand(&len_bytes)?;
                let offset = self.read_splice_operand(&off_bytes)?;
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if offset < 0 || offset >= size || len < 0 || len > size - offset {
                    return Err(self.error(&format!(
                        "OP_SUBSTR offset ({offset}) must be in range [0, {size}) and length ({len}) must be in range [0, {}]",
                        size - offset
                    )));
                }
                let (o, l) = (offset as usize, len as usize);
                let in_hand = (data.len() + len_bytes.len() + off_bytes.len()) as u64;
                let out = self.copy_element_holding(in_hand, &data[o..o + l])?;
                self.push_stack(out)?;
            }
            OP_NOP5 | OP_NOP6 => {
                // (data len -- the first / last len bytes)
                let len_bytes = self.pop_stack()?;
                let len = self.read_splice_operand(&len_bytes)?;
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if len < 0 || len > size {
                    return Err(self.error(&format!(
                        "{name} length ({len}) must be in range [0, {size}]"
                    )));
                }
                let l = len as usize;
                let in_hand = (data.len() + len_bytes.len()) as u64;
                let out = if opcode == OP_NOP5 {
                    self.copy_element_holding(in_hand, &data[..l])?
                } else {
                    self.copy_element_holding(in_hand, &data[data.len() - l..])?
                };
                self.push_stack(out)?;
            }
            _ => {
                // (x n -- x << n) / (x n -- x >> n), on script numbers
                let n_bytes = self.pop_stack()?;
                let n_bn = num(self, &n_bytes)?;
                if n_bn.is_negative() {
                    return Err(self.error(&format!("{name} bits to shift must not be negative.")));
                }
                let x_bytes = self.pop_stack()?;
                let x = num(self, &x_bytes)?;
                // the two operands, held off the stack to the push
                let in_hand = (x_bytes.len() + n_bytes.len()) as u64;
                if let Some(max) = self.max_script_num_length() {
                    // Under a word, the reference's bounds (Calhooon/bsv-rs#21).
                    // A left shift first tests the result's size, the value's
                    // serialized size plus count / 8 bytes, against the era's
                    // maximum number length, before any shift or allocation
                    // (`CScriptNum::operator<<=`, `script_num.cpp:305-308`); a
                    // right shift has no size test (`363-367`).
                    if opcode == OP_NOP7 {
                        let current = ScriptNum::to_bytes(&x).len() as u64;
                        match n_bn.to_u64().and_then(|n| current.checked_add(n / 8)) {
                            Some(size) if size <= max as u64 => {}
                            Some(size) => return Err(self.overflow_error(size as usize, max)),
                            None => {
                                return Err(self.error(&format!(
                                    "Script number overflow: a shift by {} bits, the limit is {max} bytes.",
                                    number_text(&n_bn)
                                )))
                            }
                        }
                    }
                    // Then, on both shifts, a count above INT_MAX is the
                    // reference's `big_int_error` (`bint::operator<<=` and
                    // `operator>>=` on a `bint` count, `big_int.cpp:359-369`,
                    // `383-393`), caught as `SCRIPT_ERR_BIG_INT`
                    // (`interpreter.cpp:1819-1821`).
                    if n_bn.to_i64().is_none_or(|n| n > i64::from(i32::MAX)) {
                        return Err(self.error(&format!(
                            "{name} count ({}) does not fit an int.",
                            number_text(&n_bn)
                        )));
                    }
                }
                let n = n_bn.to_i64().map(|v| v as u64).unwrap_or(u64::MAX);
                let out = if opcode == OP_NOP7 {
                    if x.is_zero() {
                        x
                    } else if let Some(max) = self.max_script_num_length() {
                        // Under a word the size test above bounds the result, and
                        // its exact length is known before the shift: the
                        // magnitude's bits plus the count, one byte for each 8
                        // bits and one for the sign's room. The reference's size
                        // test after the shift (`script_num.cpp:315-316`,
                        // SCRIPTNUM_OVERFLOW) and the node's charge of the pushed
                        // result (`limitedstack.h:171`) are decided on it before
                        // anything is allocated.
                        let bits = (x.bit_length() as u64).saturating_add(n);
                        let len = bits / 8 + 1;
                        if len > max as u64 {
                            return Err(self.overflow_error(len as usize, max));
                        }
                        self.check_node_budget(
                            self.node_mem + len + STACK_ELEMENT_OVERHEAD as u64,
                        )?;
                        self.number_room(in_hand, 2 * len + 16)?;
                        x.shl_bits(n)
                    } else {
                        // the default mode: the result's size, before allocating
                        // it, against the LOCAL budget, then the 1 GiB element
                        // bound (OP_CAT's and OP_NUM2BIN's, the only bound an
                        // uncapped budget leaves, bsv-rs#331; the exact length
                        // is the word branch's)
                        let bits = (x.bit_length() as u64).saturating_add(n);
                        let bytes = bits / 8 + 2;
                        if bytes > self.memory_limit() as u64 {
                            return Err(self.resource_error(
                                ScriptResource::ElementSize,
                                usize::try_from(bytes).unwrap_or(usize::MAX),
                            ));
                        }
                        if bits / 8 + 1 > MAX_SCRIPT_ELEMENT_SIZE as u64 {
                            return Err(self.error(&format!(
                                "It's not currently possible to push data larger than {} bytes.",
                                MAX_SCRIPT_ELEMENT_SIZE
                            )));
                        }
                        // the reference's `new BigNumber(value << bits)`
                        // (`Spend.ts:1066`) past V8's largest `BigInt` or its
                        // longest string, its words before the shift
                        // allocates; the budget's decline first
                        if let Some(words) = reference_read::shift_refusal(bits) {
                            self.ensure_stack_mem(
                                usize::try_from(bits / 8 + 1).unwrap_or(usize::MAX),
                            )?;
                            return Err(self.error(words));
                        }
                        self.number_room(in_hand, 2 * bytes + 16)?;
                        x.shl_bits(n)
                    }
                } else if n >= x.bit_length() as u64 {
                    BigNumber::zero()
                } else {
                    self.number_room(in_hand, 2 * x_bytes.len() as u64 + 16)?;
                    x.shr_bits_toward_zero(n)
                };
                self.push_number(out)?;
            }
        }
        Ok(())
    }

    /// The OP_SPLIT position check, separate from slicing so its boundary can
    /// be tested without allocating the data: bitcoin-sv v1.2.3,
    /// `interpreter.cpp:1708-1721` at `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`.
    pub(super) fn split_position(
        &self,
        position: &BigNumber,
        data_len: usize,
    ) -> Result<usize, ScriptEvaluationError> {
        let pos = position.to_i64().unwrap_or(-1);
        if pos < 0
            || (self.flags.is_some() && pos > i64::from(i32::MAX))
            || pos as u64 > data_len as u64
        {
            return Err(self.error(
                "OP_SPLIT requires the first stack item to be a non-negative number less than or equal to the size of the second-from-top stack item.",
            ));
        }
        Ok(pos as usize)
    }

    /// The `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` length and offset operands.
    /// Under a word, follows bitcoin-sv v1.2.3's fixed-width construction sites
    /// (`interpreter.cpp:622-625`, `655-656`, `680-681`) and checked decoder
    /// (`int_serialization.h:61-118`), at
    /// `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`. The era width and minimality
    /// checks precede conversion (`script_num.cpp:62-87`). A failed conversion
    /// is SCRIPT_ERR_SCRIPTNUM_OVERFLOW (`script_num.cpp:80-91`,
    /// `interpreter.cpp:1807-1809`). `getint` then saturates to the `int` range
    /// (`script_num.cpp:396-422`).
    /// The default mode uses the TypeScript SDK's unrestricted number reader.
    pub(super) fn read_splice_operand(&self, bytes: &[u8]) -> Result<i64, ScriptEvaluationError> {
        if self.flags.is_none() {
            return Ok(self.read_number(bytes)?.to_i64().unwrap_or(-1));
        }
        // Preserve the era-width/minimality ordering and their messages.
        let as_number = self.read_number(bytes)?;
        let decode_error = || self.error("Script number overflow: operand does not fit int64.");
        if bytes.len() > 9 || (bytes.len() == 9 && bytes[8] & 0x7f != 0) {
            return Err(decode_error());
        }
        // The sign-magnitude value must fit i64, including i64::MIN, whose
        // magnitude is 2^63 and whose ninth byte must be 0x80.
        let value = as_number.to_i64().ok_or_else(decode_error)?;
        Ok(value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)))
    }
}

/// `OP_NUM2BIN`'s result: `minimal` written into `result`, zero bytes of the
/// size asked (allocated by the caller, fallibly), its sign bit moved to the
/// last byte.
fn pad_into(minimal: &[u8], result: &mut [u8]) {
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
