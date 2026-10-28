//! Script numbers under the length limit in force: the reads, the counts,
//! the pushed results and their overflow error. The encoding itself is
//! `ScriptNum`'s (`script_num.rs`).

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::script_num::ScriptNum;

use super::{reference_read, Spend};

impl Spend {
    /// The script-number length limit in force: `None` in the TypeScript
    /// default mode (the SDK reads a number of any length); under a word the
    /// reference's limit ([`ScriptFlags::max_script_num_length`](crate::script::ScriptFlags::max_script_num_length)) for the
    /// coin's era, following
    /// [`set_utxo_after_chronicle`](Self::set_utxo_after_chronicle), and on
    /// the mempool path the policy of
    /// [`set_script_num_length_policy`](Self::set_script_num_length_policy).
    /// Applied before the decode at every read (`script_num.cpp:62-68`), on
    /// every arithmetic result before it is pushed (`164`, `194`, `214`,
    /// `301-315`), at `OP_BIN2NUM`'s result (`interpreter.cpp:1789-1790`), and
    /// as 4 bytes on `OP_CHECKMULTISIG`'s counts (`1519-1525`, `1550-1552`).
    pub fn max_script_num_length(&self) -> Option<usize> {
        self.flags.map(|word| {
            word.max_script_num_length(self.utxo_after_chronicle, self.script_num_length_policy)
        })
    }

    /// The node's `-maxscriptnumlengthpolicy` for a word on the mempool path
    /// (`src/policy/policy.h:156`, 10,000 bytes by default; 0 selects the
    /// consensus limit of the coin's era). A block word and the default mode
    /// ignore it.
    pub fn set_script_num_length_policy(&mut self, bytes: usize) {
        self.script_num_length_policy = bytes;
    }

    // ========================================================================
    // Script numbers under the length limit
    // ========================================================================

    /// Decodes a stack element as a script number under `limit`: the length
    /// test precedes the decode and the minimal-encoding check, as on the
    /// reference (`script_num.cpp:62-68`; `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`,
    /// `interpreter.cpp:1807-1810`).
    /// `bytes` are popped and held off the stacks with `others` more bytes of
    /// the step's (its other operands), counted in an allocator's decline.
    pub(super) fn read_number_within(
        &self,
        bytes: &[u8],
        others: u64,
        limit: Option<usize>,
    ) -> Result<BigNumber, ScriptEvaluationError> {
        if let Some(max) = limit {
            if bytes.len() > max {
                return Err(self.overflow_error(bytes.len(), max));
            }
        }
        self.check_reference_read(bytes)?;
        // the digits, at most 7 bytes past the operand's, and a non-minimal
        // operand's shrink half again, asked first (bsv-rs#374)
        let len = bytes.len() as u64;
        self.number_room(len + others, len + len / 2 + 8)?;
        ScriptNum::from_bytes(bytes, self.require_minimal).map_err(|e| self.non_minimal(e))
    }

    /// A non-minimal number's refusal (`ScriptNum::from_bytes`'s one error):
    /// in the default mode the reference's words at every number site
    /// (`BigNumber.ts:1684`, `Spend.ts:547`; bsv-rs#397), under a word this
    /// crate's reader's.
    pub(super) fn non_minimal(&self, e: crate::Error) -> ScriptEvaluationError {
        match self.flags {
            None => self.error("non-minimally encoded script number"),
            Some(_) => self.error(&format!("Invalid script number: {}", e)),
        }
    }

    /// [`read_number`](Self::read_number)'s verdicts without the decode, so a
    /// guard can judge the operands' bytes before anything is allocated
    /// (bsv-rs#374): a non-minimal encoding is the read's own refusal, which
    /// `ScriptNum::from_bytes` makes before it copies a byte.
    pub(super) fn check_number(&self, bytes: &[u8]) -> Result<(), ScriptEvaluationError> {
        if self.require_minimal && !ScriptNum::is_minimally_encoded(bytes) {
            return self.read_number(bytes).map(drop);
        }
        self.check_reference_read(bytes)?;
        match self.max_script_num_length() {
            Some(max) if bytes.len() > max => Err(self.overflow_error(bytes.len(), max)),
            _ => Ok(()),
        }
    }

    /// In the default mode, the reference's read limit
    /// ([`reference_read`](super::reference_read)): a number it cannot read
    /// is the verdict it gives, in its words, after the minimal-encoding
    /// check it makes first (`BigNumber.fromScriptNum`, `BigNumber.ts:1681-1688`).
    fn check_reference_read(&self, bytes: &[u8]) -> Result<(), ScriptEvaluationError> {
        if self.flags.is_some() || (self.require_minimal && !ScriptNum::is_minimally_encoded(bytes))
        {
            return Ok(());
        }
        match reference_read::refusal(bytes) {
            Some(words) => Err(self.error(words)),
            None => Ok(()),
        }
    }

    /// A script number read under the limit in force
    /// ([`max_script_num_length`](Self::max_script_num_length)).
    pub(super) fn read_number(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_holding(bytes, 0)
    }

    /// [`read_number`](Self::read_number) while the step holds `others` bytes
    /// off the stacks beside `bytes` (a binary opcode's other operand).
    pub(super) fn read_number_holding(
        &self,
        bytes: &[u8],
        others: u64,
    ) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, others, self.max_script_num_length())
    }

    /// `OP_CHECKMULTISIG`'s two counts: 4-byte numbers in every era
    /// (`CScriptNum::MAXIMUM_ELEMENT_SIZE`, `interpreter.cpp:1519-1525`,
    /// `1550-1552`) under a word; the default mode reads them as the
    /// TypeScript SDK does.
    pub(super) fn read_count(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, 0, self.flags.map(|_| 4))
    }

    /// Pushes a computed number, refusing one longer than the limit in force
    /// before it reaches the stack (the reference bounds the results of `+`,
    /// `-`, `*` and the numeric shifts: `script_num.cpp:164`, `194`, `214`,
    /// `301-315`). The number is freed once encoded, before its bytes join
    /// the stack (bsv-rs#348).
    pub(super) fn push_number(&mut self, value: BigNumber) -> Result<(), ScriptEvaluationError> {
        let len = value.byte_length() + 1;
        let bytes = ScriptNum::try_to_bytes(&value)
            .map_err(|_| self.allocation_declined_holding(len as u64, len))?;
        drop(value);
        self.push_encoded_number(bytes)
    }

    /// [`push_number`](Self::push_number) of a number already encoded.
    pub(super) fn push_encoded_number(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<(), ScriptEvaluationError> {
        if let Some(max) = self.max_script_num_length() {
            if bytes.len() > max {
                return Err(self.overflow_error(bytes.len(), max));
            }
        }
        self.push_stack(bytes)
    }

    pub(super) fn overflow_error(&self, len: usize, max: usize) -> ScriptEvaluationError {
        self.error(&format!(
            "Script number overflow: {len} bytes, the limit is {max} bytes."
        ))
    }
}

/// A number named in an error's text: its decimal digits up to
/// [`NUMBER_TEXT_BYTES`] bytes of magnitude, its length beyond. A decimal
/// rendering costs about five times the number's bytes in scratch, and an
/// operand may be as long as the era's number length (32,000,000 bytes after
/// Chronicle): the refusal's text is not an allocation the budget pays for
/// (bsv-rs#349).
pub(super) fn number_text(value: &BigNumber) -> String {
    let len = value.byte_length();
    if len <= NUMBER_TEXT_BYTES {
        value.to_dec_string()
    } else {
        format!("a {len}-byte number")
    }
}

/// The longest magnitude [`number_text`] writes in decimal (at most 155
/// digits).
const NUMBER_TEXT_BYTES: usize = 64;
