//! Script numbers under the length limit in force: the reads, the counts,
//! the pushed results and their overflow error. The encoding itself is
//! `ScriptNum`'s (`script_num.rs`).

use crate::primitives::BigNumber;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::script_num::ScriptNum;

use super::Spend;

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
    pub(super) fn read_number_within(
        &self,
        bytes: &[u8],
        limit: Option<usize>,
    ) -> Result<BigNumber, ScriptEvaluationError> {
        if let Some(max) = limit {
            if bytes.len() > max {
                return Err(self.overflow_error(bytes.len(), max));
            }
        }
        ScriptNum::from_bytes(bytes, self.require_minimal)
            .map_err(|e| self.error(&format!("Invalid script number: {}", e)))
    }

    /// A script number read under the limit in force
    /// ([`max_script_num_length`](Self::max_script_num_length)).
    pub(super) fn read_number(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, self.max_script_num_length())
    }

    /// `OP_CHECKMULTISIG`'s two counts: 4-byte numbers in every era
    /// (`CScriptNum::MAXIMUM_ELEMENT_SIZE`, `interpreter.cpp:1519-1525`,
    /// `1550-1552`) under a word; the default mode reads them as the
    /// TypeScript SDK does.
    pub(super) fn read_count(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, self.flags.map(|_| 4))
    }

    /// Pushes a computed number, refusing one longer than the limit in force
    /// before it reaches the stack (the reference bounds the results of `+`,
    /// `-`, `*` and the numeric shifts: `script_num.cpp:164`, `194`, `214`,
    /// `301-315`).
    pub(super) fn push_number(&mut self, value: &BigNumber) -> Result<(), ScriptEvaluationError> {
        let bytes = ScriptNum::to_bytes(value);
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
