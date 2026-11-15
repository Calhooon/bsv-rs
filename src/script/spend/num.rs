//! Script numbers under the length limit in force.

use super::{ScriptEvaluationError, ScriptNum, Spend};
use crate::primitives::BigNumber;

impl Spend {
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
    /// `1550-1552`) under a word and for a coin from before Genesis; the
    /// default mode reads them as the TypeScript SDK does.
    pub(super) fn read_count(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        let four = self.flags.is_some() || self.pre_genesis();
        self.read_number_within(bytes, four.then_some(4))
    }

    /// Pushes a computed number, refusing one longer than the limit in force
    /// before it reaches the stack (the reference bounds the results of `+`,
    /// `-`, `*` and the numeric shifts: `script_num.cpp:164`, `194`, `214`,
    /// `301-315`). A coin from before Genesis bounds its operands, not its
    /// results: the node computes them as `int64` and pushes them at any
    /// length (`interpreter.cpp:1300-1301`, `CScriptNum`'s `int64` arm).
    pub(super) fn push_number(&mut self, value: &BigNumber) -> Result<(), ScriptEvaluationError> {
        let bytes = ScriptNum::to_bytes(value);
        if let Some(max) = self.max_script_num_length().filter(|_| !self.pre_genesis()) {
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
