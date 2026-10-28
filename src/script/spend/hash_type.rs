//! Signature hash-type legality. The default's Chronicle gate is the
//! transaction version; under a word it is CHRONICLE, independently of the
//! UTXO's opcode/number-length era (bsv-rs#22, #397).

use crate::primitives::bsv::sighash::{
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_CHRONICLE, SIGHASH_FORKID, SIGHASH_SINGLE,
};
use crate::script::{ScriptEvaluationError, ScriptFlags};

use super::Spend;

impl Spend {
    pub(super) fn check_signature_hash_type(
        &self,
        scope: u32,
    ) -> Result<(), ScriptEvaluationError> {
        // STRICTENC (interpreter.cpp:291-294; sighashtype.h:82-90): ALL,
        // NONE or SINGLE after clearing the three modifier bits. Both node
        // words and the default mode check this (bsv-rs#23).
        if self
            .flags
            .is_none_or(|word| word.contains(ScriptFlags::STRICTENC))
        {
            let base = scope & !(SIGHASH_CHRONICLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);
            if !(SIGHASH_ALL..=SIGHASH_SINGLE).contains(&base) {
                return Err(self.error(&format!(
                    "The signature's hash type (0x{scope:02x}) has no defined base type."
                )));
            }
        }

        if scope & SIGHASH_CHRONICLE != 0 {
            match self.flags {
                // Node STRICTENC (interpreter.cpp:296-303): CHRONICLE,
                // not UTXO_AFTER_CHRONICLE. Keep #22's word and message.
                Some(word)
                    if word.contains(ScriptFlags::STRICTENC)
                        && !word.contains(ScriptFlags::CHRONICLE) =>
                {
                    return Err(self
                        .error("The signature must not use SIGHASH_CHRONICLE before Chronicle."));
                }
                // Spend.ts:586-591, :338-341: the default uses version > 1.
                // The keeper's #397 fold requires this inner gate's words;
                // TS :622-625 wraps them in its generic signature error.
                None if self.transaction_version <= 1 => {
                    return Err(self.error("The signature hash type is invalid before Chronicle."));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
