//! Signature hash-type legality. The default's Chronicle gate is the
//! transaction version, refused in the reference's visible words; under a word
//! it is CHRONICLE, independently of the UTXO's opcode/number-length era
//! (bsv-rs#22, #397).

use crate::primitives::bsv::sighash::{
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_CHRONICLE, SIGHASH_FORKID, SIGHASH_SINGLE,
};
use crate::script::{ScriptEvaluationError, ScriptFlags};

use super::Spend;

/// The default mode's relaxation as the reference computes it: `#isRelaxed()`
/// is `transactionVersion > 1` (`Spend.ts:319-321` at `ts-stack@edf6e03`) on
/// the number `readUInt32LE` read (`Transaction.ts:471`), so a version at or
/// above 2^31 is relaxed there; the parameter's bits are the wire's four bytes
/// (#418). A word keeps the node's `int32_t` (`interpreter.cpp:34-44`).
pub(super) const fn relaxed_by_default(version: i32) -> bool {
    version as u32 > 1
}

impl Spend {
    pub(super) fn check_signature_hash_type(
        &self,
        scope: u32,
    ) -> Result<(), ScriptEvaluationError> {
        // STRICTENC (interpreter.cpp:291-294; sighashtype.h:82-90): ALL,
        // NONE or SINGLE after clearing the three modifier bits. Both node
        // words and the default mode check this (bsv-rs#23). At version 1
        // the default caller wraps this reason in the DER words (#417).
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
                // Spend.ts:586-591, :338-341: the default uses version > 1,
                // read unsigned as the reference reads it (#418).
                // The gate's own text (`... invalid before Chronicle.`) is
                // thrown inside the try at :614-622, whose catch (:622-625) rethrows the
                // DER wrapper's words (the default always enforces DER,
                // :376-386); the caller sees only those.
                None if !relaxed_by_default(self.transaction_version) => {
                    return Err(self.error("The signature format is invalid."));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
