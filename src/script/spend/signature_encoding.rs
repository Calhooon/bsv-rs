//! Signature encoding order and the default mode's visible refusal (#417).
//! Spend.ts:609-629 checks hash type, fork ID, then low-S inside a catch
//! that replaces inner errors when DER is enforced (always without a word).
//! A word retains the node's DER, low-S, hash-type order and distinct words.
//! After the strict encoding check the signature is read by the mode's judge
//! (`signature_read.rs`, #842's fold): the node's lax parse under a word, the
//! reference's `fromDER` without one.

use crate::script::ScriptEvaluationError;

use super::crypto::is_valid_signature_encoding;
use super::hash_type::relaxed_by_default;
use super::signature_read::{self, ScriptSignature};
use super::Spend;

impl Spend {
    pub(super) fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), ScriptEvaluationError> {
        if sig.is_empty() {
            return Ok(());
        }
        if !is_valid_signature_encoding(sig) {
            return Err(self.error("The signature format is invalid."));
        }
        let tx_sig = self
            .read_signature(sig)
            .ok_or_else(|| self.error("The signature format is invalid."))?;

        if self.flags.is_none() && !relaxed_by_default(self.transaction_version) {
            self.check_default_signature_requirements(&tx_sig)
                .map_err(|_| self.error("The signature format is invalid."))?;
        } else {
            self.check_low_s(&tx_sig)?;
            self.check_signature_hash_type(tx_sig.scope)?;
        }

        // The SDK default skips the fork-ID gate (Spend.ts:595-604).
        // Every supported word requires FORKID and implies STRICTENC,
        // as VerifyScript does (interpreter.cpp:2315-2318).
        if self.flags.is_some() && !tx_sig.has_forkid() {
            return Err(self.error("The signature must use SIGHASH_FORKID."));
        }
        Ok(())
    }

    /// The signature as the mode's judge reads it, at the encoding check and
    /// at the signature check alike (`signature_read.rs`): under a word the
    /// node's lax parse, without one the reference's `fromDER`. `None` is a
    /// reading that refuses: the reference's refusal in the default mode, the
    /// lax parse's 0 under a word (which BIP 66 leaves no signature to reach).
    pub(super) fn read_signature(&self, sig: &[u8]) -> Option<ScriptSignature> {
        if self.flags.is_some() {
            signature_read::under_word(sig)
        } else {
            signature_read::by_default(sig).ok()
        }
    }

    fn check_default_signature_requirements(
        &self,
        sig: &ScriptSignature,
    ) -> Result<(), ScriptEvaluationError> {
        // The default fork-ID check is a no-op at every version (#429).
        // Version-2 undefined-type words stay as pinned by the #23 witness.
        self.check_signature_hash_type(sig.scope)?;
        self.check_low_s(sig)
    }

    fn check_low_s(&self, sig: &ScriptSignature) -> Result<(), ScriptEvaluationError> {
        // The low-S predicate is the reading's (`signature_read.rs`): under a
        // word the node's on the lax parse, where r or s at or above the
        // order, or past 32 bytes, is the all-zero signature, which is low
        // (pubkey.cpp:32-175, :353-363; #14 and #847 by one reading); in the
        // default mode the reference's, #14's order exception kept.
        if self.require_low_s && !sig.low_s {
            return Err(self.error("The signature must have a low S value."));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::from_hex;
    use crate::script::{LockingScript, SpendParams, UnlockingScript};

    #[test]
    fn issue_417_default_checks_hash_type_before_low_s_even_when_both_fail() {
        let recording: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/script_signature_words_417.json"
        ))
        .unwrap();
        let case = recording["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "undefined-hash-type-and-high-s")
            .unwrap();
        let unlock = from_hex(case["unlock"].as_str().unwrap()).unwrap();
        let sig = signature_read::by_default(&unlock[1..]).unwrap();
        let spend = Spend::new(SpendParams {
            source_txid: [0; 32],
            source_output_index: 0,
            source_satoshis: 1,
            locking_script: LockingScript::new(),
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::new(),
            input_sequence: u32::MAX,
            lock_time: 0,
            memory_limit: None,
            work_limit: None,
        });
        assert_eq!(
            spend.check_low_s(&sig).unwrap_err().message,
            "The signature must have a low S value."
        );
        assert_eq!(
            spend
                .check_default_signature_requirements(&sig)
                .unwrap_err()
                .message,
            "The signature's hash type (0x44) has no defined base type."
        );
    }
}
