//! Signature encoding order and the default mode's visible refusal (#417).
//! Spend.ts:609-629 checks hash type, fork ID, then low-S inside a catch
//! that replaces inner errors when DER is enforced (always without a word).
//! A word retains the node's DER, low-S, hash-type order and distinct words.

use crate::primitives::bsv::sighash::SIGHASH_FORKID;
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::script::ScriptEvaluationError;

use super::crypto::{is_valid_signature_encoding, signature_overflows_the_order};
use super::Spend;

impl Spend {
    pub(super) fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), ScriptEvaluationError> {
        if sig.is_empty() {
            return Ok(());
        }
        if !is_valid_signature_encoding(sig) {
            return Err(self.error("The signature format is invalid."));
        }
        let tx_sig = TransactionSignature::from_checksig_format(sig)
            .map_err(|_| self.error("The signature format is invalid."))?;

        if self.flags.is_none() && self.transaction_version <= 1 {
            self.check_default_signature_requirements(&tx_sig)
                .map_err(|_| self.error("The signature format is invalid."))?;
        } else {
            self.check_low_s(&tx_sig)?;
            self.check_signature_hash_type(tx_sig.scope())?;
        }

        // Preserve the existing FORKID requirement, including under a word.
        if (tx_sig.scope() & SIGHASH_FORKID) == 0 {
            return Err(self.error("The signature must use SIGHASH_FORKID."));
        }
        Ok(())
    }

    fn check_default_signature_requirements(
        &self,
        sig: &TransactionSignature,
    ) -> Result<(), ScriptEvaluationError> {
        // The reference's default fork-ID check is a no-op (Spend.ts:596).
        // Version-2 undefined-type words stay as pinned by the #23 witness;
        // #417 changes the strict version-1 path only.
        self.check_signature_hash_type(sig.scope())?;
        self.check_low_s(sig)
    }

    fn check_low_s(&self, sig: &TransactionSignature) -> Result<(), ScriptEvaluationError> {
        // Preserve #14's order-overflow exception in both modes: the node's
        // lax parser turns r or s >= n into the all-zero signature, which is
        // low (pubkey.cpp:146-173, :356-365). Only n/2 < s < n is refused.
        if self.require_low_s && !sig.has_low_s() && !signature_overflows_the_order(sig) {
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
        let sig = TransactionSignature::from_checksig_format(&unlock[1..]).unwrap();
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
