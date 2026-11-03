//! The key's point at the two signature sites (#660).
//!
//! The node's encoding check, `CheckPubKeyEncoding` under STRICTENC
//! (bitcoin-sv v1.2.3 `interpreter.cpp:132-152,312-327`), reads a key's length
//! and prefix byte alone. A key whose point is off the curve, or whose x is at
//! or past the field prime, passes it, and the signature check fails on it
//! (`CheckSig`, `interpreter.cpp:2133-2163`; `CPubKey::Verify` failing
//! `secp256k1_ec_pubkey_parse`, `pubkey.cpp:183-194`): `<key> OP_CHECKSIG
//! OP_NOT` is valid there. This crate reads the point so in every mode.
//!
//! The reference's default reads the point at its encoding check instead
//! (`ts-stack@edf6e03` `Spend.ts:711-715`, `PublicKey.fromDER`): an off-curve
//! key is refused there in `The public key is in an unknown format.`, and an
//! x at or past p is reduced modulo p (`Point.ts:365-367`; ts-stack #1467).
//! That reading is a stated divergence, one switch away.

use crate::primitives::ec::PublicKey;
use crate::script::ScriptEvaluationError;

use super::Spend;

impl Spend {
    /// The switch: whether the reference's reading of a key's point applies.
    /// `false` is the node's reading in every mode; a fold to the reference's
    /// reading in the default mode alone returns `self.flags.is_none()`.
    fn reads_the_reference_point(&self) -> bool {
        false
    }

    /// The encoding check's part of the point: nothing under the node's
    /// reading; under the reference's, a point its `fromDER` cannot read is
    /// refused in its words.
    /// The refusal is unreachable while the switch is the literal `false`, so the
    /// `Ok(())` mutant is a declared equivalence (`.cargo/mutants.toml`, #684).
    pub(super) fn check_public_key_point(
        &self,
        pubkey: &[u8],
    ) -> Result<(), ScriptEvaluationError> {
        if self.reads_the_reference_point() && PublicKey::from_reference_der(pubkey).is_err() {
            return Err(self.error("The public key is in an unknown format."));
        }
        Ok(())
    }

    /// The key the signature check verifies against: `None`, the check's
    /// false, for bytes that are no point, never a refusal (rule 5).
    pub(super) fn signature_key(&self, pubkey: &[u8]) -> Option<PublicKey> {
        if self.reads_the_reference_point() {
            PublicKey::from_reference_der(pubkey).ok()
        } else {
            PublicKey::from_bytes(pubkey).ok()
        }
    }
}

#[cfg(test)]
#[path = "key_point_tests.rs"]
mod tests;
