//! Multisig (M-of-N) script template.
//!
//! This module provides the [`Multisig`] template for creating and spending
//! M-of-N multi-signature outputs using OP_CHECKMULTISIG.
//!
//! # Locking Script Pattern
//!
//! ```text
//! OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
//! ```
//!
//! # Unlocking Script Pattern
//!
//! ```text
//! OP_0 <sig1> <sig2> ... <sigM>
//! ```
//!
//! The leading OP_0 is required due to a historical off-by-one bug in
//! Bitcoin's OP_CHECKMULTISIG implementation.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::Multisig;
//! use bsv_sdk::script::template::SignOutputs;
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let key1 = PrivateKey::random();
//! let key2 = PrivateKey::random();
//! let key3 = PrivateKey::random();
//!
//! // Create 2-of-3 multisig locking script
//! let template = Multisig::new(2);
//! let pubkeys = vec![
//!     key1.public_key(),
//!     key2.public_key(),
//!     key3.public_key(),
//! ];
//! let locking = template.lock_from_keys(&pubkeys)?;
//!
//! // Sign with keys 1 and 3 (in order matching the locking script)
//! let signers = vec![key1.clone(), key3.clone()];
//! let unlock = Multisig::unlock(&signers, SignOutputs::All, false);
//! let unlocking = unlock.sign(&context)?;
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

/// Converts a small integer (1-16) to its opcode (OP_1 through OP_16).
fn small_int_to_opcode(n: u8) -> Result<u8> {
    if (1..=16).contains(&n) {
        Ok(OP_1 + n - 1)
    } else {
        Err(Error::CryptoError(format!(
            "Value {} out of range for small int opcode (1-16)",
            n
        )))
    }
}

/// Multisig (M-of-N) script template.
///
/// Creates scripts that require M signatures from a set of N public keys.
/// The threshold M is stored in the template; the public keys are provided
/// when creating the locking script.
///
/// # Signature Order
///
/// Signatures in the unlocking script must appear in the same order as their
/// corresponding public keys in the locking script. The OP_CHECKMULTISIG
/// opcode walks through keys and signatures in order, matching each signature
/// to the next available key.
#[derive(Debug, Clone)]
pub struct Multisig {
    /// M — the number of required signatures.
    pub threshold: u8,
}

impl Multisig {
    /// Creates a new Multisig template with the given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The number of signatures required (M). Must be 1-16.
    pub fn new(threshold: u8) -> Self {
        Self { threshold }
    }

    /// Creates a multisig locking script from public keys.
    ///
    /// This is the recommended API. Keys are encoded in compressed form (33 bytes).
    ///
    /// # Arguments
    ///
    /// * `pubkeys` - The N public keys. Must have 1-16 keys, and threshold <= N.
    pub fn lock_from_keys(&self, pubkeys: &[PublicKey]) -> Result<LockingScript> {
        let m = self.threshold;
        let n = pubkeys.len();

        if m == 0 || m > 16 {
            return Err(Error::CryptoError(format!(
                "Threshold must be 1-16, got {}",
                m
            )));
        }
        if n == 0 || n > 16 {
            return Err(Error::CryptoError(format!(
                "Number of keys must be 1-16, got {}",
                n
            )));
        }
        if (m as usize) > n {
            return Err(Error::CryptoError(format!(
                "Threshold {} exceeds number of keys {}",
                m, n
            )));
        }

        let mut chunks = Vec::with_capacity(n + 3);

        // OP_M
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(m)?));

        // Push each compressed pubkey
        for pk in pubkeys {
            let compressed = pk.to_compressed();
            chunks.push(ScriptChunk::new(
                compressed.len() as u8,
                Some(compressed.to_vec()),
            ));
        }

        // OP_N
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(n as u8)?));

        // OP_CHECKMULTISIG
        chunks.push(ScriptChunk::new_opcode(OP_CHECKMULTISIG));

        Ok(LockingScript::from_chunks(chunks))
    }

    /// Creates an unlock template for spending a multisig output.
    ///
    /// # Arguments
    ///
    /// * `signers` - The M private keys to sign with. Must be in the same
    ///   order as their corresponding public keys appear in the locking script.
    /// * `sign_outputs` - Which outputs to sign.
    /// * `anyone_can_pay` - Whether to allow other inputs to be added.
    pub fn unlock(
        signers: &[PrivateKey],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let keys: Vec<PrivateKey> = signers.to_vec();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);
        let m = keys.len();

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                let sighash = context.compute_sighash(scope)?;

                let mut script = Script::new();
                // OP_0 dummy element (required by OP_CHECKMULTISIG off-by-one bug)
                script.write_opcode(OP_0);

                for key in &keys {
                    let signature = key.sign(&sighash)?;
                    let tx_sig = TransactionSignature::new(signature, scope);
                    script.write_bin(&tx_sig.to_checksig_format());
                }

                Ok(UnlockingScript::from_script(script))
            },
            move || {
                // OP_0 (1 byte) + M signatures (1 push + 72 DER max + 1 sighash each)
                1 + m * 74
            },
        )
    }

    /// Signs with a precomputed sighash.
    ///
    /// # Arguments
    ///
    /// * `signers` - The M private keys to sign with (in pubkey order).
    /// * `sighash` - The precomputed sighash to sign.
    /// * `sign_outputs` - Which outputs to sign (for the scope byte).
    /// * `anyone_can_pay` - Whether to allow other inputs to be added.
    pub fn sign_with_sighash(
        signers: &[PrivateKey],
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        let mut script = Script::new();
        // OP_0 dummy element
        script.write_opcode(OP_0);

        for key in signers {
            let signature = key.sign(sighash)?;
            let tx_sig = TransactionSignature::new(signature, scope);
            script.write_bin(&tx_sig.to_checksig_format());
        }

        Ok(UnlockingScript::from_script(script))
    }
}

impl ScriptTemplate for Multisig {
    /// Creates a multisig locking script from concatenated 33-byte compressed public keys.
    ///
    /// The `params` slice must be a multiple of 33 bytes (each key is 33 bytes compressed).
    fn lock(&self, params: &[u8]) -> Result<LockingScript> {
        if params.is_empty() || !params.len().is_multiple_of(33) {
            return Err(Error::CryptoError(
                "Params must be concatenated 33-byte compressed public keys".to_string(),
            ));
        }

        let n = params.len() / 33;
        if n > 16 {
            return Err(Error::CryptoError(format!("Too many keys: {} (max 16)", n)));
        }
        if (self.threshold as usize) > n {
            return Err(Error::CryptoError(format!(
                "Threshold {} exceeds number of keys {}",
                self.threshold, n
            )));
        }

        let mut chunks = Vec::with_capacity(n + 3);
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(
            self.threshold,
        )?));

        for i in 0..n {
            let pk_bytes = &params[i * 33..(i + 1) * 33];
            chunks.push(ScriptChunk::new(33, Some(pk_bytes.to_vec())));
        }

        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(n as u8)?));
        chunks.push(ScriptChunk::new_opcode(OP_CHECKMULTISIG));

        Ok(LockingScript::from_chunks(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig_2_of_3_lock() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let template = Multisig::new(2);
        let locking = template
            .lock_from_keys(&[key1.public_key(), key2.public_key(), key3.public_key()])
            .unwrap();

        let chunks = locking.chunks();
        // OP_2 + 3 pubkeys + OP_3 + OP_CHECKMULTISIG = 6 chunks
        assert_eq!(chunks.len(), 6);

        // First chunk: OP_2
        assert_eq!(chunks[0].op, OP_2);

        // Middle chunks: 33-byte pubkeys
        for chunk in chunks.iter().take(3 + 1).skip(1) {
            assert_eq!(chunk.data.as_ref().unwrap().len(), 33);
        }

        // OP_3
        assert_eq!(chunks[4].op, OP_3);

        // OP_CHECKMULTISIG
        assert_eq!(chunks[5].op, OP_CHECKMULTISIG);

        // Script detection
        assert_eq!(locking.as_script().is_multisig(), Some((2, 3)));
    }

    #[test]
    fn test_multisig_1_of_1_lock() {
        let key = PrivateKey::random();

        let template = Multisig::new(1);
        let locking = template.lock_from_keys(&[key.public_key()]).unwrap();

        assert_eq!(locking.as_script().is_multisig(), Some((1, 1)));
    }

    #[test]
    fn test_multisig_invalid_threshold_exceeds_keys() {
        let key = PrivateKey::random();
        let template = Multisig::new(3);
        assert!(template.lock_from_keys(&[key.public_key()]).is_err());
    }

    #[test]
    fn test_multisig_invalid_zero_threshold() {
        let key = PrivateKey::random();
        let template = Multisig::new(0);
        assert!(template.lock_from_keys(&[key.public_key()]).is_err());
    }

    #[test]
    fn test_multisig_invalid_too_many_keys() {
        let keys: Vec<PublicKey> = (0..17).map(|_| PrivateKey::random().public_key()).collect();
        let template = Multisig::new(1);
        assert!(template.lock_from_keys(&keys).is_err());
    }

    #[test]
    fn test_multisig_unlock_has_dummy_op_0() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let sighash = [1u8; 32];

        let unlocking =
            Multisig::sign_with_sighash(&[key1, key2], &sighash, SignOutputs::All, false).unwrap();

        let chunks = unlocking.chunks();
        // OP_0 + 2 signatures = 3 chunks
        assert_eq!(chunks.len(), 3);

        // First chunk must be OP_0
        assert_eq!(chunks[0].op, OP_0);
        assert!(chunks[0].data.is_none());

        // Second and third chunks are signatures
        for chunk in chunks.iter().take(2 + 1).skip(1) {
            let sig = chunk.data.as_ref().unwrap();
            assert!(sig.len() >= 70 && sig.len() <= 73);
            assert_eq!(*sig.last().unwrap(), 0x41u8);
        }
    }

    #[test]
    fn test_multisig_estimate_length() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let unlock = Multisig::unlock(&[key1, key2], SignOutputs::All, false);
        // OP_0 (1) + 2 * (1 push + 73 max sig) = 1 + 148 = 149
        assert_eq!(unlock.estimate_length(), 149);
    }

    #[test]
    fn test_multisig_trait_lock_concatenated_keys() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let pk1 = key1.public_key().to_compressed();
        let pk2 = key2.public_key().to_compressed();

        let mut params = Vec::with_capacity(66);
        params.extend_from_slice(&pk1);
        params.extend_from_slice(&pk2);

        let template = Multisig::new(1);
        let locking = template.lock(&params).unwrap();

        assert_eq!(locking.as_script().is_multisig(), Some((1, 2)));
    }

    #[test]
    fn test_multisig_trait_lock_invalid_params() {
        let template = Multisig::new(1);

        // Empty
        assert!(template.lock(&[]).is_err());

        // Not a multiple of 33
        assert!(template.lock(&[0x02; 34]).is_err());
    }

    #[test]
    fn test_multisig_asm() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let template = Multisig::new(2);
        let locking = template
            .lock_from_keys(&[key1.public_key(), key2.public_key()])
            .unwrap();

        let asm = locking.to_asm();
        assert!(asm.contains("OP_2"));
        assert!(asm.contains("OP_CHECKMULTISIG"));
    }

    #[test]
    fn test_small_int_to_opcode() {
        assert_eq!(small_int_to_opcode(1).unwrap(), OP_1);
        assert_eq!(small_int_to_opcode(2).unwrap(), OP_2);
        assert_eq!(small_int_to_opcode(16).unwrap(), OP_16);
        assert!(small_int_to_opcode(0).is_err());
        assert!(small_int_to_opcode(17).is_err());
    }
}
