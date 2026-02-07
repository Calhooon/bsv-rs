//! P2PK (Pay-to-Public-Key) script template.
//!
//! This module provides the [`P2PK`] template for creating and spending
//! Pay-to-Public-Key outputs. P2PK is simpler than P2PKH — it locks directly
//! to a public key rather than its hash. The unlock only needs a signature
//! (the public key is already in the locking script).
//!
//! # Locking Script Pattern
//!
//! ```text
//! <pubkey> OP_CHECKSIG
//! ```
//!
//! # Unlocking Script Pattern
//!
//! ```text
//! <signature>
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::P2PK;
//! use bsv_sdk::script::template::{ScriptTemplate, SignOutputs};
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let pubkey = private_key.public_key().to_compressed();
//!
//! // Create locking script
//! let template = P2PK::new();
//! let locking = template.lock(&pubkey)?;
//!
//! // Create unlock template
//! let unlock = P2PK::unlock(&private_key, SignOutputs::All, false);
//! let unlocking = unlock.sign(&signing_context)?;
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::PrivateKey;
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

/// P2PK (Pay-to-Public-Key) script template.
///
/// Locks funds to a public key directly. Simpler than P2PKH but reveals the
/// public key in the locking script (before spending).
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PK;

impl P2PK {
    /// Creates a new P2PK template instance.
    pub fn new() -> Self {
        Self
    }

    /// Creates an unlock template for spending a P2PK output.
    ///
    /// Unlike P2PKH, only a signature is needed (the public key is already
    /// in the locking script).
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let key = private_key.clone();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                let sighash = context.compute_sighash(scope)?;
                let signature = key.sign(&sighash)?;
                let tx_sig = TransactionSignature::new(signature, scope);
                let sig_bytes = tx_sig.to_checksig_format();

                let mut script = Script::new();
                script.write_bin(&sig_bytes);

                Ok(UnlockingScript::from_script(script))
            },
            || {
                // Estimate length: signature only (1 push + 72 DER max + 1 sighash byte)
                74
            },
        )
    }

    /// Signs with a precomputed sighash.
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);
        let signature = private_key.sign(sighash)?;
        let tx_sig = TransactionSignature::new(signature, scope);
        let sig_bytes = tx_sig.to_checksig_format();

        let mut script = Script::new();
        script.write_bin(&sig_bytes);

        Ok(UnlockingScript::from_script(script))
    }
}

impl ScriptTemplate for P2PK {
    /// Creates a P2PK locking script from a compressed (33-byte) or
    /// uncompressed (65-byte) public key.
    fn lock(&self, params: &[u8]) -> Result<LockingScript> {
        if params.len() != 33 && params.len() != 65 {
            return Err(Error::InvalidDataLength {
                expected: 33,
                actual: params.len(),
            });
        }

        // Validate key prefix
        match params[0] {
            0x02 | 0x03 if params.len() == 33 => {}
            0x04 | 0x06 | 0x07 if params.len() == 65 => {}
            _ => {
                return Err(Error::InvalidPublicKey(
                    "Invalid public key prefix".to_string(),
                ));
            }
        }

        let chunks = vec![
            ScriptChunk::new(params.len() as u8, Some(params.to_vec())),
            ScriptChunk::new_opcode(OP_CHECKSIG),
        ];

        Ok(LockingScript::from_chunks(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pk_lock_compressed() {
        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pubkey = private_key.public_key().to_compressed();

        let template = P2PK::new();
        let locking = template.lock(&pubkey).unwrap();

        // Should be: <33 bytes> OP_CHECKSIG
        let chunks = locking.chunks();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].data.as_ref().unwrap().len(), 33);
        assert_eq!(chunks[1].op, OP_CHECKSIG);

        // Verify script detection
        assert!(locking.as_script().is_p2pk());
    }

    #[test]
    fn test_p2pk_lock_invalid_length() {
        let template = P2PK::new();

        assert!(template.lock(&[0x02; 20]).is_err());
        assert!(template.lock(&[0x02; 32]).is_err());
        assert!(template.lock(&[0x02; 34]).is_err());
    }

    #[test]
    fn test_p2pk_lock_invalid_prefix() {
        let template = P2PK::new();

        // 33 bytes but wrong prefix
        let mut bad_key = [0u8; 33];
        bad_key[0] = 0x05;
        assert!(template.lock(&bad_key).is_err());
    }

    #[test]
    fn test_p2pk_unlock_signature_only() {
        let private_key = PrivateKey::random();
        let sighash = [1u8; 32];

        let unlocking =
            P2PK::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();

        // Should have exactly 1 chunk: the signature
        let chunks = unlocking.chunks();
        assert_eq!(chunks.len(), 1);

        let sig_data = chunks[0].data.as_ref().unwrap();
        assert!(sig_data.len() >= 70 && sig_data.len() <= 73);
        assert_eq!(*sig_data.last().unwrap(), 0x41u8); // SIGHASH_ALL | SIGHASH_FORKID
    }

    #[test]
    fn test_p2pk_estimate_length() {
        let private_key = PrivateKey::random();
        let unlock = P2PK::unlock(&private_key, SignOutputs::All, false);
        assert_eq!(unlock.estimate_length(), 74);
    }

    #[test]
    fn test_p2pk_asm() {
        let private_key = PrivateKey::random();
        let pubkey = private_key.public_key().to_compressed();

        let template = P2PK::new();
        let locking = template.lock(&pubkey).unwrap();

        let asm = locking.to_asm();
        assert!(asm.contains("OP_CHECKSIG"));
        assert!(!asm.contains("OP_DUP")); // No DUP in P2PK (that's P2PKH)
        assert!(!asm.contains("OP_HASH160")); // No HASH160 in P2PK
    }
}
