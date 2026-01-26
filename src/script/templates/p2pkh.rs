//! P2PKH (Pay-to-Public-Key-Hash) script template.
//!
//! This module provides the [`P2PKH`] template for creating and spending
//! Pay-to-Public-Key-Hash outputs, the most common Bitcoin transaction type.
//!
//! # Locking Script Pattern
//!
//! ```text
//! OP_DUP OP_HASH160 <20-byte pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
//! ```
//!
//! # Unlocking Script Pattern
//!
//! ```text
//! <signature> <publicKey>
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::P2PKH;
//! use bsv_sdk::script::template::{ScriptTemplate, SignOutputs, SigningContext};
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let pubkey_hash = private_key.public_key().hash160();
//!
//! // Create locking script
//! let template = P2PKH::new();
//! let locking = template.lock(&pubkey_hash)?;
//!
//! // Create unlock template
//! let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
//!
//! // Sign a transaction
//! let unlocking = unlock.sign(&signing_context)?;
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::PrivateKey;
use crate::primitives::encoding::from_base58_check;
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

/// P2PKH (Pay-to-Public-Key-Hash) script template.
///
/// This is the most common Bitcoin transaction type. The locking script requires
/// a signature that matches the public key whose hash is embedded in the script.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::script::templates::P2PKH;
/// use bsv_sdk::script::template::ScriptTemplate;
///
/// let template = P2PKH::new();
///
/// // Lock to a pubkey hash
/// let locking = template.lock(&pubkey_hash)?;
///
/// // Or lock to an address string
/// let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PKH;

impl P2PKH {
    /// Creates a new P2PKH template instance.
    pub fn new() -> Self {
        Self
    }

    /// Creates a P2PKH locking script from an address string.
    ///
    /// Supports both mainnet (prefix 0x00) and testnet (prefix 0x6f) addresses.
    ///
    /// # Arguments
    ///
    /// * `address` - A P2PKH address string
    ///
    /// # Returns
    ///
    /// The locking script, or an error if the address is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_sdk::script::templates::P2PKH;
    ///
    /// let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
    /// ```
    pub fn lock_from_address(address: &str) -> Result<LockingScript> {
        let (version, payload) = from_base58_check(address)?;

        // Check version byte: 0x00 (mainnet) or 0x6f (testnet)
        if version.len() != 1 || (version[0] != 0x00 && version[0] != 0x6f) {
            return Err(Error::CryptoError(format!(
                "Invalid P2PKH address version: expected 0x00 or 0x6f, got 0x{:02x}",
                version.first().unwrap_or(&0)
            )));
        }

        if payload.len() != 20 {
            return Err(Error::InvalidDataLength {
                expected: 20,
                actual: payload.len(),
            });
        }

        P2PKH::new().lock(&payload)
    }

    /// Creates an unlock template for spending a P2PKH output.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key for signing
    /// * `sign_outputs` - Which outputs to sign
    /// * `anyone_can_pay` - Whether to allow other inputs to be added
    ///
    /// # Returns
    ///
    /// A [`ScriptTemplateUnlock`] that can sign transaction inputs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_sdk::script::templates::P2PKH;
    /// use bsv_sdk::script::template::{SignOutputs, SigningContext};
    /// use bsv_sdk::primitives::ec::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
    ///
    /// // Create signing context
    /// let context = SigningContext::new(
    ///     &raw_tx,
    ///     0,  // input index
    ///     100_000,  // satoshis
    ///     &locking_script,
    /// );
    ///
    /// // Sign
    /// let unlocking_script = unlock.sign(&context)?;
    /// ```
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let key = private_key.clone();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                // Compute the sighash
                let sighash = context.compute_sighash(scope)?;

                // Sign the sighash
                let signature = key.sign(&sighash)?;
                let tx_sig = TransactionSignature::new(signature, scope);

                // Build the unlocking script
                let sig_bytes = tx_sig.to_checksig_format();
                let pubkey_bytes = key.public_key().to_compressed();

                let mut script = Script::new();
                script.write_bin(&sig_bytes).write_bin(&pubkey_bytes);

                Ok(UnlockingScript::from_script(script))
            },
            || {
                // Estimate length: signature (1 push + 73 bytes max) + pubkey (1 push + 33 bytes)
                // = 1 + 73 + 1 + 33 = 108 bytes
                108
            },
        )
    }

    /// Creates an unlock template that signs with a precomputed sighash.
    ///
    /// This is useful when you already have the sighash computed and don't
    /// need to parse the transaction.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key for signing
    /// * `sighash` - The precomputed sighash to sign
    /// * `sign_outputs` - Which outputs to sign (for the scope byte)
    /// * `anyone_can_pay` - Whether to allow other inputs to be added
    ///
    /// # Returns
    ///
    /// The unlocking script.
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        // Sign the sighash
        let signature = private_key.sign(sighash)?;
        let tx_sig = TransactionSignature::new(signature, scope);

        // Build the unlocking script
        let sig_bytes = tx_sig.to_checksig_format();
        let pubkey_bytes = private_key.public_key().to_compressed();

        let mut script = Script::new();
        script.write_bin(&sig_bytes).write_bin(&pubkey_bytes);

        Ok(UnlockingScript::from_script(script))
    }
}

impl ScriptTemplate for P2PKH {
    /// Creates a P2PKH locking script from a 20-byte public key hash.
    ///
    /// # Arguments
    ///
    /// * `params` - The 20-byte public key hash
    ///
    /// # Returns
    ///
    /// The locking script, or an error if the hash is not 20 bytes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_sdk::script::templates::P2PKH;
    /// use bsv_sdk::script::template::ScriptTemplate;
    ///
    /// let template = P2PKH::new();
    /// let locking = template.lock(&pubkey_hash)?;
    /// ```
    fn lock(&self, params: &[u8]) -> Result<LockingScript> {
        if params.len() != 20 {
            return Err(Error::InvalidDataLength {
                expected: 20,
                actual: params.len(),
            });
        }

        // Build the P2PKH locking script:
        // OP_DUP OP_HASH160 <20-byte pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let chunks = vec![
            ScriptChunk::new_opcode(OP_DUP),
            ScriptChunk::new_opcode(OP_HASH160),
            ScriptChunk::new(params.len() as u8, Some(params.to_vec())),
            ScriptChunk::new_opcode(OP_EQUALVERIFY),
            ScriptChunk::new_opcode(OP_CHECKSIG),
        ];

        Ok(LockingScript::from_chunks(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_lock_from_pubkey_hash() {
        let pubkey_hash = [0u8; 20];
        let template = P2PKH::new();
        let locking = template.lock(&pubkey_hash).unwrap();

        // Should produce: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        // Hex: 76 a9 14 <20 zeros> 88 ac
        let expected_hex = "76a914000000000000000000000000000000000000000088ac";
        assert_eq!(locking.to_hex(), expected_hex);
    }

    #[test]
    fn test_p2pkh_lock_invalid_length() {
        let template = P2PKH::new();

        // Too short
        let result = template.lock(&[0u8; 19]);
        assert!(result.is_err());

        // Too long
        let result = template.lock(&[0u8; 21]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2pkh_lock_from_address() {
        // This is a valid mainnet address for pubkey hash of all zeros
        // Address: 1111111111111111111114oLvT2
        // Actually let's test with a known address
        // The address for pubkey hash of 20 zeros is: 1111111111111111111114oLvT2

        // For testing, let's create a simple test
        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pubkey_hash = private_key.public_key().hash160();
        let address = private_key.public_key().to_address();

        let locking = P2PKH::lock_from_address(&address).unwrap();
        let expected = P2PKH::new().lock(&pubkey_hash).unwrap();

        assert_eq!(locking.to_hex(), expected.to_hex());
    }

    #[test]
    fn test_p2pkh_lock_from_address_invalid() {
        // Invalid address (bad checksum)
        let result = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3");
        assert!(result.is_err());
    }

    #[test]
    fn test_p2pkh_estimate_length() {
        let private_key = PrivateKey::random();
        let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);

        // Should estimate 108 bytes
        assert_eq!(unlock.estimate_length(), 108);
    }

    #[test]
    fn test_p2pkh_unlock_creates_valid_script() {
        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Create a simple test case with a mock sighash
        let sighash = [1u8; 32];
        let unlocking =
            P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();

        // The unlocking script should have 2 chunks: signature and pubkey
        let chunks = unlocking.chunks();
        assert_eq!(chunks.len(), 2);

        // First chunk should be the signature (push data)
        assert!(chunks[0].data.is_some());
        let sig_data = chunks[0].data.as_ref().unwrap();
        // DER signature + 1 byte sighash
        assert!(sig_data.len() >= 70 && sig_data.len() <= 73);

        // Last byte should be the sighash type
        assert_eq!(
            sig_data.last().unwrap(),
            &((0x41) as u8) // SIGHASH_ALL | SIGHASH_FORKID
        );

        // Second chunk should be the compressed public key (33 bytes)
        assert!(chunks[1].data.is_some());
        let pubkey_data = chunks[1].data.as_ref().unwrap();
        assert_eq!(pubkey_data.len(), 33);
    }

    #[test]
    fn test_p2pkh_sign_outputs_variants() {
        let private_key = PrivateKey::random();
        let sighash = [1u8; 32];

        // Test ALL
        let unlocking =
            P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x41u8); // ALL | FORKID

        // Test NONE
        let unlocking =
            P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::None, false).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x42u8); // NONE | FORKID

        // Test SINGLE
        let unlocking =
            P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::Single, false).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x43u8); // SINGLE | FORKID

        // Test ALL | ANYONECANPAY
        let unlocking =
            P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::All, true).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0xC1u8); // ALL | FORKID | ANYONECANPAY
    }

    #[test]
    fn test_p2pkh_locking_script_to_asm() {
        let pubkey_hash = hex::decode("0000000000000000000000000000000000000000").unwrap();
        let template = P2PKH::new();
        let locking = template.lock(&pubkey_hash).unwrap();

        let asm = locking.to_asm();
        assert!(asm.contains("OP_DUP"));
        assert!(asm.contains("OP_HASH160"));
        assert!(asm.contains("OP_EQUALVERIFY"));
        assert!(asm.contains("OP_CHECKSIG"));
    }
}
