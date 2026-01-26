//! R-Puzzle script template.
//!
//! This module provides the [`RPuzzle`] template for creating and spending
//! R-Puzzle scripts. R-Puzzles lock funds using the R-value component of
//! an ECDSA signature.
//!
//! # Overview
//!
//! An R-Puzzle allows anyone who knows a specific K-value (ECDSA nonce) to
//! spend the output, regardless of which private key they use. This creates
//! a form of "knowledge-based" locking where the secret is the K-value.
//!
//! # Locking Script Pattern (raw)
//!
//! ```text
//! OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
//! <r-value> OP_EQUALVERIFY OP_CHECKSIG
//! ```
//!
//! # Locking Script Pattern (hashed)
//!
//! ```text
//! OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
//! OP_<HASH> <r-hash> OP_EQUALVERIFY OP_CHECKSIG
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
//! use bsv_sdk::script::templates::{RPuzzle, RPuzzleType};
//! use bsv_sdk::script::template::SignOutputs;
//! use bsv_sdk::primitives::ec::PrivateKey;
//! use bsv_sdk::primitives::BigNumber;
//!
//! // Generate a random K value
//! let k = BigNumber::from_bytes_be(&random_32_bytes);
//! let r_value = compute_r_from_k(&k);
//!
//! // Create locking script with raw R value
//! let template = RPuzzle::new(RPuzzleType::Raw);
//! let locking = template.lock(&r_value);
//!
//! // Create locking script with hashed R value
//! let template = RPuzzle::new(RPuzzleType::Hash160);
//! let r_hash = hash160(&r_value);
//! let locking = template.lock(&r_hash);
//!
//! // Unlock using the K value
//! let private_key = PrivateKey::random();
//! let unlock = RPuzzle::unlock(&k, &private_key, SignOutputs::All, false);
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::PrivateKey;
use crate::primitives::hash::{hash160, ripemd160, sha1, sha256, sha256d};
use crate::primitives::BigNumber;
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::subtle::CtOption;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, U256};

/// The type of R-Puzzle to create.
///
/// Determines whether the R value is stored raw or hashed in the locking script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RPuzzleType {
    /// Store the raw R value (largest script, but simplest).
    #[default]
    Raw,
    /// Hash the R value with SHA-1 (20 bytes).
    Sha1,
    /// Hash the R value with SHA-256 (32 bytes).
    Sha256,
    /// Hash the R value with HASH256 (double SHA-256, 32 bytes).
    Hash256,
    /// Hash the R value with RIPEMD-160 (20 bytes).
    Ripemd160,
    /// Hash the R value with HASH160 (RIPEMD-160 of SHA-256, 20 bytes).
    Hash160,
}

impl RPuzzleType {
    /// Returns the opcode for this hash type, if any.
    fn hash_opcode(self) -> Option<u8> {
        match self {
            RPuzzleType::Raw => None,
            RPuzzleType::Sha1 => Some(OP_SHA1),
            RPuzzleType::Sha256 => Some(OP_SHA256),
            RPuzzleType::Hash256 => Some(OP_HASH256),
            RPuzzleType::Ripemd160 => Some(OP_RIPEMD160),
            RPuzzleType::Hash160 => Some(OP_HASH160),
        }
    }

    /// Computes the hash of the given data using this hash type.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            RPuzzleType::Raw => data.to_vec(),
            RPuzzleType::Sha1 => sha1(data).to_vec(),
            RPuzzleType::Sha256 => sha256(data).to_vec(),
            RPuzzleType::Hash256 => sha256d(data).to_vec(),
            RPuzzleType::Ripemd160 => ripemd160(data).to_vec(),
            RPuzzleType::Hash160 => hash160(data).to_vec(),
        }
    }
}

/// R-Puzzle script template.
///
/// R-Puzzles lock funds using the R-value component of an ECDSA signature.
/// Anyone who knows the K-value (ECDSA nonce) that produces a specific R-value
/// can spend the output.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::script::templates::{RPuzzle, RPuzzleType};
///
/// // Create a raw R-Puzzle
/// let template = RPuzzle::new(RPuzzleType::Raw);
/// let locking = template.lock(&r_value);
///
/// // Create a hashed R-Puzzle (smaller script)
/// let template = RPuzzle::new(RPuzzleType::Hash160);
/// let locking = template.lock(&r_hash);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RPuzzle {
    /// The type of puzzle (raw or hashed).
    pub puzzle_type: RPuzzleType,
}

impl Default for RPuzzle {
    fn default() -> Self {
        Self::new(RPuzzleType::Raw)
    }
}

impl RPuzzle {
    /// Creates a new R-Puzzle template with the specified type.
    ///
    /// # Arguments
    ///
    /// * `puzzle_type` - Whether to use raw R value or a hashed variant
    pub fn new(puzzle_type: RPuzzleType) -> Self {
        Self { puzzle_type }
    }

    /// Computes the R value from a K value.
    ///
    /// The R value is the x-coordinate of the point k*G on the secp256k1 curve.
    ///
    /// # Arguments
    ///
    /// * `k` - The K value (ECDSA nonce)
    ///
    /// # Returns
    ///
    /// The R value as 32 bytes (big-endian)
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]> {
        // Get k as bytes and convert to scalar
        let k_bytes = k.to_bytes_be(32);
        let k_uint = U256::from_be_slice(&k_bytes);
        let k_scalar: CtOption<NonZeroScalar> = NonZeroScalar::from_uint(k_uint);

        let k_scalar = k_scalar
            .into_option()
            .ok_or_else(|| Error::CryptoError("Invalid K value (zero or >= order)".to_string()))?;

        // Compute R = k * G
        let point = ProjectivePoint::GENERATOR * k_scalar.as_ref();
        let point_affine = point.to_affine();

        // Get x-coordinate (R value)
        let x: FieldBytes = point_affine.x();
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&x);

        Ok(r_bytes)
    }

    /// Creates an unlock template for spending an R-Puzzle output.
    ///
    /// # Arguments
    ///
    /// * `k` - The K value that produces the expected R value
    /// * `private_key` - A private key for signing (any key works)
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
    /// use bsv_sdk::script::templates::RPuzzle;
    /// use bsv_sdk::script::template::SignOutputs;
    /// use bsv_sdk::primitives::ec::PrivateKey;
    /// use bsv_sdk::primitives::BigNumber;
    ///
    /// let k = BigNumber::from_hex("...")?;
    /// let private_key = PrivateKey::random();
    ///
    /// let unlock = RPuzzle::unlock(&k, &private_key, SignOutputs::All, false);
    /// let unlocking = unlock.sign(&context)?;
    /// ```
    pub fn unlock(
        k: &BigNumber,
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let k_value = k.clone();
        let key = private_key.clone();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                // Compute the sighash
                let sighash = context.compute_sighash(scope)?;

                // Sign with the specific K value
                let signature = sign_with_k(&key, &sighash, &k_value)?;
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
                108
            },
        )
    }

    /// Signs with a precomputed sighash using a specific K value.
    ///
    /// # Arguments
    ///
    /// * `k` - The K value to use for signing
    /// * `private_key` - The private key for signing
    /// * `sighash` - The precomputed sighash
    /// * `sign_outputs` - Which outputs to sign (for the scope byte)
    /// * `anyone_can_pay` - Whether to allow other inputs to be added
    ///
    /// # Returns
    ///
    /// The unlocking script.
    pub fn sign_with_sighash(
        k: &BigNumber,
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        // Sign with the specific K value
        let signature = sign_with_k(private_key, sighash, k)?;
        let tx_sig = TransactionSignature::new(signature, scope);

        // Build the unlocking script
        let sig_bytes = tx_sig.to_checksig_format();
        let pubkey_bytes = private_key.public_key().to_compressed();

        let mut script = Script::new();
        script.write_bin(&sig_bytes).write_bin(&pubkey_bytes);

        Ok(UnlockingScript::from_script(script))
    }
}

impl ScriptTemplate for RPuzzle {
    /// Creates an R-Puzzle locking script.
    ///
    /// # Arguments
    ///
    /// * `params` - The R value or its hash (depending on puzzle type)
    ///
    /// # Returns
    ///
    /// The locking script.
    ///
    /// # Script Structure
    ///
    /// The script extracts the R value from the signature and compares it:
    ///
    /// ```text
    /// OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
    /// [OP_<HASH>] <value> OP_EQUALVERIFY OP_CHECKSIG
    /// ```
    fn lock(&self, params: &[u8]) -> Result<LockingScript> {
        // Build the R-extraction prefix:
        // OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
        //
        // This extracts the R value from a DER-encoded signature on the stack.
        //
        // Stack operations:
        // Initial: <sig> <pubkey>
        // OP_OVER: <sig> <pubkey> <sig>
        // OP_3: <sig> <pubkey> <sig> 3
        // OP_SPLIT: <sig> <pubkey> <3 bytes> <rest of sig>
        // OP_NIP: <sig> <pubkey> <rest of sig starting at R-length byte>
        // OP_1: <sig> <pubkey> <rest> 1
        // OP_SPLIT: <sig> <pubkey> <R-length byte> <rest>
        // OP_SWAP: <sig> <pubkey> <rest> <R-length byte>
        // OP_SPLIT: <sig> <pubkey> <R value> <rest>
        // OP_DROP: <sig> <pubkey> <R value>

        let mut chunks = vec![
            ScriptChunk::new_opcode(OP_OVER),
            ScriptChunk::new_opcode(OP_3),
            ScriptChunk::new_opcode(OP_SPLIT),
            ScriptChunk::new_opcode(OP_NIP),
            ScriptChunk::new_opcode(OP_1),
            ScriptChunk::new_opcode(OP_SPLIT),
            ScriptChunk::new_opcode(OP_SWAP),
            ScriptChunk::new_opcode(OP_SPLIT),
            ScriptChunk::new_opcode(OP_DROP),
        ];

        // Add hash opcode if not raw
        if let Some(hash_op) = self.puzzle_type.hash_opcode() {
            chunks.push(ScriptChunk::new_opcode(hash_op));
        }

        // Add the expected value
        let op = if params.len() < OP_PUSHDATA1 as usize {
            params.len() as u8
        } else if params.len() < 256 {
            OP_PUSHDATA1
        } else {
            OP_PUSHDATA2
        };
        chunks.push(ScriptChunk::new(op, Some(params.to_vec())));

        // Add comparison and checksig
        chunks.push(ScriptChunk::new_opcode(OP_EQUALVERIFY));
        chunks.push(ScriptChunk::new_opcode(OP_CHECKSIG));

        Ok(LockingScript::from_chunks(chunks))
    }
}

/// Signs a message hash with a specific K value.
///
/// This is a low-level function that creates an ECDSA signature using
/// a predetermined nonce (K value) instead of RFC 6979.
fn sign_with_k(
    private_key: &PrivateKey,
    msg_hash: &[u8; 32],
    k: &BigNumber,
) -> Result<crate::primitives::ec::Signature> {
    use k256::ecdsa::Signature as K256Signature;

    // Get the private key as a scalar
    let secret_key = k256::SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| Error::CryptoError(format!("Invalid private key: {}", e)))?;
    let d = secret_key.to_nonzero_scalar();

    // Get k as a scalar
    let k_bytes = k.to_bytes_be(32);
    let k_uint = U256::from_be_slice(&k_bytes);
    let k_scalar: CtOption<NonZeroScalar> = NonZeroScalar::from_uint(k_uint);
    let k_nonzero = k_scalar
        .into_option()
        .ok_or_else(|| Error::CryptoError("Invalid K value".to_string()))?;

    // Compute R = k * G
    let r_point = (ProjectivePoint::GENERATOR * k_nonzero.as_ref()).to_affine();
    let r_bytes: FieldBytes = r_point.x();
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&r_bytes);

    // Compute s = k^-1 * (z + r * d) mod n
    // Note: from_slice deprecation is from generic-array 0.x, a transitive dependency of k256
    #[allow(deprecated)]
    let z_bytes: FieldBytes = *FieldBytes::from_slice(msg_hash);
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&z_bytes);
    let k_inv_opt: CtOption<Scalar> = k_nonzero.invert();
    let k_inv: Scalar = k_inv_opt
        .into_option()
        .ok_or_else(|| Error::CryptoError("K has no inverse".to_string()))?;
    let s = k_inv * (z + r * d.as_ref());

    // Convert to non-zero scalar for signature
    let r_nonzero: CtOption<NonZeroScalar> = NonZeroScalar::new(r);
    let s_nonzero: CtOption<NonZeroScalar> = NonZeroScalar::new(s);

    let r_nz = r_nonzero
        .into_option()
        .ok_or_else(|| Error::CryptoError("R is zero".to_string()))?;
    let s_nz = s_nonzero
        .into_option()
        .ok_or_else(|| Error::CryptoError("S is zero".to_string()))?;

    // Create signature
    let k256_sig = K256Signature::from_scalars(r_nz, s_nz)
        .map_err(|e| Error::CryptoError(format!("Failed to create signature: {}", e)))?;

    // Convert to our Signature type
    let r_bytes = k256_sig.r().to_bytes();
    let s_bytes = k256_sig.s().to_bytes();

    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(&r_bytes);
    s_arr.copy_from_slice(&s_bytes);

    let signature = crate::primitives::ec::Signature::new(r_arr, s_arr);

    // Ensure low-S (BIP 62)
    Ok(signature.to_low_s())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpuzzle_lock_raw() {
        let r_value = [0x42u8; 32];
        let template = RPuzzle::new(RPuzzleType::Raw);
        let locking = template.lock(&r_value).unwrap();

        let asm = locking.to_asm();

        // Should contain the R-extraction prefix
        assert!(asm.contains("OP_OVER"));
        assert!(asm.contains("OP_3"));
        assert!(asm.contains("OP_SPLIT"));
        assert!(asm.contains("OP_NIP"));
        assert!(asm.contains("OP_SWAP"));
        assert!(asm.contains("OP_DROP"));

        // Should contain EQUALVERIFY and CHECKSIG
        assert!(asm.contains("OP_EQUALVERIFY"));
        assert!(asm.contains("OP_CHECKSIG"));

        // Should NOT contain hash opcodes
        assert!(!asm.contains("OP_HASH160"));
        assert!(!asm.contains("OP_SHA256"));
    }

    #[test]
    fn test_rpuzzle_lock_hash160() {
        let r_hash = [0x42u8; 20];
        let template = RPuzzle::new(RPuzzleType::Hash160);
        let locking = template.lock(&r_hash).unwrap();

        let asm = locking.to_asm();

        // Should contain OP_HASH160
        assert!(asm.contains("OP_HASH160"));
    }

    #[test]
    fn test_rpuzzle_lock_sha256() {
        let r_hash = [0x42u8; 32];
        let template = RPuzzle::new(RPuzzleType::Sha256);
        let locking = template.lock(&r_hash).unwrap();

        let asm = locking.to_asm();

        // Should contain OP_SHA256
        assert!(asm.contains("OP_SHA256"));
    }

    #[test]
    fn test_rpuzzle_type_hash() {
        let data = b"test data";

        // Test each hash type
        assert_eq!(RPuzzleType::Raw.hash(data), data.to_vec());
        assert_eq!(RPuzzleType::Sha1.hash(data).len(), 20);
        assert_eq!(RPuzzleType::Sha256.hash(data).len(), 32);
        assert_eq!(RPuzzleType::Hash256.hash(data).len(), 32);
        assert_eq!(RPuzzleType::Ripemd160.hash(data).len(), 20);
        assert_eq!(RPuzzleType::Hash160.hash(data).len(), 20);
    }

    #[test]
    fn test_compute_r_from_k() {
        // Use a known K value
        let k =
            BigNumber::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let r = RPuzzle::compute_r_from_k(&k).unwrap();

        // k=1 means R = G, which has a known x-coordinate
        // The generator point G has x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let expected_r =
            hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap();
        assert_eq!(r.to_vec(), expected_r);
    }

    #[test]
    fn test_rpuzzle_unlock_produces_valid_script() {
        let k =
            BigNumber::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let private_key = PrivateKey::random();
        let sighash = [1u8; 32];

        let unlocking =
            RPuzzle::sign_with_sighash(&k, &private_key, &sighash, SignOutputs::All, false)
                .unwrap();

        // The unlocking script should have 2 chunks: signature and pubkey
        let chunks = unlocking.chunks();
        assert_eq!(chunks.len(), 2);

        // First chunk should be the signature
        assert!(chunks[0].data.is_some());
        let sig_data = chunks[0].data.as_ref().unwrap();

        // Parse the signature and verify the R value matches k*G
        let expected_r = RPuzzle::compute_r_from_k(&k).unwrap();

        // The signature is in DER format + sighash byte
        // DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
        // Skip the DER header and extract R
        let r_len = sig_data[3] as usize;
        let r_start = 4;
        let r_bytes = &sig_data[r_start..r_start + r_len];

        // R may have a leading zero if high bit is set
        let r_trimmed: Vec<u8> = r_bytes.iter().copied().skip_while(|&b| b == 0).collect();
        let expected_trimmed: Vec<u8> =
            expected_r.iter().copied().skip_while(|&b| b == 0).collect();

        assert_eq!(r_trimmed, expected_trimmed);
    }

    #[test]
    fn test_rpuzzle_estimate_length() {
        let k = BigNumber::from_i64(1);
        let private_key = PrivateKey::random();

        let unlock = RPuzzle::unlock(&k, &private_key, SignOutputs::All, false);

        // Should estimate 108 bytes
        assert_eq!(unlock.estimate_length(), 108);
    }

    #[test]
    fn test_rpuzzle_all_hash_types_lock() {
        let data = [0x42u8; 32];

        // Test each puzzle type
        for puzzle_type in [
            RPuzzleType::Raw,
            RPuzzleType::Sha1,
            RPuzzleType::Sha256,
            RPuzzleType::Hash256,
            RPuzzleType::Ripemd160,
            RPuzzleType::Hash160,
        ] {
            let hash = puzzle_type.hash(&data);
            let template = RPuzzle::new(puzzle_type);
            let locking = template.lock(&hash);
            assert!(locking.is_ok(), "Failed for {:?}", puzzle_type);
        }
    }
}
