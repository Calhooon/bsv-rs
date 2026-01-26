//! Transaction signature operations.
//!
//! This module provides the [`TransactionSignature`] struct which wraps an ECDSA
//! signature with a sighash scope byte. This is the format used in Bitcoin
//! transaction inputs.
//!
//! # Checksig Format
//!
//! In Bitcoin scripts, signatures are encoded in "checksig format":
//! `DER_signature || sighash_byte`
//!
//! The sighash byte indicates which parts of the transaction were signed.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_primitives::bsv::tx_signature::TransactionSignature;
//! use bsv_primitives::ec::Signature;
//!
//! // Parse a signature from checksig format
//! let checksig_bytes = hex::decode("3044...41").unwrap();
//! let tx_sig = TransactionSignature::from_checksig_format(&checksig_bytes).unwrap();
//!
//! println!("Sighash type: 0x{:02x}", tx_sig.scope());
//!
//! // Encode back to checksig format
//! let encoded = tx_sig.to_checksig_format();
//! ```

use crate::ec::Signature;
use crate::error::{Error, Result};
use crate::BigNumber;

pub use crate::bsv::sighash::{
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};

/// A transaction signature with a sighash scope.
///
/// This wraps an ECDSA signature with the sighash type byte that indicates
/// which parts of the transaction were signed. This is the format used in
/// Bitcoin OP_CHECKSIG operations.
#[derive(Clone, PartialEq, Eq)]
pub struct TransactionSignature {
    /// The underlying ECDSA signature.
    signature: Signature,
    /// The sighash type/scope.
    scope: u32,
}

impl TransactionSignature {
    /// Creates a new transaction signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - The ECDSA signature
    /// * `scope` - The sighash type/scope
    pub fn new(signature: Signature, scope: u32) -> Self {
        Self { signature, scope }
    }

    /// Creates a new transaction signature from R, S components and scope.
    ///
    /// # Arguments
    ///
    /// * `r` - The R component (32 bytes, big-endian)
    /// * `s` - The S component (32 bytes, big-endian)
    /// * `scope` - The sighash type/scope
    pub fn from_components(r: [u8; 32], s: [u8; 32], scope: u32) -> Self {
        Self {
            signature: Signature::new(r, s),
            scope,
        }
    }

    /// Parses a transaction signature from checksig format.
    ///
    /// Checksig format: `DER_signature || sighash_byte`
    ///
    /// # Arguments
    ///
    /// * `data` - The checksig-formatted signature bytes
    ///
    /// # Returns
    ///
    /// The parsed transaction signature, or an error if parsing fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_primitives::bsv::tx_signature::TransactionSignature;
    ///
    /// let checksig = hex::decode("30440220...0141").unwrap();
    /// let sig = TransactionSignature::from_checksig_format(&checksig).unwrap();
    /// assert_eq!(sig.scope() & 0xff, 0x41); // SIGHASH_ALL | SIGHASH_FORKID
    /// ```
    pub fn from_checksig_format(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            // Allow "blank" signatures (used for unsigned inputs)
            let r = BigNumber::one().to_bytes_be(32);
            let s = BigNumber::one().to_bytes_be(32);
            let mut r_arr = [0u8; 32];
            let mut s_arr = [0u8; 32];
            r_arr.copy_from_slice(&r);
            s_arr.copy_from_slice(&s);
            return Ok(Self {
                signature: Signature::new(r_arr, s_arr),
                scope: 1,
            });
        }

        if data.len() < 2 {
            return Err(Error::InvalidSignature(
                "Checksig format too short".to_string(),
            ));
        }

        // The last byte is the sighash type
        let scope = data[data.len() - 1] as u32;

        // The rest is the DER-encoded signature
        let der_bytes = &data[..data.len() - 1];
        let signature = Signature::from_der(der_bytes)?;

        Ok(Self { signature, scope })
    }

    /// Returns the underlying ECDSA signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the sighash type/scope.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// Returns the R component of the signature.
    pub fn r(&self) -> &[u8; 32] {
        self.signature.r()
    }

    /// Returns the S component of the signature.
    pub fn s(&self) -> &[u8; 32] {
        self.signature.s()
    }

    /// Checks if S is in low form (S <= n/2).
    ///
    /// BIP 62 requires low-S signatures to prevent transaction malleability.
    pub fn has_low_s(&self) -> bool {
        self.signature.is_low_s()
    }

    /// Converts to low-S form if needed.
    ///
    /// If S > n/2, returns a new signature with S' = n - S.
    pub fn to_low_s(&self) -> Self {
        Self {
            signature: self.signature.to_low_s(),
            scope: self.scope,
        }
    }

    /// Encodes the signature in checksig format.
    ///
    /// Checksig format: `DER_signature || sighash_byte`
    ///
    /// The signature is automatically converted to low-S form.
    ///
    /// # Returns
    ///
    /// The checksig-formatted bytes
    pub fn to_checksig_format(&self) -> Vec<u8> {
        let mut result = self.signature.to_der();
        result.push((self.scope & 0xff) as u8);
        result
    }

    /// Encodes the signature in DER format (without the sighash byte).
    pub fn to_der(&self) -> Vec<u8> {
        self.signature.to_der()
    }

    /// Encodes the signature in compact format (64 bytes: R || S).
    pub fn to_compact(&self) -> [u8; 64] {
        self.signature.to_compact()
    }
}

impl std::fmt::Debug for TransactionSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionSignature")
            .field("r", &hex::encode(self.signature.r()))
            .field("s", &hex::encode(self.signature.s()))
            .field("scope", &format!("0x{:08x}", self.scope))
            .finish()
    }
}

impl std::fmt::Display for TransactionSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_checksig_format()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksig_format_roundtrip() {
        // Create a signature with known values
        let r = hex::decode("b4d19cdc7e93c36f3b5d6f7e8a2a6c9e3c8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b")
            .unwrap();
        let s = hex::decode("0f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e")
            .unwrap();

        let mut r_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        r_arr.copy_from_slice(&r);
        s_arr.copy_from_slice(&s);

        let tx_sig =
            TransactionSignature::from_components(r_arr, s_arr, SIGHASH_ALL | SIGHASH_FORKID);

        // Encode to checksig format
        let encoded = tx_sig.to_checksig_format();

        // Last byte should be the scope
        assert_eq!(
            encoded.last().unwrap(),
            &((SIGHASH_ALL | SIGHASH_FORKID) as u8)
        );

        // Decode back
        let decoded = TransactionSignature::from_checksig_format(&encoded).unwrap();

        // R should match (S may be converted to low-S)
        assert_eq!(decoded.r(), tx_sig.r());
        // Scope should match (only low byte)
        assert_eq!(
            decoded.scope() & 0xff,
            (SIGHASH_ALL | SIGHASH_FORKID) as u32
        );
    }

    #[test]
    fn test_empty_checksig() {
        // Empty data should create a "blank" signature
        let sig = TransactionSignature::from_checksig_format(&[]).unwrap();
        assert_eq!(sig.scope(), 1);
    }

    #[test]
    fn test_scope_values() {
        assert_eq!(SIGHASH_ALL, 0x01);
        assert_eq!(SIGHASH_NONE, 0x02);
        assert_eq!(SIGHASH_SINGLE, 0x03);
        assert_eq!(SIGHASH_FORKID, 0x40);
        assert_eq!(SIGHASH_ANYONECANPAY, 0x80);

        // Common combinations
        assert_eq!(SIGHASH_ALL | SIGHASH_FORKID, 0x41);
        assert_eq!(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY, 0xc1);
    }

    #[test]
    fn test_has_low_s() {
        // Low S value
        let r = [0u8; 32];
        let mut s = [0u8; 32];
        s[31] = 0x01;

        let sig = TransactionSignature::from_components(r, s, SIGHASH_ALL);
        assert!(sig.has_low_s());
    }

    #[test]
    fn test_to_low_s() {
        // High S value (greater than n/2)
        let r = [0u8; 32];
        let s_high =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .unwrap();
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_high);

        let sig = TransactionSignature::from_components(r, s_arr, SIGHASH_ALL);
        assert!(!sig.has_low_s());

        let low_sig = sig.to_low_s();
        assert!(low_sig.has_low_s());
    }

    #[test]
    fn test_new() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let ecdsa_sig = Signature::new(r, s);

        let tx_sig = TransactionSignature::new(ecdsa_sig.clone(), SIGHASH_ALL | SIGHASH_FORKID);

        assert_eq!(tx_sig.signature().r(), &r);
        assert_eq!(tx_sig.signature().s(), &s);
        assert_eq!(tx_sig.scope(), SIGHASH_ALL | SIGHASH_FORKID);
    }
}
