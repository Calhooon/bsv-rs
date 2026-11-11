//! ECDSA signature operations.
//!
//! This module provides the [`Signature`] struct for working with ECDSA signatures
//! on the secp256k1 curve, including DER and compact encoding/decoding.

use crate::error::{Error, Result};
use crate::primitives::BigNumber;

/// The secp256k1 curve order divided by 2.
/// Used to check if S is in low form (BIP 62).
fn half_order() -> BigNumber {
    // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    BigNumber::from_bytes_be(&[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ])
}

/// An ECDSA signature consisting of R and S components.
///
/// Signatures can be serialized in DER format (variable length) or compact
/// format (fixed 64 bytes).
///
/// # BIP 62 Compliance
///
/// Bitcoin requires "low-S" signatures where S <= n/2 (where n is the curve order).
/// This prevents transaction malleability. The [`is_low_s`](Signature::is_low_s) method
/// checks this, and [`to_low_s`](Signature::to_low_s) converts a signature to low-S form.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Creates a new signature from R and S components.
    ///
    /// # Arguments
    ///
    /// * `r` - The R component (32 bytes, big-endian)
    /// * `s` - The S component (32 bytes, big-endian)
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r, s }
    }

    /// Parses a signature from DER format, as the reference's
    /// `Signature.fromDER` reads it (`ts-stack@edf6e03`
    /// `packages/sdk/src/primitives/Signature.ts:44-97`; #842).
    ///
    /// DER format: `0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>`, every length
    /// in the short form, the sequence's naming exactly the bytes after it and
    /// S ending the input, each integer with no zero byte before it that its
    /// next byte's high bit did not need. A refusal is
    /// [`Error::InvalidSignature`] in the reference's words:
    ///
    /// | The input | The words |
    /// |---|---|
    /// | not starting with `0x30` (the empty input included) | `Signature DER must start with 0x30` |
    /// | a length byte with its high bit set | `Invalid DER entity length` |
    /// | a sequence length other than the bytes after it, a missing integer tag or R length | `Signature DER invalid` |
    /// | an S length that does not end the input | `Invalid R-length in signature DER` |
    /// | an R or S padded with a zero it did not need, or a lone `00` | `Invalid R-value in signature DER`, `Invalid S-value in signature DER` |
    ///
    /// One cell is this crate's: an integer longer than 32 bytes once its
    /// sign byte is dropped (a value at or above 2^256, never a signature
    /// component) is refused as `Integer component too large`, where the
    /// reference holds a `BigNumber` of any length (a stated divergence, #842).
    /// An empty integer is zero, as the reference reads it.
    ///
    /// Until #842 bytes after the signature, a wrong sequence length, a
    /// sequence length byte with its high bit set taken as a plain length and
    /// an unneeded leading zero were accepted; a long-form length was refused
    /// already, with other error texts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::ec::Signature;
    ///
    /// let der = hex::decode(
    ///     "3045022100b4d19cdc7e93c36f3b5d6f7e8a2a6c9e3c8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b02207f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
    /// ).unwrap();
    /// let sig = Signature::from_der(&der).unwrap();
    ///
    /// // A byte after the sequence is refused, as the reference refuses it.
    /// let mut padded = der.clone();
    /// padded.push(0);
    /// assert!(Signature::from_der(&padded).is_err());
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let integers = super::signature_der::read(der)
            .map_err(|words| Error::InvalidSignature(words.to_string()))?;
        Ok(Self {
            r: Self::der_int_to_fixed(integers.r)?,
            s: Self::der_int_to_fixed(integers.s)?,
        })
    }

    /// Parses a signature from compact format (64 bytes: R || S).
    ///
    /// # Arguments
    ///
    /// * `data` - The 64-byte compact signature
    ///
    /// # Returns
    ///
    /// The parsed signature, or an error if the format is invalid
    pub fn from_compact(data: &[u8; 64]) -> Result<Self> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&data[..32]);
        s.copy_from_slice(&data[32..]);
        Ok(Self { r, s })
    }

    /// Parses a signature from compact format (slice version).
    ///
    /// # Arguments
    ///
    /// * `data` - The compact signature bytes (must be exactly 64 bytes)
    pub fn from_compact_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature(format!(
                "Compact signature must be 64 bytes, got {}",
                data.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(data);
        Self::from_compact(&arr)
    }

    /// Returns the R component of the signature.
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Returns the S component of the signature.
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Encodes the signature in DER format.
    ///
    /// DER format: `0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>`, each integer
    /// minimal, as the reference's `toDER` writes it (`ts-stack@edf6e03`
    /// `Signature.ts:201-250`): a zero R as `02 01 00`, a zero S as `02 00`
    /// (its S loop strips a zero no high bit follows; `02 01 00` until #842's
    /// fold, which the strict reader refuses as an unneeded zero).
    ///
    /// # Returns
    ///
    /// The DER-encoded signature bytes
    pub fn to_der(&self) -> Vec<u8> {
        // Ensure we use low-S form for DER encoding
        let sig = self.to_low_s();

        let r_bytes = Self::fixed_to_der_int(&sig.r);
        let s_bytes = if sig.s == [0u8; 32] {
            Vec::new()
        } else {
            Self::fixed_to_der_int(&sig.s)
        };

        let content_len = 2 + r_bytes.len() + 2 + s_bytes.len();

        let mut der = Vec::with_capacity(2 + content_len);
        der.push(0x30); // Sequence tag
        der.push(content_len as u8);

        der.push(0x02); // Integer tag for R
        der.push(r_bytes.len() as u8);
        der.extend_from_slice(&r_bytes);

        der.push(0x02); // Integer tag for S
        der.push(s_bytes.len() as u8);
        der.extend_from_slice(&s_bytes);

        der
    }

    /// Encodes the signature in compact format (64 bytes: R || S).
    ///
    /// # Returns
    ///
    /// A 64-byte array containing the compact signature
    pub fn to_compact(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.r);
        result[32..].copy_from_slice(&self.s);
        result
    }

    /// Checks if S is in low form (S <= n/2).
    ///
    /// BIP 62 requires low-S signatures to prevent transaction malleability.
    ///
    /// # Returns
    ///
    /// `true` if S <= n/2, `false` otherwise
    pub fn is_low_s(&self) -> bool {
        let s = BigNumber::from_bytes_be(&self.s);
        let half = half_order();
        s <= half
    }

    /// Converts the signature to low-S form if needed.
    ///
    /// If S > n/2, returns a new signature with S' = n - S.
    /// Otherwise returns a clone of this signature.
    ///
    /// # Returns
    ///
    /// A signature in low-S form
    pub fn to_low_s(&self) -> Signature {
        if self.is_low_s() {
            return self.clone();
        }

        let s = BigNumber::from_bytes_be(&self.s);
        let n = BigNumber::secp256k1_order();
        let new_s = n.sub(&s);
        let s_bytes = new_s.to_bytes_be(32);

        let mut new_s_arr = [0u8; 32];
        new_s_arr.copy_from_slice(&s_bytes);

        Signature {
            r: self.r,
            s: new_s_arr,
        }
    }

    /// Verifies this signature against a message hash and public key.
    ///
    /// This is a convenience method that calls [`super::verify`].
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - The 32-byte message hash
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(&self, msg_hash: &[u8; 32], public_key: &super::PublicKey) -> bool {
        super::verify(msg_hash, self, public_key)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// An integer as the DER reader returned it (no sign byte left) in 32
    /// bytes; longer is a value at or above 2^256, which this type does not
    /// hold (the reference's `BigNumber` does; #842's stated cell).
    fn der_int_to_fixed(bytes: &[u8]) -> Result<[u8; 32]> {
        if bytes.len() > 32 {
            return Err(Error::InvalidSignature(
                "Integer component too large".to_string(),
            ));
        }

        let mut result = [0u8; 32];
        let start = 32 - bytes.len();
        result[start..].copy_from_slice(bytes);
        Ok(result)
    }

    /// Converts a fixed 32-byte integer to minimal DER integer encoding.
    fn fixed_to_der_int(bytes: &[u8; 32]) -> Vec<u8> {
        // Find first non-zero byte
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
        let trimmed = &bytes[start..];

        // If high bit is set, prepend 0x00 to indicate positive
        if trimmed.is_empty() {
            vec![0x00]
        } else if trimmed[0] & 0x80 != 0 {
            let mut result = vec![0x00];
            result.extend_from_slice(trimmed);
            result
        } else {
            trimmed.to_vec()
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("r", &hex::encode(self.r))
            .field("s", &hex::encode(self.s))
            .finish()
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_der()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_new() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let sig = Signature::new(r, s);
        assert_eq!(sig.r(), &r);
        assert_eq!(sig.s(), &s);
    }

    #[test]
    fn test_signature_compact_roundtrip() {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r[31] = 0x42;
        s[31] = 0x43;

        let sig = Signature::new(r, s);
        let compact = sig.to_compact();
        let recovered = Signature::from_compact(&compact).unwrap();

        assert_eq!(sig.r(), recovered.r());
        assert_eq!(sig.s(), recovered.s());
    }

    #[test]
    fn test_signature_der_roundtrip() {
        // Create a signature with known values
        let r = hex::decode("b4d19cdc7e93c36f3b5d6f7e8a2a6c9e3c8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b")
            .unwrap();
        let s = hex::decode("0f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e")
            .unwrap();

        let mut r_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        r_arr.copy_from_slice(&r);
        s_arr.copy_from_slice(&s);

        let sig = Signature::new(r_arr, s_arr);
        let der = sig.to_der();
        let recovered = Signature::from_der(&der).unwrap();

        assert_eq!(sig.r(), recovered.r());
        // S may be different due to low-S conversion in to_der
        // But either the original or the negated should match
        assert!(sig.s() == recovered.s() || sig.to_low_s().s() == recovered.s());
    }

    #[test]
    fn test_der_parsing() {
        // Known DER signature
        let der = hex::decode(
            "3045022100b4d19cdc7e93c36f3b5d6f7e8a2a6c9e3c8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b02200f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e",
        )
        .unwrap();

        let sig = Signature::from_der(&der).unwrap();
        assert_eq!(
            hex::encode(sig.r()),
            "b4d19cdc7e93c36f3b5d6f7e8a2a6c9e3c8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b"
        );
        assert_eq!(
            hex::encode(sig.s()),
            "0f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
        );
    }

    #[test]
    fn test_is_low_s() {
        // Low S value (well below n/2)
        let r = [0u8; 32];
        let mut s_low = [0u8; 32];
        s_low[31] = 0x01;

        let sig_low = Signature::new(r, s_low);
        assert!(sig_low.is_low_s());

        // High S value (greater than n/2)
        let s_high =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .unwrap();
        let mut s_high_arr = [0u8; 32];
        s_high_arr.copy_from_slice(&s_high);

        let sig_high = Signature::new(r, s_high_arr);
        assert!(!sig_high.is_low_s());
    }

    #[test]
    fn test_to_low_s() {
        let r = [0u8; 32];

        // High S value
        let s_high =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .unwrap();
        let mut s_high_arr = [0u8; 32];
        s_high_arr.copy_from_slice(&s_high);

        let sig_high = Signature::new(r, s_high_arr);
        assert!(!sig_high.is_low_s());

        let sig_low = sig_high.to_low_s();
        assert!(sig_low.is_low_s());

        // Low S stays unchanged
        let mut s_already_low = [0u8; 32];
        s_already_low[31] = 0x01;
        let sig = Signature::new(r, s_already_low);
        let sig_converted = sig.to_low_s();
        assert_eq!(sig.s(), sig_converted.s());
    }

    #[test]
    fn test_der_int_to_fixed_pads_on_the_left() {
        // The reader has dropped the sign byte; the integer is right-aligned
        let bytes = vec![0x80, 0x00, 0x00];
        let fixed = Signature::der_int_to_fixed(&bytes).unwrap();
        assert_eq!(&fixed[29..], &[0x80, 0x00, 0x00]);
        assert_eq!(&fixed[..29], &[0u8; 29]);
    }

    #[test]
    fn test_fixed_to_der_int_adds_leading_zero() {
        // When high bit is set, DER needs leading 0x00
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;

        let der = Signature::fixed_to_der_int(&bytes);
        assert_eq!(der[0], 0x00);
        assert_eq!(der[1], 0x80);
    }

    #[test]
    fn test_signature_from_compact_slice() {
        let data = [0x42u8; 64];
        let sig = Signature::from_compact_slice(&data).unwrap();
        assert_eq!(sig.r()[0], 0x42);
        assert_eq!(sig.s()[0], 0x42);

        // Wrong length should fail
        assert!(Signature::from_compact_slice(&[0u8; 63]).is_err());
        assert!(Signature::from_compact_slice(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_all_zero_signature_fails_verification() {
        // All-zero R and S should parse but fail verification
        let sig = Signature::from_compact_slice(&[0u8; 64]).unwrap();
        assert_eq!(sig.r(), &[0u8; 32]);
        assert_eq!(sig.s(), &[0u8; 32]);

        // Verification must fail with any public key and message
        use crate::primitives::hash::sha256;
        use crate::primitives::PrivateKey;
        let pubkey = PrivateKey::random().public_key();
        let msg_hash = sha256(b"test");
        assert!(!pubkey.verify(&msg_hash, &sig));
    }

    #[test]
    fn test_signature_r_at_curve_order() {
        // R = secp256k1 curve order N (should fail verification)
        // N = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let r = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap();
        let mut r_arr = [0u8; 32];
        r_arr.copy_from_slice(&r);
        let mut s_arr = [0u8; 32];
        s_arr[31] = 1;
        let sig = Signature::new(r_arr, s_arr);

        use crate::primitives::hash::sha256;
        use crate::primitives::PrivateKey;
        let pubkey = PrivateKey::random().public_key();
        let msg_hash = sha256(b"test");
        assert!(!pubkey.verify(&msg_hash, &sig));
    }

    #[test]
    fn test_signature_s_at_curve_order() {
        // S = secp256k1 curve order N (should fail verification)
        let s = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap();
        let mut r_arr = [0u8; 32];
        r_arr[31] = 1;
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s);
        let sig = Signature::new(r_arr, s_arr);

        use crate::primitives::hash::sha256;
        use crate::primitives::PrivateKey;
        let pubkey = PrivateKey::random().public_key();
        let msg_hash = sha256(b"test");
        assert!(!pubkey.verify(&msg_hash, &sig));
    }
}
