//! P-256 (NIST secp256r1) elliptic curve operations.
//!
//! This module provides ECDSA signing and verification for the P-256 curve,
//! which is used in certain authentication scenarios.
//!
//! # Overview
//!
//! - [`P256PrivateKey`] - A P-256 private key for signing
//! - [`P256PublicKey`] - A P-256 public key for verification
//! - [`P256Signature`] - An ECDSA signature with DER and compact encoding
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::primitives::p256::{P256PrivateKey, P256PublicKey};
//!
//! // Generate a random key pair
//! let private_key = P256PrivateKey::random();
//! let public_key = private_key.public_key();
//!
//! // Sign a message (will be hashed with SHA-256)
//! let message = b"Hello, P-256!";
//! let signature = private_key.sign(message);
//!
//! // Verify the signature
//! assert!(public_key.verify(message, &signature));
//! ```

use crate::error::{Error, Result};
use crate::primitives::hash::sha256;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256EcdsaSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey as P256InternalPublicKey, SecretKey};
use rand::rngs::OsRng;

/// The P-256 curve order divided by 2, used for low-S normalization.
/// n/2 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
fn half_order() -> [u8; 32] {
    [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ]
}

/// The P-256 curve order.
/// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
fn curve_order() -> [u8; 32] {
    [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ]
}

/// A P-256 (secp256r1) private key.
///
/// This key can be used for ECDSA signing on the P-256 curve.
#[derive(Clone)]
pub struct P256PrivateKey {
    inner: SigningKey,
}

impl P256PrivateKey {
    /// Generates a random P-256 private key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let key = P256PrivateKey::random();
    /// ```
    pub fn random() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        Self {
            inner: SigningKey::from(secret_key),
        }
    }

    /// Creates a private key from raw 32-byte secret.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte secret key material
    ///
    /// # Returns
    ///
    /// The private key, or an error if the bytes are invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let key = P256PrivateKey::from_bytes(&bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let secret_key = SecretKey::from_slice(bytes)
            .map_err(|e| Error::InvalidPrivateKey(format!("invalid P-256 private key: {}", e)))?;

        Ok(Self {
            inner: SigningKey::from(secret_key),
        })
    }

    /// Creates a private key from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded private key (64 characters)
    ///
    /// # Returns
    ///
    /// The private key, or an error if the hex is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let key = P256PrivateKey::from_hex(
    ///     "0000000000000000000000000000000000000000000000000000000000000001"
    /// ).unwrap();
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = crate::primitives::encoding::from_hex(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the corresponding public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let key = P256PrivateKey::random();
    /// let pubkey = key.public_key();
    /// ```
    pub fn public_key(&self) -> P256PublicKey {
        P256PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Signs a message (will be hashed with SHA-256).
    ///
    /// The signature is normalized to low-S form for consistency.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let key = P256PrivateKey::random();
    /// let sig = key.sign(b"Hello, P-256!");
    /// ```
    pub fn sign(&self, message: &[u8]) -> P256Signature {
        let hash = sha256(message);
        self.sign_hash(&hash)
    }

    /// Signs a message hash directly (32 bytes).
    ///
    /// Use this when you have already computed the SHA-256 hash.
    /// The signature is normalized to low-S form.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte message hash
    ///
    /// # Returns
    ///
    /// The signature
    pub fn sign_hash(&self, hash: &[u8; 32]) -> P256Signature {
        // Use prehash signing (sign a hash directly)
        let signature: P256EcdsaSignature = self.inner.sign_prehash(hash).expect("signing failed");

        let sig = P256Signature { inner: signature };

        // Normalize to low-S
        sig.to_low_s()
    }

    /// Exports the private key as raw 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        result
    }

    /// Exports the private key as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl std::fmt::Debug for P256PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the secret key in debug output
        f.debug_struct("P256PrivateKey")
            .field("public_key", &self.public_key().to_hex())
            .finish()
    }
}

impl PartialEq for P256PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for P256PrivateKey {}

/// A P-256 (secp256r1) public key.
///
/// This key can be used for ECDSA signature verification on the P-256 curve.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256PublicKey {
    inner: VerifyingKey,
}

impl P256PublicKey {
    /// Parses a public key from compressed (33 bytes) or uncompressed (65 bytes) format.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The encoded public key
    ///
    /// # Returns
    ///
    /// The public key, or an error if the encoding is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::{P256PrivateKey, P256PublicKey};
    ///
    /// let key = P256PrivateKey::random();
    /// let pubkey = key.public_key();
    /// let compressed = pubkey.to_compressed();
    /// let recovered = P256PublicKey::from_bytes(&compressed).unwrap();
    /// assert_eq!(pubkey, recovered);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| Error::InvalidPublicKey(format!("invalid encoded point: {}", e)))?;

        let public_key = P256InternalPublicKey::from_encoded_point(&encoded);

        if public_key.is_none().into() {
            return Err(Error::InvalidPublicKey(
                "point not on curve or at infinity".to_string(),
            ));
        }

        let verifying_key = VerifyingKey::from(public_key.unwrap());
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Parses a public key from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded public key (compressed or uncompressed)
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = crate::primitives::encoding::from_hex(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Verifies a signature on a message (will be hashed with SHA-256).
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::p256::P256PrivateKey;
    ///
    /// let key = P256PrivateKey::random();
    /// let pubkey = key.public_key();
    /// let message = b"Hello, P-256!";
    /// let sig = key.sign(message);
    ///
    /// assert!(pubkey.verify(message, &sig));
    /// assert!(!pubkey.verify(b"wrong message", &sig));
    /// ```
    pub fn verify(&self, message: &[u8], signature: &P256Signature) -> bool {
        let hash = sha256(message);
        self.verify_hash(&hash, signature)
    }

    /// Verifies a signature on a message hash directly.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte message hash
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &P256Signature) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        self.inner.verify_prehash(hash, &signature.inner).is_ok()
    }

    /// Exports the public key as compressed format (33 bytes).
    ///
    /// Format: `02/03 || X` where the prefix indicates Y parity.
    pub fn to_compressed(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        result
    }

    /// Exports the public key as uncompressed format (65 bytes).
    ///
    /// Format: `04 || X || Y`
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut result = [0u8; 65];
        result.copy_from_slice(bytes);
        result
    }

    /// Exports the public key as compressed hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_compressed())
    }

    /// Exports the public key as uncompressed hex.
    pub fn to_hex_uncompressed(&self) -> String {
        hex::encode(self.to_uncompressed())
    }

    /// Returns the X coordinate (32 bytes, big-endian).
    pub fn x(&self) -> [u8; 32] {
        let point = self.inner.to_encoded_point(false);
        let x_bytes = point.x().expect("not at infinity");
        let mut result = [0u8; 32];
        result.copy_from_slice(x_bytes);
        result
    }

    /// Returns the Y coordinate (32 bytes, big-endian).
    pub fn y(&self) -> [u8; 32] {
        let point = self.inner.to_encoded_point(false);
        let y_bytes = point.y().expect("not at infinity");
        let mut result = [0u8; 32];
        result.copy_from_slice(y_bytes);
        result
    }
}

impl std::fmt::Debug for P256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256PublicKey")
            .field("hex", &self.to_hex())
            .finish()
    }
}

impl std::fmt::Display for P256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A P-256 ECDSA signature.
///
/// Signatures can be serialized in DER format (variable length) or compact
/// format (fixed 64 bytes: R || S).
#[derive(Clone, PartialEq, Eq)]
pub struct P256Signature {
    inner: P256EcdsaSignature,
}

impl P256Signature {
    /// Creates a signature from R and S components (32 bytes each).
    ///
    /// # Arguments
    ///
    /// * `r` - The R component (32 bytes, big-endian)
    /// * `s` - The S component (32 bytes, big-endian)
    ///
    /// # Returns
    ///
    /// The signature, or an error if the components are invalid
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Result<Self> {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r);
        bytes[32..].copy_from_slice(&s);

        let sig = P256EcdsaSignature::from_slice(&bytes)
            .map_err(|e| Error::InvalidSignature(format!("invalid P-256 signature: {}", e)))?;

        Ok(Self { inner: sig })
    }

    /// Parses a signature from DER format.
    ///
    /// DER format: `0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>`
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded signature bytes
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let sig = P256EcdsaSignature::from_der(der)
            .map_err(|e| Error::InvalidSignature(format!("invalid DER signature: {}", e)))?;

        Ok(Self { inner: sig })
    }

    /// Parses a signature from compact format (64 bytes: R || S).
    ///
    /// # Arguments
    ///
    /// * `data` - The 64-byte compact signature
    pub fn from_compact(data: &[u8; 64]) -> Result<Self> {
        let sig = P256EcdsaSignature::from_slice(data)
            .map_err(|e| Error::InvalidSignature(format!("invalid compact signature: {}", e)))?;

        Ok(Self { inner: sig })
    }

    /// Parses a signature from compact format (slice version).
    ///
    /// # Arguments
    ///
    /// * `data` - The compact signature bytes (must be exactly 64 bytes)
    pub fn from_compact_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature(format!(
                "compact signature must be 64 bytes, got {}",
                data.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(data);
        Self::from_compact(&arr)
    }

    /// Returns the R component (32 bytes, big-endian).
    pub fn r(&self) -> [u8; 32] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32]);
        result
    }

    /// Returns the S component (32 bytes, big-endian).
    pub fn s(&self) -> [u8; 32] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[32..]);
        result
    }

    /// Encodes the signature in DER format.
    ///
    /// The signature is normalized to low-S form before encoding.
    pub fn to_der(&self) -> Vec<u8> {
        let normalized = self.to_low_s();
        normalized.inner.to_der().as_bytes().to_vec()
    }

    /// Encodes the signature in compact format (64 bytes: R || S).
    pub fn to_compact(&self) -> [u8; 64] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 64];
        result.copy_from_slice(&bytes);
        result
    }

    /// Checks if S is in low form (S <= n/2).
    pub fn is_low_s(&self) -> bool {
        let s = self.s();
        let half = half_order();

        // Compare as big-endian integers
        for i in 0..32 {
            if s[i] < half[i] {
                return true;
            }
            if s[i] > half[i] {
                return false;
            }
        }
        true // s == half_order, which is still low-S
    }

    /// Converts the signature to low-S form if needed.
    ///
    /// If S > n/2, returns a new signature with S' = n - S.
    /// Otherwise returns a clone of this signature.
    pub fn to_low_s(&self) -> P256Signature {
        if self.is_low_s() {
            return self.clone();
        }

        // Compute n - S
        let s = self.s();
        let n = curve_order();
        let new_s = subtract_mod_n(&n, &s);

        // Create new signature with same R, new S
        let r = self.r();
        P256Signature::new(r, new_s).expect("valid signature")
    }
}

/// Subtract two 256-bit numbers: a - b (assuming a >= b)
fn subtract_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;

    for i in (0..32).rev() {
        let diff = (a[i] as i16) - (b[i] as i16) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

impl std::fmt::Debug for P256Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256Signature")
            .field("r", &hex::encode(self.r()))
            .field("s", &hex::encode(self.s()))
            .finish()
    }
}

impl std::fmt::Display for P256Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_der()))
    }
}

// ============================================================================
// Convenience functions matching TypeScript API
// ============================================================================

/// Generates a random P-256 private key as hex.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::p256::generate_private_key_hex;
///
/// let hex = generate_private_key_hex();
/// assert_eq!(hex.len(), 64);
/// ```
pub fn generate_private_key_hex() -> String {
    P256PrivateKey::random().to_hex()
}

/// Gets the public key from a private key hex string.
///
/// # Arguments
///
/// * `private_key_hex` - The hex-encoded private key
///
/// # Returns
///
/// The corresponding public key, or an error if the private key is invalid
pub fn public_key_from_private(private_key_hex: &str) -> Result<P256PublicKey> {
    let key = P256PrivateKey::from_hex(private_key_hex)?;
    Ok(key.public_key())
}

/// Signs a message with a private key.
///
/// The message will be hashed with SHA-256 before signing.
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `private_key_hex` - The hex-encoded private key
///
/// # Returns
///
/// The signature, or an error if the private key is invalid
pub fn sign(message: &[u8], private_key_hex: &str) -> Result<P256Signature> {
    let key = P256PrivateKey::from_hex(private_key_hex)?;
    Ok(key.sign(message))
}

/// Verifies a signature on a message.
///
/// The message will be hashed with SHA-256 before verification.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise
pub fn verify(message: &[u8], signature: &P256Signature, public_key: &P256PublicKey) -> bool {
    public_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known P-256 test vectors from the TypeScript tests
    // 2G uncompressed
    const TWO_G: &str = "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    // 3G uncompressed
    const THREE_G: &str = "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";

    #[test]
    fn test_private_key_random() {
        let key1 = P256PrivateKey::random();
        let key2 = P256PrivateKey::random();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_key_from_bytes_roundtrip() {
        let key = P256PrivateKey::random();
        let bytes = key.to_bytes();
        let key2 = P256PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_key_from_hex_roundtrip() {
        let key = P256PrivateKey::random();
        let hex = key.to_hex();
        let key2 = P256PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(key.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_key_from_bytes_invalid_length() {
        assert!(P256PrivateKey::from_bytes(&[0u8; 31]).is_err());
        assert!(P256PrivateKey::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_public_key_generation_on_curve() {
        let key = P256PrivateKey::random();
        let pubkey = key.public_key();

        // Verify round-trip
        let compressed = pubkey.to_compressed();
        let recovered = P256PublicKey::from_bytes(&compressed).unwrap();
        assert_eq!(pubkey.to_hex(), recovered.to_hex());

        let uncompressed = pubkey.to_uncompressed();
        let recovered2 = P256PublicKey::from_bytes(&uncompressed).unwrap();
        assert_eq!(pubkey.to_hex(), recovered2.to_hex());
    }

    #[test]
    fn test_public_key_known_points() {
        // Test that scalar multiplication by 2 and 3 gives known points
        // We need to derive these by signing and checking coordinates
        // For now, just verify that the constant test vectors parse correctly
        let two_g = P256PublicKey::from_hex(TWO_G).unwrap();
        let three_g = P256PublicKey::from_hex(THREE_G).unwrap();

        assert_eq!(two_g.to_hex_uncompressed().to_lowercase(), TWO_G);
        assert_eq!(three_g.to_hex_uncompressed().to_lowercase(), THREE_G);
    }

    #[test]
    fn test_public_key_invalid_encoding() {
        // Bad prefix
        assert!(P256PublicKey::from_hex("05abcdef").is_err());
        // Too short
        assert!(P256PublicKey::from_hex("02").is_err());
        // Empty
        assert!(P256PublicKey::from_hex("").is_err());
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let priv_key = P256PrivateKey::from_hex(&"1".repeat(64)).unwrap();
        let pub_key = priv_key.public_key();
        let message = b"p256 check";

        let signature = priv_key.sign(message);

        // Low-S enforced
        assert!(signature.is_low_s());

        // Verify succeeds
        assert!(pub_key.verify(message, &signature));

        // Wrong message fails
        assert!(!pub_key.verify(b"different", &signature));
    }

    #[test]
    fn test_sign_deterministic() {
        let priv_key = P256PrivateKey::from_hex(&"2".repeat(64)).unwrap();
        let pub_key = priv_key.public_key();
        let message = b"deterministic nonce";

        let sig1 = priv_key.sign(message);
        let sig2 = priv_key.sign(message);

        // RFC 6979 ensures deterministic signatures
        assert_eq!(sig1.r(), sig2.r());
        assert_eq!(sig1.s(), sig2.s());

        // Different message gives different signature
        let sig3 = priv_key.sign(b"different message");
        assert_ne!(sig1.r(), sig3.r());

        // All verify
        assert!(pub_key.verify(message, &sig1));
        assert!(pub_key.verify(message, &sig2));
    }

    #[test]
    fn test_prehashed_signing() {
        let priv_key = P256PrivateKey::from_hex(&"4".repeat(64)).unwrap();
        let pub_key = priv_key.public_key();
        let message = b"prehashed path";

        let digest = sha256(message);
        let sig1 = priv_key.sign(message);
        let sig2 = priv_key.sign_hash(&digest);

        // Both should produce the same signature
        assert_eq!(sig1.r(), sig2.r());
        assert_eq!(sig1.s(), sig2.s());

        // Both verify
        assert!(pub_key.verify(message, &sig1));
        assert!(pub_key.verify_hash(&digest, &sig2));
    }

    #[test]
    fn test_signature_der_roundtrip() {
        let key = P256PrivateKey::random();
        let sig = key.sign(b"test message");

        let der = sig.to_der();
        let recovered = P256Signature::from_der(&der).unwrap();

        assert_eq!(sig.r(), recovered.r());
        // S might differ if original wasn't low-S (to_der normalizes)
        assert!(recovered.is_low_s());
    }

    #[test]
    fn test_signature_compact_roundtrip() {
        let key = P256PrivateKey::random();
        let sig = key.sign(b"test message");

        let compact = sig.to_compact();
        let recovered = P256Signature::from_compact(&compact).unwrap();

        assert_eq!(sig.r(), recovered.r());
        assert_eq!(sig.s(), recovered.s());
    }

    #[test]
    fn test_signature_new() {
        let r = [0x42u8; 32];
        let s = [0x43u8; 32];
        let sig = P256Signature::new(r, s).unwrap();
        assert_eq!(sig.r(), r);
        assert_eq!(sig.s(), s);
    }

    #[test]
    fn test_low_s_enforcement() {
        // Create a signature and check low-S
        let key = P256PrivateKey::random();
        let sig = key.sign(b"test");

        // Our sign() always returns low-S
        assert!(sig.is_low_s());

        // The half_order value should be correct
        let half = half_order();
        // n/2 for P-256 starts with 0x7f...
        assert_eq!(half[0], 0x7f);
    }

    #[test]
    fn test_verify_rejects_invalid_signatures() {
        let key = P256PrivateKey::random();
        let pubkey = key.public_key();
        let message = b"test message";
        let sig = key.sign(message);

        // Tampered R
        let mut tampered_r = sig.r();
        tampered_r[0] ^= 0xff;
        if let Ok(tampered_sig) = P256Signature::new(tampered_r, sig.s()) {
            assert!(!pubkey.verify(message, &tampered_sig));
        }

        // Tampered S
        let mut tampered_s = sig.s();
        tampered_s[0] ^= 0xff;
        if let Ok(tampered_sig) = P256Signature::new(sig.r(), tampered_s) {
            assert!(!pubkey.verify(message, &tampered_sig));
        }
    }

    #[test]
    fn test_convenience_functions() {
        let hex = generate_private_key_hex();
        assert_eq!(hex.len(), 64);

        let pubkey = public_key_from_private(&hex).unwrap();
        let message = b"hello";
        let sig = sign(message, &hex).unwrap();

        assert!(verify(message, &sig, &pubkey));
        assert!(!verify(b"wrong", &sig, &pubkey));
    }

    #[test]
    fn test_public_key_coordinates() {
        let key = P256PrivateKey::random();
        let pubkey = key.public_key();

        let x = pubkey.x();
        let y = pubkey.y();

        // X and Y should be 32 bytes each
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);

        // Uncompressed should be 04 || X || Y
        let uncompressed = pubkey.to_uncompressed();
        assert_eq!(uncompressed[0], 0x04);
        assert_eq!(&uncompressed[1..33], &x);
        assert_eq!(&uncompressed[33..65], &y);
    }

    #[test]
    fn test_from_compact_slice_invalid_length() {
        assert!(P256Signature::from_compact_slice(&[0u8; 63]).is_err());
        assert!(P256Signature::from_compact_slice(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_subtract_mod_n() {
        // Simple test: 5 - 3 = 2
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 5;
        b[31] = 3;
        let result = subtract_mod_n(&a, &b);
        assert_eq!(result[31], 2);

        // Test with borrow
        a = [0u8; 32];
        b = [0u8; 32];
        a[30] = 1;
        a[31] = 0;
        b[31] = 1;
        let result = subtract_mod_n(&a, &b);
        assert_eq!(result[31], 0xff);
        assert_eq!(result[30], 0);
    }
}
