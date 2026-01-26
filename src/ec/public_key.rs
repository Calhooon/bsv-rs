//! Public key operations for secp256k1.
//!
//! This module provides the [`PublicKey`] struct for working with secp256k1 public keys,
//! including serialization, address generation, signature verification, and BRC-42 key derivation.

use crate::encoding::{from_hex, to_base58_check, to_hex};
use crate::error::{Error, Result};
use crate::hash::{hash160, sha256_hmac};
use crate::BigNumber;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, PublicKey as K256PublicKey, Scalar, U256};

use super::Signature;

/// A secp256k1 public key.
///
/// Public keys can be serialized in compressed (33 bytes) or uncompressed (65 bytes) format.
/// They are used for signature verification, address generation, and BRC-42 key derivation.
#[derive(Clone)]
pub struct PublicKey {
    inner: K256PublicKey,
}

impl PublicKey {
    /// Parses a public key from compressed (33 bytes) or uncompressed (65 bytes) format.
    ///
    /// Compressed format: `02/03 || X` (33 bytes)
    /// Uncompressed format: `04 || X || Y` (65 bytes)
    ///
    /// # Arguments
    ///
    /// * `bytes` - The encoded public key bytes
    ///
    /// # Returns
    ///
    /// The parsed public key, or an error if the format is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = EncodedPoint::from_bytes(bytes).map_err(|e| {
            Error::InvalidPublicKey(format!("Invalid public key encoding: {}", e))
        })?;

        let point = AffinePoint::from_encoded_point(&encoded);
        if point.is_none().into() {
            return Err(Error::InvalidPublicKey(
                "Point not on curve".to_string(),
            ));
        }

        let inner = K256PublicKey::from_affine(point.unwrap())
            .map_err(|_| Error::InvalidPublicKey("Invalid point".to_string()))?;

        Ok(Self { inner })
    }

    /// Parses a public key from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded public key
    ///
    /// # Returns
    ///
    /// The parsed public key, or an error if the format is invalid
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = from_hex(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a public key from a private key.
    ///
    /// This performs scalar multiplication: `G * private_key`
    pub fn from_private_key(private_key: &super::PrivateKey) -> Self {
        private_key.public_key()
    }

    /// Verifies a signature against a message hash.
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - The 32-byte message hash
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(&self, msg_hash: &[u8; 32], signature: &Signature) -> bool {
        super::verify(msg_hash, signature, self)
    }

    /// Exports the public key in compressed format (33 bytes).
    ///
    /// Format: `02/03 || X` where the prefix indicates Y coordinate parity.
    pub fn to_compressed(&self) -> [u8; 33] {
        let encoded = self.inner.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        result
    }

    /// Exports the public key in uncompressed format (65 bytes).
    ///
    /// Format: `04 || X || Y`
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let encoded = self.inner.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let mut result = [0u8; 65];
        result.copy_from_slice(bytes);
        result
    }

    /// Exports the public key as a compressed hex string.
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_compressed())
    }

    /// Exports the public key as an uncompressed hex string.
    pub fn to_hex_uncompressed(&self) -> String {
        to_hex(&self.to_uncompressed())
    }

    /// Returns the X coordinate as bytes (32 bytes, big-endian).
    pub fn x(&self) -> [u8; 32] {
        let encoded = self.inner.to_encoded_point(false);
        let x_bytes = encoded.x().expect("point not at infinity");
        let mut result = [0u8; 32];
        result.copy_from_slice(x_bytes);
        result
    }

    /// Returns the Y coordinate as bytes (32 bytes, big-endian).
    pub fn y(&self) -> [u8; 32] {
        let encoded = self.inner.to_encoded_point(false);
        let y_bytes = encoded.y().expect("point not at infinity");
        let mut result = [0u8; 32];
        result.copy_from_slice(y_bytes);
        result
    }

    /// Checks if the Y coordinate is even.
    ///
    /// This determines the compression prefix: `02` for even Y, `03` for odd Y.
    pub fn y_is_even(&self) -> bool {
        let y = self.y();
        // Check the least significant bit
        y[31] & 1 == 0
    }

    /// Computes the hash160 of the compressed public key.
    ///
    /// This is `RIPEMD160(SHA256(compressed_pubkey))`, used for Bitcoin addresses.
    pub fn hash160(&self) -> [u8; 20] {
        hash160(&self.to_compressed())
    }

    /// Converts to a Bitcoin address (P2PKH, mainnet).
    ///
    /// This uses version byte `0x00` for mainnet P2PKH addresses.
    pub fn to_address(&self) -> String {
        self.to_address_with_prefix(0x00)
    }

    /// Converts to a Bitcoin address with a custom version prefix.
    ///
    /// Common prefixes:
    /// - `0x00` - Mainnet P2PKH
    /// - `0x6f` - Testnet P2PKH
    ///
    /// # Arguments
    ///
    /// * `version` - The version byte to use
    pub fn to_address_with_prefix(&self, version: u8) -> String {
        let hash = self.hash160();
        to_base58_check(&hash, &[version])
    }

    /// Derives a child public key using BRC-42 key derivation.
    ///
    /// Algorithm:
    /// 1. Compute shared secret: `this * other_privkey` (ECDH)
    /// 2. Compute HMAC: `HMAC-SHA256(invoice_number, compressed_shared_secret)`
    /// 3. Compute offset point: `G * HMAC`
    /// 4. New public key: `this + offset_point`
    ///
    /// # Arguments
    ///
    /// * `other_privkey` - The other party's private key
    /// * `invoice_number` - A unique string identifier for this derivation
    ///
    /// # Returns
    ///
    /// The derived child public key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let alice_priv = PrivateKey::random();
    /// let bob_priv = PrivateKey::random();
    ///
    /// // Alice can derive Bob's child public key
    /// let bob_child_pub = bob_priv.public_key().derive_child(&alice_priv, "invoice-123").unwrap();
    ///
    /// // Bob can derive his own child private key and get the same public key
    /// let bob_child_priv = bob_priv.derive_child(&alice_priv.public_key(), "invoice-123").unwrap();
    /// assert_eq!(bob_child_pub.to_compressed(), bob_child_priv.public_key().to_compressed());
    /// ```
    pub fn derive_child(
        &self,
        other_privkey: &super::PrivateKey,
        invoice_number: &str,
    ) -> Result<PublicKey> {
        // 1. Compute shared secret using ECDH
        let shared_secret = self.derive_shared_secret(other_privkey)?;

        // 2. Compute HMAC-SHA256 with key=compressed_shared_secret, data=invoice_number
        // This matches the Go SDK: crypto.Sha256HMAC(invoiceNumberBin, pubKeyEncoded)
        // where Go's Sha256HMAC(data, key) has data first, key second
        let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

        // 3. Compute G * hmac (scalar base multiplication)
        let hmac_scalar = BigNumber::from_bytes_be(&hmac);
        let order = BigNumber::secp256k1_order();
        let hmac_mod = hmac_scalar.modulo(&order);
        let hmac_bytes = hmac_mod.to_bytes_be(32);

        let scalar = bytes_to_scalar(&hmac_bytes)?;

        let generator = ProjectivePoint::GENERATOR;
        let offset_point = generator * scalar;

        // 4. Add offset point to this public key
        let self_point = ProjectivePoint::from(*self.inner.as_affine());
        let new_point = self_point + offset_point;

        let new_affine = new_point.to_affine();
        if new_affine.is_identity().into() {
            return Err(Error::PointAtInfinity);
        }

        let new_pubkey = K256PublicKey::from_affine(new_affine)
            .map_err(|_| Error::InvalidPublicKey("Result is invalid".to_string()))?;

        Ok(Self { inner: new_pubkey })
    }

    /// Performs scalar multiplication on this public key.
    ///
    /// Returns: `this * scalar`
    ///
    /// This is used internally for ECDH.
    pub fn mul_scalar(&self, scalar_bytes: &[u8; 32]) -> Result<PublicKey> {
        let scalar = bytes_to_scalar(scalar_bytes)?;

        let point = ProjectivePoint::from(*self.inner.as_affine());
        let result = point * scalar;

        let affine = result.to_affine();
        if affine.is_identity().into() {
            return Err(Error::PointAtInfinity);
        }

        let pubkey = K256PublicKey::from_affine(affine)
            .map_err(|_| Error::InvalidPublicKey("Result is invalid".to_string()))?;

        Ok(Self { inner: pubkey })
    }

    /// Derives a shared secret using ECDH.
    ///
    /// Computes: `this * other_privkey`
    ///
    /// # Arguments
    ///
    /// * `other_privkey` - The other party's private key
    ///
    /// # Returns
    ///
    /// The shared secret as a public key (representing the resulting point)
    pub fn derive_shared_secret(&self, other_privkey: &super::PrivateKey) -> Result<PublicKey> {
        let scalar_bytes = other_privkey.to_bytes();
        self.mul_scalar(&scalar_bytes)
    }

    /// Creates a public key from an internal k256 public key.
    pub(crate) fn from_k256(inner: K256PublicKey) -> Self {
        Self { inner }
    }
}

/// Helper function to convert 32 bytes to a Scalar.
fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != 32 {
        return Err(Error::CryptoError(format!(
            "Expected 32 bytes for scalar, got {}",
            bytes.len()
        )));
    }

    // Convert bytes to U256 (big-endian)
    let uint = U256::from_be_slice(bytes);

    // Create scalar from uint (reducing mod n if necessary)
    let scalar = Scalar::from_uint_unchecked(uint);
    Ok(scalar)
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed() == other.to_compressed()
    }
}

impl Eq for PublicKey {}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("compressed", &self.to_hex())
            .finish()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_compressed().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_from_hex_compressed() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();
        assert_eq!(pubkey.to_hex(), hex);
    }

    #[test]
    fn test_public_key_from_hex_uncompressed() {
        let hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        // Should round-trip to compressed
        assert_eq!(
            pubkey.to_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_public_key_compression() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        let compressed = pubkey.to_compressed();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        let uncompressed = pubkey.to_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
    }

    #[test]
    fn test_public_key_x_y_coordinates() {
        // Generator point G
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        let x = pubkey.x();
        assert_eq!(
            to_hex(&x),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        // For the generator point with even Y (prefix 02)
        assert!(pubkey.y_is_even());
    }

    #[test]
    fn test_public_key_hash160() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        let h160 = pubkey.hash160();
        assert_eq!(h160.len(), 20);
    }

    #[test]
    fn test_public_key_to_address() {
        // Known test vector: generator point
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        let address = pubkey.to_address();
        // This is the mainnet address for the generator point (compressed)
        assert_eq!(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_public_key_equality() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey1 = PublicKey::from_hex(hex).unwrap();
        let pubkey2 = PublicKey::from_hex(hex).unwrap();

        assert_eq!(pubkey1, pubkey2);
    }

    #[test]
    fn test_public_key_invalid_hex() {
        assert!(PublicKey::from_hex("invalid").is_err());
        assert!(PublicKey::from_hex("02").is_err());
    }

    #[test]
    fn test_public_key_mul_scalar() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = PublicKey::from_hex(hex).unwrap();

        let mut scalar = [0u8; 32];
        scalar[31] = 2; // scalar = 2

        let result = pubkey.mul_scalar(&scalar).unwrap();
        // Should be 2G
        assert!(result.to_hex() != pubkey.to_hex());
    }
}
