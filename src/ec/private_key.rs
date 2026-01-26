//! Private key operations for secp256k1.
//!
//! This module provides the [`PrivateKey`] struct for working with secp256k1 private keys,
//! including signing, WIF encoding/decoding, and BRC-42 key derivation.

use crate::encoding::{from_base58_check, from_hex, to_base58_check, to_hex};
use crate::error::{Error, Result};
use crate::hash::sha256_hmac;
use crate::BigNumber;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use k256::SecretKey;

use super::{PublicKey, Signature};

/// A secp256k1 private key.
///
/// Private keys are 32-byte scalars in the range [1, n-1] where n is the curve order.
/// They are used for signing messages and deriving child keys using BRC-42.
///
/// # Security
///
/// Private keys are sensitive data. This implementation:
/// - Zeros the key bytes on drop
/// - Does not expose the key in Debug output
#[derive(Clone)]
pub struct PrivateKey {
    inner: SecretKey,
}

impl PrivateKey {
    /// Generates a random private key using the operating system's CSPRNG.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// assert_eq!(key.to_bytes().len(), 32);
    /// ```
    pub fn random() -> Self {
        let inner = SecretKey::random(&mut OsRng);
        Self { inner }
    }

    /// Creates a private key from raw 32-byte secret.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte secret value
    ///
    /// # Returns
    ///
    /// The private key, or an error if the value is invalid (zero or >= curve order)
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let key = PrivateKey::from_bytes(&bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let inner = SecretKey::from_slice(bytes)
            .map_err(|e| Error::InvalidPrivateKey(format!("Invalid key bytes: {}", e)))?;

        Ok(Self { inner })
    }

    /// Creates a private key from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded 32-byte secret
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = from_hex(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a private key from WIF (Wallet Import Format).
    ///
    /// WIF is Base58Check encoded with:
    /// - Version byte: 0x80 (mainnet) or 0xef (testnet)
    /// - 32 bytes private key
    /// - Optional compression flag: 0x01
    /// - 4 byte checksum
    ///
    /// # Arguments
    ///
    /// * `wif` - The WIF-encoded private key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    /// let key = PrivateKey::from_wif(wif).unwrap();
    /// ```
    pub fn from_wif(wif: &str) -> Result<Self> {
        let (version, payload) = from_base58_check(wif)?;

        // Version should be 0x80 (mainnet) or 0xef (testnet)
        if version.len() != 1 || (version[0] != 0x80 && version[0] != 0xef) {
            return Err(Error::InvalidPrivateKey(format!(
                "Invalid WIF version byte: expected 0x80 or 0xef, got {:02x}",
                version.get(0).unwrap_or(&0)
            )));
        }

        // Payload is either 32 bytes (uncompressed) or 33 bytes (compressed with 0x01 suffix)
        let key_bytes = if payload.len() == 33 && payload[32] == 0x01 {
            &payload[..32]
        } else if payload.len() == 32 {
            &payload[..]
        } else {
            return Err(Error::InvalidPrivateKey(format!(
                "Invalid WIF payload length: expected 32 or 33 bytes, got {}",
                payload.len()
            )));
        };

        Self::from_bytes(key_bytes)
    }

    /// Returns the corresponding public key.
    ///
    /// This performs scalar multiplication: `G * private_key`
    pub fn public_key(&self) -> PublicKey {
        let verifying_key = self.inner.public_key();
        PublicKey::from_k256(verifying_key.into())
    }

    /// Signs a message hash (32 bytes) and returns a low-S signature.
    ///
    /// Uses RFC 6979 deterministic nonce generation for security.
    /// The resulting signature is always in low-S form (BIP 62 compliant).
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - The 32-byte message hash (e.g., SHA-256 of the message)
    ///
    /// # Returns
    ///
    /// A low-S signature, or an error if signing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    /// use bsv_primitives::hash::sha256;
    ///
    /// let key = PrivateKey::random();
    /// let msg_hash = sha256(b"Hello, BSV!");
    /// let signature = key.sign(&msg_hash).unwrap();
    ///
    /// assert!(signature.is_low_s());
    /// assert!(key.public_key().verify(&msg_hash, &signature));
    /// ```
    pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<Signature> {
        let signing_key = SigningKey::from(&self.inner);

        // Use prehash signing (RFC 6979)
        let (sig, _recovery_id): (k256::ecdsa::Signature, _) = signing_key
            .sign_prehash(msg_hash)
            .map_err(|e| Error::CryptoError(format!("Signing failed: {}", e)))?;

        // Convert to our Signature type
        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        let signature = Signature::new(r, s);

        // Ensure low-S (BIP 62)
        Ok(signature.to_low_s())
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
        to_hex(&self.to_bytes())
    }

    /// Exports the private key as WIF (mainnet, compressed).
    ///
    /// Uses version byte 0x80 and includes the compression flag 0x01.
    pub fn to_wif(&self) -> String {
        self.to_wif_with_prefix(0x80)
    }

    /// Exports the private key as WIF with a custom version prefix.
    ///
    /// Common prefixes:
    /// - `0x80` - Mainnet
    /// - `0xef` - Testnet
    ///
    /// # Arguments
    ///
    /// * `prefix` - The version byte to use
    pub fn to_wif_with_prefix(&self, prefix: u8) -> String {
        let mut payload = Vec::with_capacity(33);
        payload.extend_from_slice(&self.to_bytes());
        payload.push(0x01); // Compression flag

        to_base58_check(&payload, &[prefix])
    }

    /// Derives a shared secret using ECDH.
    ///
    /// Computes: `other_pubkey * self`
    ///
    /// # Arguments
    ///
    /// * `other_pubkey` - The other party's public key
    ///
    /// # Returns
    ///
    /// The shared secret as a public key (representing the resulting point)
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let alice = PrivateKey::random();
    /// let bob = PrivateKey::random();
    ///
    /// // Both arrive at the same shared secret
    /// let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
    /// let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();
    ///
    /// assert_eq!(alice_shared.to_compressed(), bob_shared.to_compressed());
    /// ```
    pub fn derive_shared_secret(&self, other_pubkey: &PublicKey) -> Result<PublicKey> {
        other_pubkey.mul_scalar(&self.to_bytes())
    }

    /// Derives a child private key using BRC-42 key derivation.
    ///
    /// Algorithm:
    /// 1. Compute shared secret: `other_pubkey * self` (ECDH)
    /// 2. Compute HMAC: `HMAC-SHA256(invoice_number, compressed_shared_secret)`
    /// 3. New key: `(self + HMAC) mod n`
    ///
    /// # Arguments
    ///
    /// * `other_pubkey` - The other party's public key
    /// * `invoice_number` - A unique string identifier for this derivation
    ///
    /// # Returns
    ///
    /// The derived child private key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::ec::PrivateKey;
    ///
    /// let alice_priv = PrivateKey::random();
    /// let bob_priv = PrivateKey::random();
    ///
    /// // Bob derives a child private key using Alice's public key
    /// let bob_child = bob_priv.derive_child(&alice_priv.public_key(), "invoice-123").unwrap();
    ///
    /// // Alice derives the corresponding child public key
    /// let alice_derived_pub = bob_priv.public_key().derive_child(&alice_priv, "invoice-123").unwrap();
    ///
    /// // They get the same public key
    /// assert_eq!(bob_child.public_key().to_compressed(), alice_derived_pub.to_compressed());
    /// ```
    pub fn derive_child(&self, other_pubkey: &PublicKey, invoice_number: &str) -> Result<PrivateKey> {
        // 1. Compute shared secret
        let shared_secret = self.derive_shared_secret(other_pubkey)?;

        // 2. HMAC-SHA256 with key=compressed_shared_secret, data=invoice_number
        // This matches the Go SDK: crypto.Sha256HMAC(invoiceNumberBin, sharedSecret.Compressed())
        // where Go's Sha256HMAC(data, key) has data first, key second
        let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

        // 3. new_key = (self + hmac) mod n
        let self_scalar = BigNumber::from_bytes_be(&self.to_bytes());
        let hmac_scalar = BigNumber::from_bytes_be(&hmac);
        let order = BigNumber::secp256k1_order();

        let new_scalar = self_scalar.add(&hmac_scalar).modulo(&order);

        // Check that the result is not zero
        if new_scalar.is_zero() {
            return Err(Error::CryptoError(
                "Derived key would be zero".to_string(),
            ));
        }

        let new_bytes = new_scalar.to_bytes_be(32);
        PrivateKey::from_bytes(&new_bytes)
    }

}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Note: k256::SecretKey already implements Zeroize, so the internal
        // secret is automatically zeroed when dropped.
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key().to_hex())
            .finish_non_exhaustive()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for PrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[test]
    fn test_private_key_random() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        // Two random keys should be different
        assert_ne!(key1.to_hex(), key2.to_hex());

        // Should be 32 bytes
        assert_eq!(key1.to_bytes().len(), 32);
    }

    #[test]
    fn test_private_key_from_bytes() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // Key value = 1

        let key = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_from_hex() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = PrivateKey::from_hex(hex).unwrap();

        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(key.to_bytes(), expected);
    }

    #[test]
    fn test_private_key_invalid_length() {
        let short = [0u8; 31];
        assert!(PrivateKey::from_bytes(&short).is_err());

        let long = [0u8; 33];
        assert!(PrivateKey::from_bytes(&long).is_err());
    }

    #[test]
    fn test_private_key_zero_is_invalid() {
        let zero = [0u8; 32];
        assert!(PrivateKey::from_bytes(&zero).is_err());
    }

    #[test]
    fn test_private_key_wif_roundtrip() {
        // Known WIF test vector
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let key = PrivateKey::from_wif(wif).unwrap();
        assert_eq!(key.to_wif(), wif);
    }

    #[test]
    fn test_private_key_wif_uncompressed() {
        // Uncompressed WIF (no 0x01 suffix in payload)
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let key = PrivateKey::from_wif(wif).unwrap();

        // Should still work
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    fn test_private_key_to_public_key() {
        // Known test vector: private key 1 -> generator point G
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = PrivateKey::from_hex(hex).unwrap();
        let pubkey = key.public_key();

        // Generator point compressed
        assert_eq!(
            pubkey.to_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let msg_hash = sha256(b"Hello, BSV!");
        let signature = key.sign(&msg_hash).unwrap();

        // Signature should be low-S
        assert!(signature.is_low_s());

        // Should verify with correct public key
        assert!(pubkey.verify(&msg_hash, &signature));
    }

    #[test]
    fn test_sign_deterministic() {
        // RFC 6979 should produce deterministic signatures
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let msg_hash = sha256(b"test");
        let sig1 = key.sign(&msg_hash).unwrap();
        let sig2 = key.sign(&msg_hash).unwrap();

        assert_eq!(sig1.r(), sig2.r());
        assert_eq!(sig1.s(), sig2.s());
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();

        let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
        let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();

        assert_eq!(alice_shared.to_compressed(), bob_shared.to_compressed());
    }

    #[test]
    fn test_derive_child_consistency() {
        // Test that private key derivation and public key derivation are consistent
        let alice_priv = PrivateKey::random();
        let bob_priv = PrivateKey::random();
        let invoice = "test-invoice-12345";

        // Bob derives child private key
        let bob_child_priv = bob_priv.derive_child(&alice_priv.public_key(), invoice).unwrap();

        // Alice derives child public key (for Bob)
        let bob_child_pub_from_alice = bob_priv.public_key().derive_child(&alice_priv, invoice).unwrap();

        // They should match
        assert_eq!(
            bob_child_priv.public_key().to_compressed(),
            bob_child_pub_from_alice.to_compressed()
        );
    }

    #[test]
    fn test_private_key_equality() {
        let bytes = [1u8; 32];
        let key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_wif_testnet() {
        // Test testnet WIF (version 0xef)
        let key = PrivateKey::random();
        let wif = key.to_wif_with_prefix(0xef);

        // Testnet compressed WIF starts with 'c'
        assert!(wif.starts_with('c'));

        // Should round-trip
        let recovered = PrivateKey::from_wif(&wif).unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }
}
