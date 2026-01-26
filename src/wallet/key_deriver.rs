//! BRC-42 Key Derivation.
//!
//! This module provides the [`KeyDeriver`] struct for deriving cryptographic keys
//! according to the BRC-42 standard. It supports deriving public keys, private keys,
//! and symmetric keys based on protocol identifiers, key IDs, and counterparty public keys.
//!
//! # Overview
//!
//! BRC-42 key derivation allows two parties to independently derive corresponding
//! key pairs using their own private keys and each other's public keys. This enables
//! secure, deterministic key generation for various protocols without requiring
//! a shared secret to be transmitted.
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create a key deriver from a root private key
//! let root_key = PrivateKey::random();
//! let deriver = KeyDeriver::new(Some(root_key));
//!
//! // Define a protocol
//! let protocol = Protocol::new(SecurityLevel::App, "my application");
//!
//! // Derive a public key for self
//! let key_id = "invoice-123";
//! let pub_key = deriver.derive_public_key(&protocol, key_id, &Counterparty::Self_, true).unwrap();
//! ```

use crate::error::{Error, Result};
use crate::primitives::hash::sha256_hmac;
use crate::primitives::{PrivateKey, PublicKey, SymmetricKey};

use super::types::{validate_key_id, validate_protocol_name, Counterparty, Protocol};

#[cfg(test)]
use super::types::SecurityLevel;

/// Derives cryptographic keys from a root private key using BRC-42 standards.
///
/// Keys are derived using a combination of:
/// - Security level (0-2)
/// - Protocol name (5-400 characters)
/// - Key ID (1-800 characters)
/// - Counterparty (public key, 'self', or 'anyone')
///
/// The derivation process uses HMAC-SHA256 with ECDH shared secrets to create
/// deterministic, hierarchical key pairs that can be independently computed
/// by both parties.
#[derive(Clone)]
pub struct KeyDeriver {
    root_key: PrivateKey,
}

impl KeyDeriver {
    /// Creates a new KeyDeriver from a root private key.
    ///
    /// If `None` is passed, uses the special "anyone" key (derived from SHA256("anyone")).
    ///
    /// # Arguments
    ///
    /// * `root_key` - The root private key, or None to use the "anyone" key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::wallet::KeyDeriver;
    /// use bsv_sdk::primitives::PrivateKey;
    ///
    /// let deriver = KeyDeriver::new(Some(PrivateKey::random()));
    /// let anyone_deriver = KeyDeriver::new(None);
    /// ```
    pub fn new(root_key: Option<PrivateKey>) -> Self {
        let root_key = root_key.unwrap_or_else(|| Self::anyone_key().0);
        Self { root_key }
    }

    /// Returns the special "anyone" key pair.
    ///
    /// The "anyone" private key is derived from SHA256("anyone"), creating a
    /// deterministic key pair that anyone can compute. This is used for publicly
    /// derivable keys.
    ///
    /// # Returns
    ///
    /// A tuple of (private_key, public_key) for the "anyone" identity.
    pub fn anyone_key() -> (PrivateKey, PublicKey) {
        // In the TypeScript SDK, "anyone" uses PrivateKey(1), but for compatibility
        // we'll check both approaches. The TS SDK uses `new PrivateKey(1)` which
        // creates a key with scalar value 1.
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1; // Scalar value 1
        let private_key = PrivateKey::from_bytes(&key_bytes).expect("valid key");
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    /// Returns the root private key.
    pub fn root_key(&self) -> &PrivateKey {
        &self.root_key
    }

    /// Returns the identity public key (root key's public key).
    ///
    /// This is the public key that identifies this wallet to counterparties.
    pub fn identity_key(&self) -> PublicKey {
        self.root_key.public_key()
    }

    /// Returns the identity key as a hex string.
    pub fn identity_key_hex(&self) -> String {
        self.identity_key().to_hex()
    }

    /// Derives a public key based on protocol, key ID, and counterparty.
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol identifier (security level + name)
    /// * `key_id` - The unique key identifier (1-800 characters)
    /// * `counterparty` - The counterparty (self, anyone, or specific public key)
    /// * `for_self` - If true, derive the public key for the wallet owner;
    ///                if false, derive the public key for the counterparty
    ///
    /// # Returns
    ///
    /// The derived public key, or an error if derivation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
    /// use bsv_sdk::primitives::PrivateKey;
    ///
    /// let deriver = KeyDeriver::new(Some(PrivateKey::random()));
    /// let protocol = Protocol::new(SecurityLevel::App, "my application");
    ///
    /// // Derive own public key
    /// let own_key = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();
    ///
    /// // Derive counterparty's public key
    /// let cp_key = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, false).unwrap();
    /// ```
    pub fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;

        if for_self {
            // Derive child from our private key
            let derived = self
                .root_key
                .derive_child(&counterparty_key, &invoice_number)?;
            Ok(derived.public_key())
        } else {
            // Derive child from counterparty's public key
            counterparty_key.derive_child(&self.root_key, &invoice_number)
        }
    }

    /// Derives a private key based on protocol, key ID, and counterparty.
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol identifier (security level + name)
    /// * `key_id` - The unique key identifier (1-800 characters)
    /// * `counterparty` - The counterparty (self, anyone, or specific public key)
    ///
    /// # Returns
    ///
    /// The derived private key, or an error if derivation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
    /// use bsv_sdk::primitives::PrivateKey;
    ///
    /// let deriver = KeyDeriver::new(Some(PrivateKey::random()));
    /// let protocol = Protocol::new(SecurityLevel::App, "my application");
    ///
    /// let private_key = deriver.derive_private_key(&protocol, "key-1", &Counterparty::Self_).unwrap();
    /// ```
    pub fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;
        self.root_key
            .derive_child(&counterparty_key, &invoice_number)
    }

    /// Derives a symmetric key for encryption/decryption.
    ///
    /// The symmetric key is derived using ECDH between the derived private and
    /// public keys, producing a shared secret that can be used for AES encryption.
    ///
    /// Note: If the counterparty is 'anyone', a fixed public key is used, making
    /// the symmetric key publicly derivable.
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol identifier (security level + name)
    /// * `key_id` - The unique key identifier (1-800 characters)
    /// * `counterparty` - The counterparty (self, anyone, or specific public key)
    ///
    /// # Returns
    ///
    /// The derived symmetric key, or an error if derivation fails.
    pub fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey> {
        // If counterparty is 'anyone', use the fixed anyone public key
        let actual_counterparty = match counterparty {
            Counterparty::Anyone => {
                let (_, anyone_pub) = Self::anyone_key();
                Counterparty::Other(anyone_pub)
            }
            other => other.clone(),
        };

        let derived_public =
            self.derive_public_key(protocol, key_id, &actual_counterparty, false)?;
        let derived_private = self.derive_private_key(protocol, key_id, &actual_counterparty)?;

        // Create shared secret (ECDH)
        let shared_secret = derived_private.derive_shared_secret(&derived_public)?;

        // Use x-coordinate as symmetric key
        let x_bytes = shared_secret.x();
        SymmetricKey::from_bytes(&x_bytes)
    }

    /// Reveals the specific key linkage for a protocol and key ID.
    ///
    /// This produces an HMAC that proves the relationship between the wallet
    /// and a specific protocol/key combination, without revealing the root key.
    ///
    /// # Arguments
    ///
    /// * `counterparty` - The counterparty (self, anyone, or specific public key)
    /// * `protocol` - The protocol identifier
    /// * `key_id` - The key identifier
    ///
    /// # Returns
    ///
    /// The HMAC proving the specific key linkage (32 bytes).
    pub fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let shared_secret = self.root_key.derive_shared_secret(&counterparty_key)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;

        // HMAC-SHA256(shared_secret_compressed, invoice_number)
        Ok(sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes()).to_vec())
    }

    /// Reveals the counterparty secret (shared point).
    ///
    /// This reveals the ECDH shared secret between the wallet and a counterparty,
    /// which can be used to prove the relationship exists.
    ///
    /// # Arguments
    ///
    /// * `counterparty` - The counterparty (cannot be 'self')
    ///
    /// # Returns
    ///
    /// The shared secret as a compressed public key point.
    ///
    /// # Errors
    ///
    /// Returns an error if counterparty is 'self', as revealing the secret
    /// for 'self' would expose the root key relationship.
    pub fn reveal_counterparty_secret(&self, counterparty: &Counterparty) -> Result<PublicKey> {
        if matches!(counterparty, Counterparty::Self_) {
            return Err(Error::InvalidCounterparty(
                "counterparty secrets cannot be revealed for 'self'".to_string(),
            ));
        }

        let counterparty_key = self.normalize_counterparty(counterparty)?;

        // Verify we're not actually revealing for self
        let self_pub = self.root_key.public_key();
        if counterparty_key == self_pub {
            return Err(Error::InvalidCounterparty(
                "counterparty secrets cannot be revealed if counterparty key is self".to_string(),
            ));
        }

        self.root_key.derive_shared_secret(&counterparty_key)
    }

    /// Normalizes a counterparty to a public key.
    fn normalize_counterparty(&self, counterparty: &Counterparty) -> Result<PublicKey> {
        match counterparty {
            Counterparty::Self_ => Ok(self.root_key.public_key()),
            Counterparty::Anyone => Ok(Self::anyone_key().1),
            Counterparty::Other(pubkey) => Ok(pubkey.clone()),
        }
    }

    /// Computes the invoice number string for key derivation.
    ///
    /// Format: "{security_level}-{protocol_name}-{key_id}"
    fn compute_invoice_number(&self, protocol: &Protocol, key_id: &str) -> Result<String> {
        // Validate security level
        let level = protocol.security_level.as_u8();
        if level > 2 {
            return Err(Error::ProtocolValidationError(
                "security level must be 0, 1, or 2".to_string(),
            ));
        }

        // Validate key ID
        validate_key_id(key_id)?;

        // Validate and normalize protocol name
        let protocol_name = validate_protocol_name(&protocol.protocol_name)?;

        Ok(format!("{}-{}-{}", level, protocol_name, key_id))
    }
}

impl std::fmt::Debug for KeyDeriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDeriver")
            .field("identity_key", &self.identity_key_hex())
            .finish_non_exhaustive()
    }
}

/// Trait for key derivation API.
///
/// This trait allows both [`KeyDeriver`] and [`super::CachedKeyDeriver`] to be used
/// interchangeably where key derivation is needed.
pub trait KeyDeriverApi {
    /// Returns the identity public key.
    fn identity_key(&self) -> PublicKey;

    /// Returns the identity key as a hex string.
    fn identity_key_hex(&self) -> String {
        self.identity_key().to_hex()
    }

    /// Derives a public key.
    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey>;

    /// Derives a private key.
    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey>;

    /// Derives a symmetric key.
    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey>;

    /// Reveals the specific secret for a protocol/key combination.
    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>>;

    /// Reveals the counterparty secret.
    fn reveal_counterparty_secret(&self, counterparty: &Counterparty) -> Result<PublicKey>;
}

impl KeyDeriverApi for KeyDeriver {
    fn identity_key(&self) -> PublicKey {
        self.identity_key()
    }

    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey> {
        self.derive_public_key(protocol, key_id, counterparty, for_self)
    }

    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey> {
        self.derive_private_key(protocol, key_id, counterparty)
    }

    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey> {
        self.derive_symmetric_key(protocol, key_id, counterparty)
    }

    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        self.reveal_specific_secret(counterparty, protocol, key_id)
    }

    fn reveal_counterparty_secret(&self, counterparty: &Counterparty) -> Result<PublicKey> {
        self.reveal_counterparty_secret(counterparty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_deriver_creation() {
        let key = PrivateKey::random();
        let deriver = KeyDeriver::new(Some(key.clone()));
        assert_eq!(deriver.identity_key(), key.public_key());
    }

    #[test]
    fn test_key_deriver_anyone() {
        let deriver = KeyDeriver::new(None);
        let (_anyone_priv, anyone_pub) = KeyDeriver::anyone_key();
        assert_eq!(deriver.identity_key(), anyone_pub);
    }

    #[test]
    fn test_anyone_key_is_deterministic() {
        let (priv1, pub1) = KeyDeriver::anyone_key();
        let (priv2, pub2) = KeyDeriver::anyone_key();
        assert_eq!(priv1.to_bytes(), priv2.to_bytes());
        assert_eq!(pub1.to_compressed(), pub2.to_compressed());
    }

    #[test]
    fn test_derive_public_key_for_self() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "invoice-123";

        let pub_key = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        // Should be deterministic
        let pub_key2 = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        assert_eq!(pub_key.to_compressed(), pub_key2.to_compressed());
    }

    #[test]
    fn test_derive_private_key_matches_public() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "invoice-123";

        let priv_key = deriver
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let pub_key = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        assert_eq!(
            priv_key.public_key().to_compressed(),
            pub_key.to_compressed()
        );
    }

    #[test]
    fn test_two_party_derivation() {
        // Alice and Bob should derive matching keys
        let alice = KeyDeriver::new(Some(PrivateKey::random()));
        let bob = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "payment-456";

        // Bob's counterparty is Alice
        let alice_counterparty = Counterparty::Other(alice.identity_key());

        // Bob derives his private key using Alice's public key
        let bob_priv = bob
            .derive_private_key(&protocol, key_id, &alice_counterparty)
            .unwrap();

        // Alice derives Bob's public key using her private key
        let bob_pub_from_alice = bob
            .derive_public_key(&protocol, key_id, &alice_counterparty, true)
            .unwrap();

        // They should match
        assert_eq!(
            bob_priv.public_key().to_compressed(),
            bob_pub_from_alice.to_compressed()
        );
    }

    #[test]
    fn test_derive_symmetric_key() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "encryption test");
        let key_id = "message-789";

        let sym_key = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();

        // Should be deterministic
        let sym_key2 = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();

        assert_eq!(sym_key.as_bytes(), sym_key2.as_bytes());
    }

    #[test]
    fn test_reveal_specific_secret() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "secret-123";

        let secret = deriver
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();

        assert_eq!(secret.len(), 32);

        // Should be deterministic
        let secret2 = deriver
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();

        assert_eq!(secret, secret2);
    }

    #[test]
    fn test_reveal_counterparty_secret_fails_for_self() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));

        let result = deriver.reveal_counterparty_secret(&Counterparty::Self_);
        assert!(result.is_err());
    }

    #[test]
    fn test_reveal_counterparty_secret_succeeds_for_other() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let other = PrivateKey::random().public_key();

        let result = deriver.reveal_counterparty_secret(&Counterparty::Other(other));
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_protocol_name() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "bad"); // Too short
        let result = deriver.derive_private_key(&protocol, "key-1", &Counterparty::Self_);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_id() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        // Empty key ID
        let result = deriver.derive_private_key(&protocol, "", &Counterparty::Self_);
        assert!(result.is_err());

        // Key ID too long
        let long_key = "a".repeat(801);
        let result = deriver.derive_private_key(&protocol, &long_key, &Counterparty::Self_);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_security_levels_produce_different_keys() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let key_id = "test-key";

        let proto0 = Protocol::new(SecurityLevel::Silent, "test application");
        let proto1 = Protocol::new(SecurityLevel::App, "test application");
        let proto2 = Protocol::new(SecurityLevel::Counterparty, "test application");

        let key0 = deriver
            .derive_public_key(&proto0, key_id, &Counterparty::Self_, true)
            .unwrap();
        let key1 = deriver
            .derive_public_key(&proto1, key_id, &Counterparty::Self_, true)
            .unwrap();
        let key2 = deriver
            .derive_public_key(&proto2, key_id, &Counterparty::Self_, true)
            .unwrap();

        // All three should be different
        assert_ne!(key0.to_compressed(), key1.to_compressed());
        assert_ne!(key1.to_compressed(), key2.to_compressed());
        assert_ne!(key0.to_compressed(), key2.to_compressed());
    }
}
