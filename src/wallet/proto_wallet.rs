//! ProtoWallet - Foundational Cryptographic Wallet Operations.
//!
//! This module provides the [`ProtoWallet`] struct, a precursor to a full wallet
//! that is capable of performing all foundational cryptographic operations.
//!
//! # Overview
//!
//! ProtoWallet can:
//! - Derive keys using BRC-42
//! - Create and verify ECDSA signatures
//! - Encrypt and decrypt data (AES-GCM via derived symmetric keys)
//! - Create and verify HMACs
//! - Reveal key linkages for verification
//!
//! ProtoWallet does NOT:
//! - Create transactions
//! - Manage UTXOs
//! - Interact with the blockchain
//! - Manage certificates
//! - Store any persistent data
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::wallet::{ProtoWallet, Protocol, SecurityLevel, Counterparty};
//! use bsv_rs::primitives::PrivateKey;
//!
//! // Create a ProtoWallet from a root key
//! let wallet = ProtoWallet::new(Some(PrivateKey::random()));
//!
//! // Or create an "anyone" wallet for publicly derivable operations
//! let anyone_wallet = ProtoWallet::anyone();
//! ```

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::primitives::bsv::schnorr::Schnorr;
use crate::primitives::hash::sha256_hmac;
use crate::primitives::{sha256, PrivateKey, PublicKey, Signature};

use super::key_args::{
    CreateHmacArgs, CreateHmacResult, CreateSignatureArgs, CreateSignatureResult, DecryptArgs,
    DecryptResult, EncryptArgs, EncryptResult, GetPublicKeyArgs, GetPublicKeyResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult,
};
use super::key_deriver::{verify_hmac_tag, KeyDeriver, KeyDeriverApi};
use super::types::{Counterparty, Protocol, SecurityLevel};
use super::validation::crypto;
use super::CachedKeyDeriver;

// =============================================================================
// Argument and Result Types
// =============================================================================

/// Arguments for revealing counterparty key linkage.
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageArgs {
    /// The counterparty whose linkage to reveal.
    pub counterparty: PublicKey,
    /// The verifier who will receive the encrypted linkage.
    pub verifier: PublicKey,
}

/// Result of revealing counterparty key linkage.
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageResult {
    /// The prover's identity public key (hex).
    pub prover: String,
    /// The verifier's public key (hex).
    pub verifier: String,
    /// The counterparty's public key (hex).
    pub counterparty: String,
    /// The time of revelation (ISO 8601 timestamp).
    pub revelation_time: String,
    /// Encrypted linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Encrypted linkage proof.
    pub encrypted_linkage_proof: Vec<u8>,
}

/// Arguments for revealing specific key linkage.
#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageArgs {
    /// The counterparty.
    pub counterparty: Counterparty,
    /// The verifier who will receive the encrypted linkage.
    pub verifier: PublicKey,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
}

/// Result of revealing specific key linkage.
#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageResult {
    /// The prover's identity public key (hex).
    pub prover: String,
    /// The verifier's public key (hex).
    pub verifier: String,
    /// The counterparty's compressed public key (hex).
    pub counterparty: String,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// Encrypted linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Encrypted linkage proof.
    pub encrypted_linkage_proof: Vec<u8>,
    /// The proof type (0 = no proof provided).
    pub proof_type: u8,
}

// =============================================================================
// ProtoWallet
// =============================================================================

/// A foundational wallet capable of cryptographic operations.
///
/// ProtoWallet provides cryptographic operations without blockchain interaction.
/// It uses [`CachedKeyDeriver`] internally for efficient key derivation.
///
/// It has one keyring and asks no one. All nine cryptographic calls validate
/// `privileged` and `privileged_reason`, as the reference's argument validators
/// do (#415, #420); `seek_permission` is already a boolean. These fields do
/// not change key derivation. The linkage trait adapters validate privilege
/// before calling the inherent methods, whose arguments have no such fields.
///
/// # Example
///
/// ```rust
/// use bsv_rs::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs};
/// use bsv_rs::primitives::PrivateKey;
///
/// let wallet = ProtoWallet::new(Some(PrivateKey::random()));
///
/// // Create a signature
/// let result = wallet.create_signature(CreateSignatureArgs {
///     data: Some(b"Hello, BSV!".to_vec()),
///     hash_to_directly_sign: None,
///     protocol_id: Protocol::new(SecurityLevel::App, "my application"),
///     key_id: "signature-1".to_string(),
///     counterparty: None,
///     ..Default::default()
/// }).unwrap();
/// ```
#[derive(Clone)]
pub struct ProtoWallet {
    /// The internal key deriver (wrapped in Arc for clonability).
    key_deriver: Arc<CachedKeyDeriver>,
}

impl ProtoWallet {
    /// Creates a new ProtoWallet from a root private key.
    ///
    /// # Arguments
    ///
    /// * `root_key` - The root private key, or None to use the "anyone" key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::wallet::ProtoWallet;
    /// use bsv_rs::primitives::PrivateKey;
    ///
    /// let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    /// let anyone_wallet = ProtoWallet::new(None);
    /// ```
    pub fn new(root_key: Option<PrivateKey>) -> Self {
        Self {
            key_deriver: Arc::new(CachedKeyDeriver::new(root_key, None)),
        }
    }

    /// Creates a ProtoWallet with the special "anyone" key.
    ///
    /// The "anyone" key allows publicly derivable operations.
    pub fn anyone() -> Self {
        Self::new(None)
    }

    /// Returns a reference to the internal key deriver.
    pub fn key_deriver(&self) -> &CachedKeyDeriver {
        &self.key_deriver
    }

    /// Returns the identity public key.
    ///
    /// This is the root public key that identifies this wallet.
    pub fn identity_key(&self) -> PublicKey {
        self.key_deriver.identity_key()
    }

    /// Returns the identity public key as a hex string.
    pub fn identity_key_hex(&self) -> String {
        self.key_deriver.identity_key_hex()
    }

    /// Gets a public key based on the provided arguments.
    ///
    /// If `identity_key` is true, returns the root identity public key.
    /// Otherwise, derives a public key using the protocol, key ID, and counterparty.
    pub fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult> {
        let Some((protocol_id, key_id)) = crypto::get_public_key_args(&args)? else {
            return Ok(GetPublicKeyResult {
                public_key: self.identity_key_hex(),
            });
        };

        let counterparty = args.counterparty.as_ref().unwrap_or(&Counterparty::Self_);
        let for_self = args.for_self.unwrap_or(false);

        let public_key =
            self.key_deriver
                .derive_public_key(protocol_id, key_id, counterparty, for_self)?;

        Ok(GetPublicKeyResult {
            public_key: public_key.to_hex(),
        })
    }

    /// Encrypts plaintext using a derived symmetric key.
    ///
    /// The symmetric key is derived using the protocol, key ID, and counterparty.
    /// Uses AES-256-GCM encryption.
    pub fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult> {
        crypto::encrypt_args(&args)?;
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver.derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;

        let ciphertext = symmetric_key.encrypt(&args.plaintext)?;

        Ok(EncryptResult { ciphertext })
    }

    /// Decrypts ciphertext using a derived symmetric key.
    ///
    /// The symmetric key is derived using the protocol, key ID, and counterparty.
    pub fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult> {
        crypto::decrypt_args(&args)?;
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver.derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;

        let plaintext = symmetric_key.decrypt(&args.ciphertext)?;

        Ok(DecryptResult { plaintext })
    }

    /// Creates an HMAC of the data using a derived symmetric key.
    ///
    /// Uses HMAC-SHA256 with the derived symmetric key.
    pub fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult> {
        crypto::create_hmac_args(&args)?;
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver.derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;

        let hmac = sha256_hmac(symmetric_key.as_bytes(), &args.data);

        Ok(CreateHmacResult { hmac })
    }

    /// Verifies an HMAC using a derived symmetric key.
    ///
    /// Uses constant-time comparison to prevent timing attacks. Only the tag
    /// under the 32-byte key is accepted (BRC-56); a tag under the
    /// minimal-length key is [`Error::HmacMinimalLengthKey`], any other miss
    /// `WalletError("HMAC is not valid")`.
    pub fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult> {
        crypto::verify_hmac_args(&args)?;
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver.derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;

        // Constant time; a tag under the minimal-length key is refused by name
        verify_hmac_tag(&symmetric_key, &args.data, &args.hmac)?;
        Ok(VerifyHmacResult { valid: true })
    }

    /// Creates a signature using a derived private key.
    ///
    /// If `data` is provided, it will be SHA-256 hashed before signing.
    /// If `hash_to_directly_sign` is provided, it will be signed directly.
    /// Exactly one must be provided. Arguments are validated before hashing.
    pub fn create_signature(&self, args: CreateSignatureArgs) -> Result<CreateSignatureResult> {
        crypto::create_signature_args(&args)?;
        let hash = args
            .hash_to_directly_sign
            .unwrap_or_else(|| sha256(args.data.as_deref().unwrap_or_default()));

        // Default counterparty is 'anyone' for signatures
        let counterparty = args.counterparty.unwrap_or(Counterparty::Anyone);
        let private_key =
            self.key_deriver
                .derive_private_key(&args.protocol_id, &args.key_id, &counterparty)?;

        let signature = private_key.sign(&hash)?;

        Ok(CreateSignatureResult {
            signature: signature.to_der(),
        })
    }

    /// Verifies a signature using a derived public key.
    ///
    /// If `data` is provided, it will be SHA-256 hashed before verification.
    /// If `hash_to_directly_verify` is provided, it will be verified directly.
    /// Exactly one must be provided. Arguments are validated before hashing,
    /// key derivation or DER parsing, as the reference's ProtoWallet does.
    pub fn verify_signature(&self, args: VerifySignatureArgs) -> Result<VerifySignatureResult> {
        crypto::verify_signature_args(&args)?;
        let hash = args
            .hash_to_directly_verify
            .unwrap_or_else(|| sha256(args.data.as_deref().unwrap_or_default()));

        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let for_self = args.for_self.unwrap_or(false);
        let public_key = self.key_deriver.derive_public_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
            for_self,
        )?;

        let signature = Signature::from_der(&args.signature)?;
        let valid = public_key.verify(&hash, &signature);

        if !valid {
            return Err(Error::WalletError("Signature is not valid".to_string()));
        }

        Ok(VerifySignatureResult { valid: true })
    }

    /// Reveals counterparty key linkage with encrypted proof.
    ///
    /// This reveals the ECDH shared secret between this wallet and the counterparty,
    /// encrypted for the verifier. This allows the verifier to confirm the relationship
    /// exists without exposing the secret to anyone else.
    pub fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        crypto::reveal_counterparty_args(
            &args.counterparty.to_compressed(),
            &args.verifier.to_compressed(),
            None,
            None,
        )?;
        let identity_key = self.identity_key();

        // Get the shared secret point with the counterparty
        let linkage = self
            .key_deriver
            .reveal_counterparty_secret(&Counterparty::Other(args.counterparty.clone()))?;

        // Get current timestamp
        let revelation_time = get_iso_timestamp();

        // Encrypt linkage for verifier
        let encrypted_linkage = self.encrypt_for_verifier(
            linkage.to_compressed().to_vec(),
            &revelation_time,
            &args.verifier,
        )?;

        // Generate Schnorr ZK proof demonstrating knowledge of private key
        // and correct computation of the ECDH shared secret (linkage)
        let proof = Schnorr::generate_proof(
            self.key_deriver.root_key(),
            &identity_key,
            &args.counterparty,
            &linkage,
        )?;

        // Encode proof as R (33 bytes) || S' (33 bytes) || z (32 bytes) = 98 bytes
        let mut proof_bin = Vec::with_capacity(98);
        proof_bin.extend_from_slice(&proof.r.to_compressed());
        proof_bin.extend_from_slice(&proof.s_prime.to_compressed());
        proof_bin.extend_from_slice(&proof.z.to_bytes_be(32));

        let encrypted_linkage_proof =
            self.encrypt_for_verifier(proof_bin, &revelation_time, &args.verifier)?;

        Ok(RevealCounterpartyKeyLinkageResult {
            prover: identity_key.to_hex(),
            verifier: args.verifier.to_hex(),
            counterparty: args.counterparty.to_hex(),
            revelation_time,
            encrypted_linkage,
            encrypted_linkage_proof,
        })
    }

    /// Encrypts a linkage revelation for the verifier under the counterparty
    /// linkage revelation protocol, keyed by the revelation time.
    fn encrypt_for_verifier(
        &self,
        plaintext: Vec<u8>,
        revelation_time: &str,
        verifier: &PublicKey,
    ) -> Result<Vec<u8>> {
        Ok(self
            .encrypt(EncryptArgs {
                plaintext,
                protocol_id: Protocol::new(
                    SecurityLevel::Counterparty,
                    "counterparty linkage revelation",
                ),
                key_id: revelation_time.to_string(),
                counterparty: Some(Counterparty::Other(verifier.clone())),
                ..Default::default()
            })?
            .ciphertext)
    }

    /// Reveals specific key linkage for a protocol and key ID.
    ///
    /// This reveals the specific HMAC linkage for a protocol/key combination,
    /// encrypted for the verifier. The result identifies the counterparty by
    /// compressed public-key hex, including for `Self_` and `Anyone`.
    pub fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        crypto::reveal_specific_args(
            Some(&args.counterparty),
            &args.verifier.to_compressed(),
            &args.protocol_id,
            &args.key_id,
            None,
            None,
        )?;
        let identity_key = self.identity_key();

        // Get the specific secret
        let linkage = self.key_deriver.reveal_specific_secret(
            &args.counterparty,
            &args.protocol_id,
            &args.key_id,
        )?;

        // Build protocol name for encryption
        let protocol_name = format!(
            "specific linkage revelation {} {}",
            args.protocol_id.security_level.as_u8(),
            args.protocol_id.protocol_name
        );

        // Encrypt linkage for verifier
        let protocol = Protocol::new(SecurityLevel::Counterparty, &protocol_name);
        let key = self.key_deriver.derive_symmetric_key(
            &protocol,
            &args.key_id,
            &Counterparty::Other(args.verifier.clone()),
        )?;
        // Internal derivation permits the 430-byte revelation protocol. The
        // reference calls deriveSymmetricKey directly, not public encrypt.
        let encrypted_linkage = key.encrypt(&linkage)?;

        // Proof type 0: no proof provided
        let encrypted_linkage_proof = key.encrypt(&[0])?;

        // Format counterparty for result
        let counterparty_str = match &args.counterparty {
            Counterparty::Self_ => identity_key.to_hex(),
            Counterparty::Anyone => KeyDeriver::anyone_key().1.to_hex(),
            Counterparty::Other(pk) => pk.to_hex(),
        };

        Ok(RevealSpecificKeyLinkageResult {
            prover: identity_key.to_hex(),
            verifier: args.verifier.to_hex(),
            counterparty: counterparty_str,
            protocol_id: args.protocol_id,
            key_id: args.key_id,
            encrypted_linkage,
            encrypted_linkage_proof,
            proof_type: 0,
        })
    }
}

impl std::fmt::Debug for ProtoWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtoWallet")
            .field("identity_key", &self.identity_key_hex())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Gets the current time as an ISO 8601 timestamp.
fn get_iso_timestamp() -> String {
    // Simple timestamp without chrono dependency
    // Format: "2024-01-01T00:00:00.000Z"
    let now = crate::util::time::duration_since_unix_epoch();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Calculate date/time components
    const SECS_PER_DAY: u64 = 86400;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_MIN: u64 = 60;

    let days = secs / SECS_PER_DAY;
    let time_secs = secs % SECS_PER_DAY;
    let hours = time_secs / SECS_PER_HOUR;
    let mins = (time_secs % SECS_PER_HOUR) / SECS_PER_MIN;
    let secs = time_secs % SECS_PER_MIN;

    // Simple date calculation (approximate, but good enough for timestamps)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, mins, secs, millis
    )
}

/// Converts days since Unix epoch to year, month, day.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calculation - not perfectly accurate for all edge cases
    // but good enough for timestamp purposes
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in month_days.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    (year, month, remaining_days + 1)
}

/// Checks if a year is a leap year.
#[allow(unknown_lints, clippy::manual_is_multiple_of)]
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

mod interface;

#[cfg(test)]
mod tests;
