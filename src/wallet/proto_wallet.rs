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
//! use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, Counterparty};
//! use bsv_sdk::primitives::PrivateKey;
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

use super::key_deriver::KeyDeriverApi;
use super::types::{Counterparty, Protocol, SecurityLevel};
use super::CachedKeyDeriver;

// =============================================================================
// Argument and Result Types
// =============================================================================

/// Arguments for getting a public key.
#[derive(Debug, Clone)]
pub struct GetPublicKeyArgs {
    /// If true, return the identity (root) public key.
    pub identity_key: bool,
    /// The protocol identifier (required if identity_key is false).
    pub protocol_id: Option<Protocol>,
    /// The key identifier (required if identity_key is false).
    pub key_id: Option<String>,
    /// The counterparty for derivation.
    pub counterparty: Option<Counterparty>,
    /// If true, derive the key for self; otherwise for counterparty.
    pub for_self: Option<bool>,
}

/// Result of getting a public key.
#[derive(Debug, Clone)]
pub struct GetPublicKeyResult {
    /// The public key as a hex string.
    pub public_key: String,
}

/// Arguments for encryption.
#[derive(Debug, Clone)]
pub struct EncryptArgs {
    /// The plaintext data to encrypt.
    pub plaintext: Vec<u8>,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
}

/// Result of encryption.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// The encrypted ciphertext (IV + ciphertext + auth tag).
    pub ciphertext: Vec<u8>,
}

/// Arguments for decryption.
#[derive(Debug, Clone)]
pub struct DecryptArgs {
    /// The ciphertext to decrypt (IV + ciphertext + auth tag).
    pub ciphertext: Vec<u8>,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
}

/// Result of decryption.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
}

/// Arguments for creating an HMAC.
#[derive(Debug, Clone)]
pub struct CreateHmacArgs {
    /// The data to create HMAC for.
    pub data: Vec<u8>,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
}

/// Result of creating an HMAC.
#[derive(Debug, Clone)]
pub struct CreateHmacResult {
    /// The HMAC (32 bytes).
    pub hmac: [u8; 32],
}

/// Arguments for verifying an HMAC.
#[derive(Debug, Clone)]
pub struct VerifyHmacArgs {
    /// The data that was HMACed.
    pub data: Vec<u8>,
    /// The HMAC to verify.
    pub hmac: [u8; 32],
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
}

/// Result of verifying an HMAC.
#[derive(Debug, Clone)]
pub struct VerifyHmacResult {
    /// True if the HMAC is valid.
    pub valid: bool,
}

/// Arguments for creating a signature.
#[derive(Debug, Clone)]
pub struct CreateSignatureArgs {
    /// The data to sign (will be SHA-256 hashed if hash_to_directly_sign is None).
    pub data: Option<Vec<u8>>,
    /// A pre-computed hash to sign directly.
    pub hash_to_directly_sign: Option<[u8; 32]>,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
}

/// Result of creating a signature.
#[derive(Debug, Clone)]
pub struct CreateSignatureResult {
    /// The DER-encoded signature.
    pub signature: Vec<u8>,
}

/// Arguments for verifying a signature.
#[derive(Debug, Clone)]
pub struct VerifySignatureArgs {
    /// The data that was signed.
    pub data: Option<Vec<u8>>,
    /// The pre-computed hash that was signed.
    pub hash_to_directly_verify: Option<[u8; 32]>,
    /// The DER-encoded signature to verify.
    pub signature: Vec<u8>,
    /// The protocol identifier.
    pub protocol_id: Protocol,
    /// The key identifier.
    pub key_id: String,
    /// The counterparty for key derivation.
    pub counterparty: Option<Counterparty>,
    /// If true, verify with own derived public key; otherwise with counterparty's.
    pub for_self: Option<bool>,
}

/// Result of verifying a signature.
#[derive(Debug, Clone)]
pub struct VerifySignatureResult {
    /// True if the signature is valid.
    pub valid: bool,
}

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
    /// The counterparty (hex or "self"/"anyone").
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
/// # Example
///
/// ```rust
/// use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs};
/// use bsv_sdk::primitives::PrivateKey;
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
    /// use bsv_sdk::wallet::ProtoWallet;
    /// use bsv_sdk::primitives::PrivateKey;
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
        &*self.key_deriver
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
        if args.identity_key {
            return Ok(GetPublicKeyResult {
                public_key: self.identity_key_hex(),
            });
        }

        let protocol_id = args.protocol_id.ok_or_else(|| {
            Error::WalletError("protocolID is required when identityKey is false".to_string())
        })?;

        let key_id = args.key_id.ok_or_else(|| {
            Error::WalletError("keyID is required when identityKey is false".to_string())
        })?;

        if key_id.is_empty() {
            return Err(Error::WalletError(
                "keyID is required when identityKey is false".to_string(),
            ));
        }

        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let for_self = args.for_self.unwrap_or(false);

        let public_key =
            self.key_deriver
                .derive_public_key(&protocol_id, &key_id, &counterparty, for_self)?;

        Ok(GetPublicKeyResult {
            public_key: public_key.to_hex(),
        })
    }

    /// Encrypts plaintext using a derived symmetric key.
    ///
    /// The symmetric key is derived using the protocol, key ID, and counterparty.
    /// Uses AES-256-GCM encryption.
    pub fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult> {
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
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult> {
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver.derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;

        let computed = sha256_hmac(symmetric_key.as_bytes(), &args.data);

        // Constant-time comparison
        if !constant_time_eq(&computed, &args.hmac) {
            return Err(Error::WalletError("HMAC is not valid".to_string()));
        }

        Ok(VerifyHmacResult { valid: true })
    }

    /// Creates a signature using a derived private key.
    ///
    /// If `data` is provided, it will be SHA-256 hashed before signing.
    /// If `hash_to_directly_sign` is provided, it will be signed directly.
    /// At least one must be provided.
    pub fn create_signature(&self, args: CreateSignatureArgs) -> Result<CreateSignatureResult> {
        if args.data.is_none() && args.hash_to_directly_sign.is_none() {
            return Err(Error::WalletError(
                "data or hashToDirectlySign must be provided".to_string(),
            ));
        }

        let hash = args
            .hash_to_directly_sign
            .unwrap_or_else(|| sha256(args.data.as_ref().unwrap()));

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
    /// At least one must be provided.
    pub fn verify_signature(&self, args: VerifySignatureArgs) -> Result<VerifySignatureResult> {
        if args.data.is_none() && args.hash_to_directly_verify.is_none() {
            return Err(Error::WalletError(
                "data or hashToDirectlyVerify must be provided".to_string(),
            ));
        }

        let hash = args
            .hash_to_directly_verify
            .unwrap_or_else(|| sha256(args.data.as_ref().unwrap()));

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
        let identity_key = self.identity_key();

        // Get the shared secret point with the counterparty
        let linkage = self
            .key_deriver
            .reveal_counterparty_secret(&Counterparty::Other(args.counterparty.clone()))?;

        // Get current timestamp
        let revelation_time = get_iso_timestamp();

        // Encrypt linkage for verifier
        let encrypted_linkage = self
            .encrypt(EncryptArgs {
                plaintext: linkage.to_compressed().to_vec(),
                protocol_id: Protocol::new(
                    SecurityLevel::Counterparty,
                    "counterparty linkage revelation",
                ),
                key_id: revelation_time.clone(),
                counterparty: Some(Counterparty::Other(args.verifier.clone())),
            })?
            .ciphertext;

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

        let encrypted_linkage_proof = self
            .encrypt(EncryptArgs {
                plaintext: proof_bin,
                protocol_id: Protocol::new(
                    SecurityLevel::Counterparty,
                    "counterparty linkage revelation",
                ),
                key_id: revelation_time.clone(),
                counterparty: Some(Counterparty::Other(args.verifier.clone())),
            })?
            .ciphertext;

        Ok(RevealCounterpartyKeyLinkageResult {
            prover: identity_key.to_hex(),
            verifier: args.verifier.to_hex(),
            counterparty: args.counterparty.to_hex(),
            revelation_time,
            encrypted_linkage,
            encrypted_linkage_proof,
        })
    }

    /// Reveals specific key linkage for a protocol and key ID.
    ///
    /// This reveals the specific HMAC linkage for a protocol/key combination,
    /// encrypted for the verifier.
    pub fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult> {
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
        let encrypted_linkage = self
            .encrypt(EncryptArgs {
                plaintext: linkage,
                protocol_id: Protocol::new(SecurityLevel::Counterparty, &protocol_name),
                key_id: args.key_id.clone(),
                counterparty: Some(Counterparty::Other(args.verifier.clone())),
            })?
            .ciphertext;

        // Proof type 0: no proof provided
        let encrypted_linkage_proof = self
            .encrypt(EncryptArgs {
                plaintext: vec![0],
                protocol_id: Protocol::new(SecurityLevel::Counterparty, &protocol_name),
                key_id: args.key_id.clone(),
                counterparty: Some(Counterparty::Other(args.verifier.clone())),
            })?
            .ciphertext;

        // Format counterparty for result
        let counterparty_str = match &args.counterparty {
            Counterparty::Self_ => "self".to_string(),
            Counterparty::Anyone => "anyone".to_string(),
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

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Gets the current time as an ISO 8601 timestamp.
fn get_iso_timestamp() -> String {
    // Simple timestamp without chrono dependency
    // Format: "2024-01-01T00:00:00.000Z"
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
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

// =============================================================================
// WalletInterface Implementation
// =============================================================================

use super::interface::{
    RevealCounterpartyKeyLinkageArgs as InterfaceRevealCounterpartyArgs,
    RevealSpecificKeyLinkageArgs as InterfaceRevealSpecificArgs, WalletInterface,
};
use super::types::{
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult as TypesRevealCounterpartyResult,
    RevealSpecificKeyLinkageResult as TypesRevealSpecificResult,
};
use super::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs,
    DiscoverCertificatesResult, GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult,
    GetVersionResult, InternalizeActionArgs, InternalizeActionResult, ListActionsArgs,
    ListActionsResult, ListCertificatesArgs, ListCertificatesResult, ListOutputsArgs,
    ListOutputsResult, Network, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, SignActionArgs, SignActionResult, WalletCertificate,
};
use async_trait::async_trait;

#[async_trait]
impl WalletInterface for ProtoWallet {
    // =========================================================================
    // Key Operations (all supported)
    // =========================================================================

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        _originator: &str,
    ) -> Result<GetPublicKeyResult> {
        self.get_public_key(args)
    }

    async fn encrypt(&self, args: EncryptArgs, _originator: &str) -> Result<EncryptResult> {
        self.encrypt(args)
    }

    async fn decrypt(&self, args: DecryptArgs, _originator: &str) -> Result<DecryptResult> {
        self.decrypt(args)
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        _originator: &str,
    ) -> Result<CreateHmacResult> {
        self.create_hmac(args)
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        _originator: &str,
    ) -> Result<VerifyHmacResult> {
        self.verify_hmac(args)
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        _originator: &str,
    ) -> Result<CreateSignatureResult> {
        self.create_signature(args)
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        _originator: &str,
    ) -> Result<VerifySignatureResult> {
        self.verify_signature(args)
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: InterfaceRevealCounterpartyArgs,
        _originator: &str,
    ) -> Result<TypesRevealCounterpartyResult> {
        let result = self.reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs {
            counterparty: args.counterparty.clone(),
            verifier: args.verifier.clone(),
        })?;

        // Parse the hex strings back to PublicKeys
        let prover = PublicKey::from_hex(&result.prover)?;
        let counterparty_key = PublicKey::from_hex(&result.counterparty)?;

        Ok(TypesRevealCounterpartyResult {
            linkage: KeyLinkageResult {
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
                prover,
                verifier: args.verifier,
                counterparty: counterparty_key,
            },
            revelation_time: result.revelation_time,
        })
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: InterfaceRevealSpecificArgs,
        _originator: &str,
    ) -> Result<TypesRevealSpecificResult> {
        let result = self.reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
            counterparty: args.counterparty.clone(),
            verifier: args.verifier.clone(),
            protocol_id: args.protocol_id.clone(),
            key_id: args.key_id.clone(),
        })?;

        // Parse the hex strings back to PublicKeys
        let prover = PublicKey::from_hex(&result.prover)?;
        // Counterparty may be "self" or "anyone" - handle gracefully
        let counterparty_key = match args.counterparty {
            Counterparty::Self_ | Counterparty::Anyone => self.identity_key(),
            Counterparty::Other(ref pk) => pk.clone(),
        };

        Ok(TypesRevealSpecificResult {
            linkage: KeyLinkageResult {
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
                prover,
                verifier: args.verifier,
                counterparty: counterparty_key,
            },
            protocol: result.protocol_id,
            key_id: result.key_id,
            proof_type: result.proof_type,
        })
    }

    // =========================================================================
    // Action Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: &str,
    ) -> Result<CreateActionResult> {
        Err(Error::WalletError(
            "createAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _originator: &str,
    ) -> Result<SignActionResult> {
        Err(Error::WalletError(
            "signAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: &str,
    ) -> Result<AbortActionResult> {
        Err(Error::WalletError(
            "abortAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: &str,
    ) -> Result<ListActionsResult> {
        Err(Error::WalletError(
            "listActions requires a full wallet implementation with transaction history"
                .to_string(),
        ))
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: &str,
    ) -> Result<InternalizeActionResult> {
        Err(Error::WalletError(
            "internalizeAction requires a full wallet implementation with UTXO management"
                .to_string(),
        ))
    }

    // =========================================================================
    // Output Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: &str,
    ) -> Result<ListOutputsResult> {
        Err(Error::WalletError(
            "listOutputs requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: &str,
    ) -> Result<RelinquishOutputResult> {
        Err(Error::WalletError(
            "relinquishOutput requires a full wallet implementation with UTXO management"
                .to_string(),
        ))
    }

    // =========================================================================
    // Certificate Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: &str,
    ) -> Result<WalletCertificate> {
        Err(Error::WalletError(
            "acquireCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: &str,
    ) -> Result<ListCertificatesResult> {
        Err(Error::WalletError(
            "listCertificates requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: &str,
    ) -> Result<ProveCertificateResult> {
        Err(Error::WalletError(
            "proveCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: &str,
    ) -> Result<RelinquishCertificateResult> {
        Err(Error::WalletError(
            "relinquishCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    // =========================================================================
    // Discovery Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: &str,
    ) -> Result<DiscoverCertificatesResult> {
        Err(Error::WalletError(
            "discoverByIdentityKey requires a full wallet implementation with certificate discovery"
                .to_string(),
        ))
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: &str,
    ) -> Result<DiscoverCertificatesResult> {
        Err(Error::WalletError(
            "discoverByAttributes requires a full wallet implementation with certificate discovery"
                .to_string(),
        ))
    }

    // =========================================================================
    // Chain/Status Operations (partial support)
    // =========================================================================

    async fn is_authenticated(&self, _originator: &str) -> Result<AuthenticatedResult> {
        // ProtoWallet is always authenticated (it has a key)
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(&self, _originator: &str) -> Result<AuthenticatedResult> {
        // ProtoWallet is always authenticated
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _originator: &str) -> Result<GetHeightResult> {
        // ProtoWallet doesn't track chain state
        // Return 0 to indicate unknown
        Ok(GetHeightResult { height: 0 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _originator: &str,
    ) -> Result<GetHeaderResult> {
        Err(Error::WalletError(
            "getHeaderForHeight requires a full wallet implementation with block header storage"
                .to_string(),
        ))
    }

    async fn get_network(&self, _originator: &str) -> Result<GetNetworkResult> {
        // ProtoWallet defaults to mainnet
        Ok(GetNetworkResult {
            network: Network::Mainnet,
        })
    }

    async fn get_version(&self, _originator: &str) -> Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: "bsv-sdk-0.1.0".to_string(),
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_wallet_creation() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        assert!(!wallet.identity_key_hex().is_empty());
    }

    #[test]
    fn test_proto_wallet_anyone() {
        let wallet = ProtoWallet::anyone();
        let wallet2 = ProtoWallet::anyone();
        // Anyone wallets should have the same identity key
        assert_eq!(wallet.identity_key_hex(), wallet2.identity_key_hex());
    }

    #[test]
    fn test_get_public_key_identity() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let result = wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                for_self: None,
            })
            .unwrap();
        assert_eq!(result.public_key, wallet.identity_key_hex());
    }

    #[test]
    fn test_get_public_key_derived() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        let result = wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol.clone()),
                key_id: Some("key-1".to_string()),
                counterparty: Some(Counterparty::Self_),
                for_self: Some(true),
            })
            .unwrap();

        // Should be different from identity key
        assert_ne!(result.public_key, wallet.identity_key_hex());

        // Should be deterministic
        let result2 = wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol),
                key_id: Some("key-1".to_string()),
                counterparty: Some(Counterparty::Self_),
                for_self: Some(true),
            })
            .unwrap();
        assert_eq!(result.public_key, result2.public_key);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "encryption test");
        let plaintext = b"Hello, ProtoWallet!".to_vec();

        let encrypted = wallet
            .encrypt(EncryptArgs {
                plaintext: plaintext.clone(),
                protocol_id: protocol.clone(),
                key_id: "enc-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let decrypted = wallet
            .decrypt(DecryptArgs {
                ciphertext: encrypted.ciphertext,
                protocol_id: protocol,
                key_id: "enc-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_create_verify_hmac() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "hmac test");
        let data = b"HMAC me!".to_vec();

        let created = wallet
            .create_hmac(CreateHmacArgs {
                data: data.clone(),
                protocol_id: protocol.clone(),
                key_id: "hmac-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        // Verify should pass
        let verified = wallet
            .verify_hmac(VerifyHmacArgs {
                data: data.clone(),
                hmac: created.hmac,
                protocol_id: protocol.clone(),
                key_id: "hmac-1".to_string(),
                counterparty: None,
            })
            .unwrap();
        assert!(verified.valid);

        // Verify with wrong data should fail
        let bad_result = wallet.verify_hmac(VerifyHmacArgs {
            data: b"wrong data".to_vec(),
            hmac: created.hmac,
            protocol_id: protocol,
            key_id: "hmac-1".to_string(),
            counterparty: None,
        });
        assert!(bad_result.is_err());
    }

    #[test]
    fn test_create_verify_signature() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "signature test");
        let data = b"Sign me!".to_vec();

        let signed = wallet
            .create_signature(CreateSignatureArgs {
                data: Some(data.clone()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: "sig-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        // Verify should pass (note: for_self must be true to verify our own signature)
        let verified = wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data.clone()),
                hash_to_directly_verify: None,
                signature: signed.signature.clone(),
                protocol_id: protocol.clone(),
                key_id: "sig-1".to_string(),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
            })
            .unwrap();
        assert!(verified.valid);

        // Verify with wrong data should fail
        let bad_result = wallet.verify_signature(VerifySignatureArgs {
            data: Some(b"wrong data".to_vec()),
            hash_to_directly_verify: None,
            signature: signed.signature,
            protocol_id: protocol,
            key_id: "sig-1".to_string(),
            counterparty: Some(Counterparty::Anyone),
            for_self: Some(true),
        });
        assert!(bad_result.is_err());
    }

    #[test]
    fn test_signature_with_hash() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "hash signature test");
        let hash = sha256(b"prehashed data");

        let signed = wallet
            .create_signature(CreateSignatureArgs {
                data: None,
                hash_to_directly_sign: Some(hash),
                protocol_id: protocol.clone(),
                key_id: "hash-sig-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let verified = wallet
            .verify_signature(VerifySignatureArgs {
                data: None,
                hash_to_directly_verify: Some(hash),
                signature: signed.signature,
                protocol_id: protocol,
                key_id: "hash-sig-1".to_string(),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
            })
            .unwrap();
        assert!(verified.valid);
    }

    #[test]
    fn test_reveal_specific_key_linkage() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let verifier = PrivateKey::random().public_key();
        let protocol = Protocol::new(SecurityLevel::App, "linkage test");

        let result = wallet
            .reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
                counterparty: Counterparty::Self_,
                verifier: verifier.clone(),
                protocol_id: protocol.clone(),
                key_id: "linkage-1".to_string(),
            })
            .unwrap();

        assert_eq!(result.prover, wallet.identity_key_hex());
        assert_eq!(result.verifier, verifier.to_hex());
        assert_eq!(result.counterparty, "self");
        assert_eq!(result.proof_type, 0);
        assert!(!result.encrypted_linkage.is_empty());
    }

    #[test]
    fn test_reveal_counterparty_key_linkage() {
        let prover_key = PrivateKey::random();
        let wallet = ProtoWallet::new(Some(prover_key.clone()));
        let counterparty = PrivateKey::random().public_key();
        let verifier_key = PrivateKey::random();
        let verifier = verifier_key.public_key();

        let result = wallet
            .reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs {
                counterparty: counterparty.clone(),
                verifier: verifier.clone(),
            })
            .unwrap();

        assert_eq!(result.prover, wallet.identity_key_hex());
        assert_eq!(result.verifier, verifier.to_hex());
        assert_eq!(result.counterparty, counterparty.to_hex());
        assert!(!result.revelation_time.is_empty());
        assert!(!result.encrypted_linkage.is_empty());
        assert!(!result.encrypted_linkage_proof.is_empty());

        // Verifier decrypts and validates the Schnorr proof
        let verifier_wallet = ProtoWallet::new(Some(verifier_key));
        let protocol = Protocol::new(
            SecurityLevel::Counterparty,
            "counterparty linkage revelation",
        );

        // Decrypt the linkage
        let decrypted_linkage = verifier_wallet
            .decrypt(DecryptArgs {
                ciphertext: result.encrypted_linkage,
                protocol_id: protocol.clone(),
                key_id: result.revelation_time.clone(),
                counterparty: Some(Counterparty::Other(wallet.identity_key())),
            })
            .unwrap();
        let linkage_point = PublicKey::from_bytes(&decrypted_linkage.plaintext).unwrap();

        // Decrypt the proof
        let decrypted_proof = verifier_wallet
            .decrypt(DecryptArgs {
                ciphertext: result.encrypted_linkage_proof,
                protocol_id: protocol,
                key_id: result.revelation_time,
                counterparty: Some(Counterparty::Other(wallet.identity_key())),
            })
            .unwrap();

        // Parse the 98-byte proof: R (33) || S' (33) || z (32)
        let proof_bytes = &decrypted_proof.plaintext;
        assert_eq!(proof_bytes.len(), 98);

        use crate::primitives::bsv::schnorr::{Schnorr, SchnorrProof};
        use crate::primitives::BigNumber;

        let r = PublicKey::from_bytes(&proof_bytes[0..33]).unwrap();
        let s_prime = PublicKey::from_bytes(&proof_bytes[33..66]).unwrap();
        let z = BigNumber::from_bytes_be(&proof_bytes[66..98]);

        let proof = SchnorrProof { r, s_prime, z };

        // Verify the Schnorr proof
        assert!(Schnorr::verify_proof(
            &wallet.identity_key(),
            &counterparty,
            &linkage_point,
            &proof,
        ));
    }

    #[test]
    fn test_two_party_encryption() {
        let alice = ProtoWallet::new(Some(PrivateKey::random()));
        let bob = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "two party encryption");
        let message = b"Secret message from Alice to Bob".to_vec();

        // Alice encrypts for Bob
        let encrypted = alice
            .encrypt(EncryptArgs {
                plaintext: message.clone(),
                protocol_id: protocol.clone(),
                key_id: "message-1".to_string(),
                counterparty: Some(Counterparty::Other(bob.identity_key())),
            })
            .unwrap();

        // Bob decrypts using Alice as counterparty
        let decrypted = bob
            .decrypt(DecryptArgs {
                ciphertext: encrypted.ciphertext,
                protocol_id: protocol,
                key_id: "message-1".to_string(),
                counterparty: Some(Counterparty::Other(alice.identity_key())),
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, message);
    }

    #[test]
    fn test_iso_timestamp() {
        let timestamp = get_iso_timestamp();
        // Should be in format "YYYY-MM-DDTHH:MM:SS.mmmZ"
        assert!(timestamp.len() == 24, "Timestamp: {}", timestamp);
        assert!(timestamp.ends_with('Z'));
        assert!(timestamp.contains('T'));
    }
}
