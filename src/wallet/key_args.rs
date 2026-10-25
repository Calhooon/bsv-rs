//! The arguments and results of the seven key-related calls (getPublicKey,
//! encrypt, decrypt, createHmac, verifyHmac, createSignature, verifySignature),
//! moved out of `proto_wallet.rs` unchanged.

use super::types::{Counterparty, Protocol};

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
