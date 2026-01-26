//! Error types for the BSV primitives library.

use thiserror::Error;

/// The main error type for the BSV primitives library.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid key length for cryptographic operations.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid data length for cryptographic operations.
    #[error("invalid data length: expected {expected}, got {actual}")]
    InvalidDataLength { expected: usize, actual: usize },

    /// Invalid hex string.
    #[error("invalid hex string: {0}")]
    InvalidHex(String),

    /// Invalid base58 string.
    #[error("invalid base58 string: {0}")]
    InvalidBase58(String),

    /// Invalid base64 string.
    #[error("invalid base64 string: {0}")]
    InvalidBase64(String),

    /// Cryptographic operation failed.
    #[error("cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Invalid signature.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Point at infinity (invalid for most operations).
    #[error("point at infinity")]
    PointAtInfinity,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Invalid nonce.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid tag (for authenticated encryption).
    #[error("invalid authentication tag")]
    InvalidTag,
}

/// A specialized Result type for BSV primitives operations.
pub type Result<T> = std::result::Result<T, Error>;
