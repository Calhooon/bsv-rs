//! Error types for the BSV SDK.

use thiserror::Error;

/// Main error type for the BSV SDK.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ===================
    // Primitives errors
    // ===================
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

    /// Invalid UTF-8 sequence.
    #[error("invalid UTF-8 sequence: {0}")]
    InvalidUtf8(String),

    /// Reader underflow (not enough bytes to read).
    #[error("reader underflow: need {needed} bytes, only {available} available")]
    ReaderUnderflow { needed: usize, available: usize },

    /// Invalid checksum.
    #[error("invalid checksum")]
    InvalidChecksum,

    // ===================
    // Script errors (Phase S1+)
    // ===================
    /// Script parse error.
    #[cfg(feature = "script")]
    #[error("script parse error: {0}")]
    ScriptParseError(String),

    /// Script execution error.
    #[cfg(feature = "script")]
    #[error("script execution error: {0}")]
    ScriptExecutionError(String),

    /// Invalid opcode.
    #[cfg(feature = "script")]
    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    /// Disabled opcode.
    #[cfg(feature = "script")]
    #[error("disabled opcode: 0x{0:02x}")]
    DisabledOpcode(u8),

    /// Stack underflow.
    #[cfg(feature = "script")]
    #[error("stack underflow")]
    StackUnderflow,

    /// Stack overflow.
    #[cfg(feature = "script")]
    #[error("stack overflow")]
    StackOverflow,

    // ===================
    // Transaction errors
    // ===================
    /// Transaction error.
    #[cfg(feature = "transaction")]
    #[error("transaction error: {0}")]
    TransactionError(String),

    /// MerklePath error.
    #[cfg(feature = "transaction")]
    #[error("merkle path error: {0}")]
    MerklePathError(String),

    /// BEEF format error.
    #[cfg(feature = "transaction")]
    #[error("BEEF error: {0}")]
    BeefError(String),

    /// Fee model error.
    #[cfg(feature = "transaction")]
    #[error("fee model error: {0}")]
    FeeModelError(String),

    // ===================
    // Wallet errors
    // ===================
    /// General wallet error.
    #[cfg(feature = "wallet")]
    #[error("wallet error: {0}")]
    WalletError(String),

    /// Key derivation error.
    #[cfg(feature = "wallet")]
    #[error("key derivation error: {0}")]
    KeyDerivationError(String),

    /// Protocol validation error.
    #[cfg(feature = "wallet")]
    #[error("protocol validation error: {0}")]
    ProtocolValidationError(String),

    /// Invalid counterparty.
    #[cfg(feature = "wallet")]
    #[error("invalid counterparty: {0}")]
    InvalidCounterparty(String),
}

/// Result type alias for BSV SDK operations.
pub type Result<T> = std::result::Result<T, Error>;
