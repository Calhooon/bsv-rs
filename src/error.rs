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

    /// BIP-276 encoding/decoding error.
    #[cfg(feature = "script")]
    #[error("BIP-276 error: {0}")]
    Bip276Error(String),

    /// Invalid address.
    #[cfg(feature = "script")]
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid address length.
    #[cfg(feature = "script")]
    #[error("invalid address length for '{0}'")]
    InvalidAddressLength(String),

    /// Unsupported address type.
    #[cfg(feature = "script")]
    #[error("address not supported {0}")]
    UnsupportedAddress(String),

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

    // ===================
    // Messages errors
    // ===================
    /// Message version mismatch.
    #[cfg(feature = "messages")]
    #[error("message version mismatch: expected {expected}, got {actual}")]
    MessageVersionMismatch { expected: String, actual: String },

    /// General message error.
    #[cfg(feature = "messages")]
    #[error("message error: {0}")]
    MessageError(String),

    /// Message recipient mismatch.
    #[cfg(feature = "messages")]
    #[error("message recipient mismatch: expected {expected}, got {actual}")]
    MessageRecipientMismatch { expected: String, actual: String },

    // ===================
    // Compat errors
    // ===================
    /// Invalid mnemonic phrase.
    #[cfg(feature = "compat")]
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid entropy length for mnemonic generation.
    #[cfg(feature = "compat")]
    #[error("invalid entropy length: expected {expected}, got {actual}")]
    InvalidEntropyLength { expected: String, actual: usize },

    /// Invalid word in mnemonic phrase.
    #[cfg(feature = "compat")]
    #[error("invalid word in mnemonic: {0}")]
    InvalidMnemonicWord(String),

    /// Invalid extended key.
    #[cfg(feature = "compat")]
    #[error("invalid extended key: {0}")]
    InvalidExtendedKey(String),

    /// Cannot derive hardened child from public key.
    #[cfg(feature = "compat")]
    #[error("cannot derive hardened child from public key")]
    HardenedFromPublic,

    /// Invalid derivation path.
    #[cfg(feature = "compat")]
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// ECIES decryption failed.
    #[cfg(feature = "compat")]
    #[error("ECIES decryption failed: {0}")]
    EciesDecryptionFailed(String),

    /// ECIES HMAC verification failed.
    #[cfg(feature = "compat")]
    #[error("ECIES HMAC verification failed")]
    EciesHmacMismatch,

    // ===================
    // Auth errors
    // ===================
    /// General authentication error.
    #[cfg(feature = "auth")]
    #[error("authentication error: {0}")]
    AuthError(String),

    /// Session not found.
    #[cfg(feature = "auth")]
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Certificate validation failed.
    #[cfg(feature = "auth")]
    #[error("certificate validation failed: {0}")]
    CertificateValidationError(String),

    /// Transport error.
    #[cfg(feature = "auth")]
    #[error("transport error: {0}")]
    TransportError(String),

    // ===================
    // Overlay errors
    // ===================
    /// General overlay error.
    #[cfg(feature = "overlay")]
    #[error("overlay error: {0}")]
    OverlayError(String),

    /// No hosts found for service.
    #[cfg(feature = "overlay")]
    #[error("no hosts found for service: {0}")]
    NoHostsFound(String),

    /// Broadcast to overlay failed.
    #[cfg(feature = "overlay")]
    #[error("overlay broadcast failed: {0}")]
    OverlayBroadcastFailed(String),

    // ===================
    // Registry errors
    // ===================
    /// General registry error.
    #[cfg(feature = "registry")]
    #[error("registry error: {0}")]
    RegistryError(String),

    /// Definition not found in registry.
    #[cfg(feature = "registry")]
    #[error("definition not found: {0}")]
    DefinitionNotFound(String),

    /// Invalid definition data.
    #[cfg(feature = "registry")]
    #[error("invalid definition data: {0}")]
    InvalidDefinitionData(String),

    // ===================
    // KVStore errors
    // ===================
    /// General kvstore error.
    #[cfg(feature = "kvstore")]
    #[error("kvstore error: {0}")]
    KvStoreError(String),

    /// Key not found in kvstore.
    #[cfg(feature = "kvstore")]
    #[error("kvstore key not found: {0}")]
    KvStoreKeyNotFound(String),

    /// Corrupted kvstore state.
    #[cfg(feature = "kvstore")]
    #[error("corrupted kvstore state: {0}")]
    KvStoreCorruptedState(String),

    /// Empty context (protocol_id) provided to kvstore.
    #[cfg(feature = "kvstore")]
    #[error("context cannot be empty")]
    KvStoreEmptyContext,

    /// Invalid key provided to kvstore (empty).
    #[cfg(feature = "kvstore")]
    #[error("invalid key")]
    KvStoreInvalidKey,

    /// Invalid value provided to kvstore (empty).
    #[cfg(feature = "kvstore")]
    #[error("invalid value")]
    KvStoreInvalidValue,

    // ===================
    // Identity errors
    // ===================
    /// General identity error.
    #[cfg(feature = "identity")]
    #[error("identity error: {0}")]
    IdentityError(String),

    /// Identity not found.
    #[cfg(feature = "identity")]
    #[error("identity not found: {0}")]
    IdentityNotFound(String),

    /// Contact not found.
    #[cfg(feature = "identity")]
    #[error("contact not found: {0}")]
    ContactNotFound(String),
}

/// Result type alias for BSV SDK operations.
pub type Result<T> = std::result::Result<T, Error>;
