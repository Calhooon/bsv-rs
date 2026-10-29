//! Error types for the BSV SDK.

use thiserror::Error;

#[cfg(feature = "wallet")]
mod wallet_fault;
#[cfg(feature = "wallet")]
pub use wallet_fault::{AbortAcceptance, WalletFault, WalletFaultFamily};

#[cfg(feature = "wallet")]
mod wallet_refusal;
#[cfg(feature = "wallet")]
pub use wallet_refusal::WalletRefusalClass;

/// Main error type for the BSV SDK.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ===================
    // Primitives errors
    // ===================
    /// Invalid key length for cryptographic operations.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// The length the operation requires, in bytes.
        expected: usize,
        /// The length supplied, in bytes.
        actual: usize,
    },

    /// Invalid data length for cryptographic operations.
    #[error("invalid data length: expected {expected}, got {actual}")]
    InvalidDataLength {
        /// The length the operation requires, in bytes.
        expected: usize,
        /// The length supplied, in bytes.
        actual: usize,
    },

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
    ReaderUnderflow {
        /// The bytes the read asked for.
        needed: usize,
        /// The bytes left in the reader.
        available: usize,
    },

    /// A varint using more bytes than its value requires. Width includes the marker.
    #[error("non-canonical varint: {value} encoded in {width} bytes")]
    NonCanonicalVarInt {
        /// The encoded width in bytes, the marker included.
        width: u8,
        /// The value the varint carries.
        value: u64,
    },

    /// A node CompactSize above `MAX_COMPACT_SIZE`.
    #[error("compact size too large: {0}")]
    CompactSizeTooLarge(u64),

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

    /// `Transaction::verify` stopped an input's evaluation at a local budget:
    /// the script was not judged, valid or not (the reference's `ScriptResourceLimitError`; bsv-rs#38).
    #[cfg(feature = "transaction")]
    #[error("script evaluation declined for input {input_index}: {limit}")]
    ScriptEvaluationDeclined {
        /// The index of the input whose evaluation stopped.
        input_index: usize,
        /// The resource, its budget and the attempted usage.
        limit: crate::script::ScriptResourceLimit,
    },

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

    /// The port's typed fault extension; displays exactly as `WalletError`.
    /// This crate emits no such variant; see [`WalletFault`].
    #[cfg(feature = "wallet")]
    #[error("wallet error: {0}")]
    WalletFault(WalletFault),

    /// The port's stored-acceptance extension for a refused abort, not a successful abort.
    /// Preserves the guard's class and complete string; see [`AbortAcceptance`].
    #[cfg(feature = "wallet")]
    #[error("{0}")]
    AbortAccepted(Box<AbortAcceptance>),

    /// A wallet's refusal with its class: the reference's classed wallet error.
    ///
    /// The reference's `WalletError` carries a code beside its message: the
    /// SDK's a number (`ts-stack@edf6e03` `packages/sdk/src/wallet/WalletError.ts:3`,
    /// the table at `:71-80`), the wallet-toolbox's its `WERR_*` name
    /// (`packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts`); this is that
    /// error, the class the code and the words the message. A wallet raises
    /// it where the caller should learn why (a bad argument, too few funds, a
    /// refused abort, an unauthorized call); every other failure stays
    /// [`Error::WalletError`], the reference's `unknownError`. The wire
    /// processor frames a class with an SDK code ([`WalletRefusalClass::wire_code`])
    /// with that code and its words, and every other class as
    /// `Wallet operation failed`, code 1 (`WalletWireProcessor.ts:2402-2418`);
    /// the transceiver reads a frame coded 2 to 8 back as this variant
    /// (`WalletWireTransceiver.ts:153`); the HTTP JSON substrate reads an
    /// error body's class by its name or its code (#137). `Display` is the message alone: the class is the typed field.
    #[cfg(feature = "wallet")]
    #[error("{message}")]
    WalletRefusal {
        /// The reference's class of the refusal, and its code.
        class: WalletRefusalClass,
        /// The refusal in the wallet's words, as the frame carries them.
        message: String,
    },

    /// `WERR_REVIEW_ACTIONS` with its review results ([`crate::wallet::ReviewActionsRefusal`], #327).
    #[cfg(feature = "wallet")]
    #[error("{}", .0.message)]
    WalletReviewActions(Box<crate::wallet::ReviewActionsRefusal>),

    /// The wallet is busy: a refusal before acting, in the wallet's word.
    ///
    /// The wallet answered that it refused the call before acting (a
    /// contended store, a lock not acquired) and promised that nothing was
    /// written, built or locked, so the caller may repeat the same call
    /// unchanged after `retry_after_ms`, or after a moment when it is `None`.
    /// The SDK reports the server's promise; it cannot check it.
    /// `HttpWalletJson` reads it from the body's code (`STORE_BUSY`,
    /// `ERR_SERVER_BUSY`), never from the HTTP status; a 503 without that
    /// code is [`Error::WalletTransport`].
    #[cfg(feature = "wallet")]
    #[error("wallet busy: {detail}")]
    WalletBusy {
        /// What was busy, in the wallet's words.
        detail: String,
        /// How long the wallet asks the caller to wait before repeating the
        /// call, in milliseconds; `None` when it did not say. Unbounded: the
        /// server's word, not checked (a huge `Retry-After` saturates to
        /// `u64::MAX`), so a caller caps its own wait.
        retry_after_ms: Option<u64>,
    },

    /// The way to the wallet failed: no answer in the wallet's word.
    ///
    /// A caller may retry it; it carries no promise about what the wallet
    /// did (the request may or may not have reached it), which is the one
    /// way it differs from [`Error::WalletBusy`]. `HttpWalletJson` answers it
    /// for a 502, 503 or 504 whose body carries no busy code and no numeric
    /// wallet code, a connection error (refused, reset, DNS) and a timeout;
    /// every other failure, and every refusal, stays [`Error::WalletError`].
    /// The crate never retries by itself.
    #[cfg(feature = "wallet")]
    #[error("wallet transport fault: {detail}")]
    WalletTransport {
        /// The HTTP status of the answer, when one arrived (502, 503 or
        /// 504); `None` when no answer arrived (a connection error, a
        /// timeout).
        status: Option<u16>,
        /// What failed, in the transport's words.
        detail: String,
    },

    /// A transport fault with its class: no answer in the far side's word.
    ///
    /// The auth transports answer it for a connection error, a timeout and
    /// a handshake answered 429, 502, 503 or 504; the wallet substrates for a
    /// 429 without a busy code (their other faults stay
    /// [`Error::WalletTransport`]). A caller may retry it after the wait of
    /// [`TransportFault::RateLimited`]; the crate never retries by itself.
    /// [`Error::transport_fault`] reads the class of either variant.
    #[cfg(feature = "wallet")]
    #[error("transport fault {fault}: {detail}")]
    TransportFault {
        /// What the caller may assume about the far side.
        fault: TransportFault,
        /// The HTTP status of the answer, when one arrived; `None` when no
        /// answer arrived (a connection error, a timeout).
        status: Option<u16>,
        /// What failed, in the transport's words.
        detail: String,
    },

    /// Former minimal-length-key refusal (#148), retained for source compatibility.
    /// Never emitted since #379; strict verification returns [`Error::HmacLegacyKey`].
    #[cfg(feature = "wallet")]
    #[error(
        "HMAC is not valid: the tag was made under a minimal-length key (the sender drops the {leading_zero_bytes} leading zero byte(s) of the 32-byte X coordinate; BRC-56)"
    )]
    HmacMinimalLengthKey {
        /// Leading zero octets omitted by the sender.
        leading_zero_bytes: usize,
    },

    /// Strict refusal of a pre-amendment 32-byte-key tag (#379).
    #[cfg(feature = "wallet")]
    #[error("HMAC is not valid: legacy 32-byte key ({leading_zero_bytes} leading zero byte(s))")]
    HmacLegacyKey {
        /// The leading zero octets retained by the legacy key.
        leading_zero_bytes: usize,
    },

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
    MessageVersionMismatch {
        /// The version prefix this crate reads, as hex.
        expected: String,
        /// The version prefix the message carries, as hex.
        actual: String,
    },

    /// General message error.
    #[cfg(feature = "messages")]
    #[error("message error: {0}")]
    MessageError(String),

    /// Message recipient mismatch.
    #[cfg(feature = "messages")]
    #[error("message recipient mismatch: expected {expected}, got {actual}")]
    MessageRecipientMismatch {
        /// The recipient public key the message names, compressed, as hex.
        expected: String,
        /// The public key of the private key supplied to read it, compressed, as hex.
        actual: String,
    },

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
    InvalidEntropyLength {
        /// The entropy lengths accepted, in bits.
        expected: String,
        /// The entropy length supplied, in bits.
        actual: usize,
    },

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

    /// ECIES plaintext failed input validation before encryption.
    #[cfg(feature = "compat")]
    #[error("{0}")]
    EciesInvalidPlaintext(String),

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

    /// The chain facts cannot select a supported word; the input was not judged.
    #[cfg(feature = "transaction")]
    #[error("transaction {txid} input {input_index} not judged: {cause}")]
    TransactionNotJudged {
        /// The display txid of the unproven transaction being checked.
        txid: String,
        /// The index of the input outside the verifier's scope.
        input_index: usize,
        /// The typed scope or configuration refusal.
        cause: crate::script::NotJudgedCause,
    },
}

/// The class of a transport fault: what a caller may assume about the far
/// side when no answer arrived in its word (Calhooon/bsv-rs#87).
///
/// Busy is the body's word, never the HTTP status: a 502, 503 or 504 without
/// it, a connection error or a timeout is a fault, retryable, promising
/// nothing about what the far side did. A broadcaster's failure names the
/// class in its `code` ([`TransportFault::code`]).
#[cfg(feature = "transaction")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportFault {
    /// No byte of the request left: the connection was never made, or the
    /// request could not be built. A spender may release its inputs.
    NeverSent,
    /// The request may have reached the far side: a timeout or a connection
    /// lost after it was written, or a 502, 503 or 504 without the far
    /// side's word. A spender holds its inputs.
    MayHaveBeenReceived,
    /// The far side answered 429, or 503 with `Retry-After`: a rate limit,
    /// never a verdict on the request.
    RateLimited {
        /// The wait `Retry-After` asked for, in milliseconds (delta seconds
        /// or an HTTP date, saturating; a date passed is 0); `None` when it
        /// was absent or unreadable. The server's word: a caller caps it.
        retry_after_ms: Option<u64>,
    },
}

#[cfg(feature = "transaction")]
impl TransportFault {
    /// The class's code word: `NEVER_SENT`, `MAY_HAVE_BEEN_RECEIVED` or
    /// `RATE_LIMITED`, as a broadcaster's failure carries it.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NeverSent => "NEVER_SENT",
            Self::MayHaveBeenReceived => "MAY_HAVE_BEEN_RECEIVED",
            Self::RateLimited { .. } => "RATE_LIMITED",
        }
    }
}

#[cfg(feature = "transaction")]
impl std::fmt::Display for TransportFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(feature = "wallet")]
impl Error {
    /// The transport fault this error reports, if it is one:
    /// [`Error::TransportFault`]'s class, and
    /// [`TransportFault::MayHaveBeenReceived`] for [`Error::WalletTransport`]
    /// (it promises nothing about what the wallet did). Busy, a refusal and
    /// every other error are `None`.
    #[must_use]
    pub fn transport_fault(&self) -> Option<TransportFault> {
        match self {
            Self::TransportFault { fault, .. } => Some(*fault),
            Self::WalletTransport { .. } => Some(TransportFault::MayHaveBeenReceived),
            _ => None,
        }
    }
}

/// Result type alias for BSV SDK operations.
pub type Result<T> = std::result::Result<T, Error>;
