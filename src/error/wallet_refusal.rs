//! The reference's wallet refusal classes, re-exported by the error module.

#[cfg(doc)]
use super::Error;

/// The class of a wallet's refusal: the reference's wallet error table by
/// name (bsv-rs#137). Two tables at `ts-stack@edf6e03` meet here:
///
/// - the SDK's codes 2 to 8 (`walletErrors`,
///   `packages/sdk/src/wallet/WalletError.ts:71-80`), the ones its wire
///   processor keeps on the wire with the wallet's words
///   (`WalletWireProcessor.ts:2379-2384`, `:2407-2416`); code 1,
///   `unknownError`, is no class here: it is [`Error::WalletError`], framed
///   as `Wallet operation failed` (`:2417`);
/// - the wallet-toolbox's `WERR_*` classes
///   (`packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts`), each serving
///   its name as its code string (`WalletError.ts:35-37` there), four with a
///   numeric code in their JSON "to match HTTPWalletJSON.ts": 6 (`:110`), 8
///   (`:136`), 7 (`:225`), 5 (`:278`).
///
/// The SDK's `WERR_REVIEW_ACTIONS`, `WERR_INVALID_PARAMETER` and
/// `WERR_INSUFFICIENT_FUNDS` (codes 5, 6, 7) are the toolbox's classes of the
/// same names, one class each. The toolbox's `WERR_INVALID_MERKLE_ROOT` 8
/// collides with the SDK's `abortRefused` 8: the reference's, kept as it is.
/// [`Self::from_code`] reads the SDK's table (8 is `abortRefused`), and the
/// binary wire carries the SDK's codes only ([`Self::wire_code`]).
///
/// BRC-100 (`5119a9b` `wallet/0100.md:289-319`) asks a machine-readable code
/// of every error and leaves its naming to the implementation; its wire's
/// error byte is `1-255`, "predefined error types or ... custom error
/// categorization" (`:1609`).
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WalletRefusalClass {
    /// `unsupportedAction`, code 2: the wallet does not perform the call.
    UnsupportedAction,
    /// `invalidHmac`, code 3: an HMAC that does not verify.
    InvalidHmac,
    /// `invalidSignature`, code 4: a signature that does not verify.
    InvalidSignature,
    /// `WERR_REVIEW_ACTIONS` (`reviewActions`), code 5: an undelayed
    /// createAction or signAction whose results require review
    /// (`WERR_REVIEW_ACTIONS.ts:24-25`; the toolbox's `WERR_errors.ts:260`).
    ReviewActions,
    /// `WERR_INVALID_PARAMETER` (`invalidParameter`), code 6: an argument the
    /// wallet refuses (`WERR_INVALID_PARAMETER.ts:14-15`; `WERR_errors.ts:100`).
    InvalidParameter,
    /// `WERR_INSUFFICIENT_FUNDS` (`insufficientFunds`), code 7: the inputs
    /// cannot cover the outputs and the fee (`WERR_INSUFFICIENT_FUNDS.ts:19-20`;
    /// `WERR_errors.ts:208`).
    InsufficientFunds,
    /// `abortRefused`, code 8: the wallet refused to abort the action
    /// (`WalletWireProcessor.ts:801-804`).
    AbortRefused,
    /// `WERR_NOT_IMPLEMENTED`, no code (`WERR_errors.ts:8`).
    NotImplemented,
    /// `WERR_INTERNAL`, no code: an internal error (`WERR_errors.ts:19`).
    Internal,
    /// `WERR_INVALID_OPERATION`, no code (`WERR_errors.ts:30`).
    InvalidOperation,
    /// `WERR_UTXO_REVIEW_INCONCLUSIVE`, no code: a UTXO review with no
    /// verdict for every candidate, retryable (`WERR_errors.ts:41`).
    UtxoReviewInconclusive,
    /// `WERR_ACTION_BATCH_STATE`, no code: an action batch that cannot
    /// continue in its state (`WERR_errors.ts:68`, exported at `:84`).
    ActionBatchState,
    /// `WERR_BROADCAST_UNAVAILABLE`, no code (`WERR_errors.ts:89`).
    BroadcastUnavailable,
    /// `WERR_INVALID_MERKLE_ROOT`, code 8 in the toolbox's JSON (`:136`), the
    /// SDK's `abortRefused` code: no code on the binary wire
    /// (`WERR_errors.ts:121`).
    InvalidMerkleRoot,
    /// `WERR_MISSING_PARAMETER`, no code (`WERR_errors.ts:150`).
    MissingParameter,
    /// `WERR_BAD_REQUEST`, no code (`WERR_errors.ts:165`).
    BadRequest,
    /// `WERR_NETWORK_CHAIN`, no code (`WERR_errors.ts:174`).
    NetworkChain,
    /// `WERR_UNAUTHORIZED`, no code (`WERR_errors.ts:183`).
    Unauthorized,
    /// `WERR_NOT_ACTIVE`, no code: the storage manager is not on the user's
    /// active storage (`WERR_errors.ts:192`).
    NotActive,
    /// `WERR_INVALID_PUBLIC_KEY`, no code (`WERR_errors.ts:232`).
    InvalidPublicKey,
}

#[cfg(feature = "wallet")]
impl WalletRefusalClass {
    /// Every class: the SDK's seven in the order of their code, then the
    /// toolbox's other classes in the order of its file.
    pub const ALL: [Self; 20] = [
        Self::UnsupportedAction,
        Self::InvalidHmac,
        Self::InvalidSignature,
        Self::ReviewActions,
        Self::InvalidParameter,
        Self::InsufficientFunds,
        Self::AbortRefused,
        Self::NotImplemented,
        Self::Internal,
        Self::InvalidOperation,
        Self::UtxoReviewInconclusive,
        Self::ActionBatchState,
        Self::BroadcastUnavailable,
        Self::InvalidMerkleRoot,
        Self::MissingParameter,
        Self::BadRequest,
        Self::NetworkChain,
        Self::Unauthorized,
        Self::NotActive,
        Self::InvalidPublicKey,
    ];

    /// The reference's numeric code where it assigns one: the SDK's 2 to 8
    /// (a `UInt8`, `WalletError.ts:70`), and the toolbox's 8 for
    /// `WERR_INVALID_MERKLE_ROOT`; `None` for every other class, whose code
    /// is its name.
    #[must_use]
    pub fn code(&self) -> Option<u8> {
        match self {
            Self::UnsupportedAction => Some(2),
            Self::InvalidHmac => Some(3),
            Self::InvalidSignature => Some(4),
            Self::ReviewActions => Some(5),
            Self::InvalidParameter => Some(6),
            Self::InsufficientFunds => Some(7),
            Self::AbortRefused | Self::InvalidMerkleRoot => Some(8),
            _ => None,
        }
    }

    /// The error byte of a binary wire frame: the SDK's code 2 to 8, the
    /// class [`Self::from_code`] reads back. `None` for every other class,
    /// `WERR_INVALID_MERKLE_ROOT` among them (its 8 is the toolbox's JSON
    /// alone, and the reference's processor frames a toolbox error, whose
    /// `code` is its name, as `Wallet operation failed`,
    /// `WalletWireProcessor.ts:2406-2418`).
    #[must_use]
    pub fn wire_code(&self) -> Option<u8> {
        self.code()
            .filter(|code| Self::from_code(*code) == Some(*self))
    }

    /// The reference's name: the `WERR_*` class name where one exists (the
    /// toolbox's, and the SDK's for codes 5, 6, 7), else the SDK's
    /// `walletErrors` key (`unsupportedAction`, `invalidHmac`,
    /// `invalidSignature`, `abortRefused`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::UnsupportedAction => "unsupportedAction",
            Self::InvalidHmac => "invalidHmac",
            Self::InvalidSignature => "invalidSignature",
            Self::ReviewActions => "WERR_REVIEW_ACTIONS",
            Self::InvalidParameter => "WERR_INVALID_PARAMETER",
            Self::InsufficientFunds => "WERR_INSUFFICIENT_FUNDS",
            Self::AbortRefused => "abortRefused",
            Self::NotImplemented => "WERR_NOT_IMPLEMENTED",
            Self::Internal => "WERR_INTERNAL",
            Self::InvalidOperation => "WERR_INVALID_OPERATION",
            Self::UtxoReviewInconclusive => "WERR_UTXO_REVIEW_INCONCLUSIVE",
            Self::ActionBatchState => "WERR_ACTION_BATCH_STATE",
            Self::BroadcastUnavailable => "WERR_BROADCAST_UNAVAILABLE",
            Self::InvalidMerkleRoot => "WERR_INVALID_MERKLE_ROOT",
            Self::MissingParameter => "WERR_MISSING_PARAMETER",
            Self::BadRequest => "WERR_BAD_REQUEST",
            Self::NetworkChain => "WERR_NETWORK_CHAIN",
            Self::Unauthorized => "WERR_UNAUTHORIZED",
            Self::NotActive => "WERR_NOT_ACTIVE",
            Self::InvalidPublicKey => "WERR_INVALID_PUBLIC_KEY",
        }
    }

    /// The SDK's `walletErrors` key of a class with an SDK code
    /// (`WalletError.ts:73-79`); `None` for the toolbox's other classes.
    #[must_use]
    pub fn code_name(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedAction => Some("unsupportedAction"),
            Self::InvalidHmac => Some("invalidHmac"),
            Self::InvalidSignature => Some("invalidSignature"),
            Self::ReviewActions => Some("reviewActions"),
            Self::InvalidParameter => Some("invalidParameter"),
            Self::InsufficientFunds => Some("insufficientFunds"),
            Self::AbortRefused => Some("abortRefused"),
            _ => None,
        }
    }

    /// The class of a name: a [`Self::name`] or a [`Self::code_name`],
    /// compared byte for byte; `None` for any other string (`WERR_UNKNOWN`,
    /// the toolbox's un-classed error, among them).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.name() == name || class.code_name() == Some(name))
    }

    /// The class of an SDK code, 2 to 8 (8 is `abortRefused`); `None` for
    /// every other byte (1 is `unknownError`, 9 and above no class of the
    /// reference's).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            2 => Some(Self::UnsupportedAction),
            3 => Some(Self::InvalidHmac),
            4 => Some(Self::InvalidSignature),
            5 => Some(Self::ReviewActions),
            6 => Some(Self::InvalidParameter),
            7 => Some(Self::InsufficientFunds),
            8 => Some(Self::AbortRefused),
            _ => None,
        }
    }
}

#[cfg(feature = "wallet")]
impl std::fmt::Display for WalletRefusalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
