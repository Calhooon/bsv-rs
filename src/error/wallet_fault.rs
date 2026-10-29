//! Wallet fault and stored abort-acceptance metadata for in-process hosts.

use super::WalletRefusalClass;
use thiserror::Error;

/// The port's extension beyond the reference: a wallet fault family for hosts.
///
/// The reference's `WalletError` has a string and a code, with no fault family
/// (`ts-stack@edf6e03`, `packages/sdk/src/wallet/WalletError.ts`). The string
/// remains the reference's; this metadata changes no verdict or retry promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WalletFaultFamily {
    /// Report an upstream communication failure, without inferring delivery
    /// or retry safety. Existing `TransportFault` metadata carries those facts.
    Transport,
    /// Report an upstream service failure rather than an invalid request.
    Service,
    /// Report a persistence failure as a server fault and retain diagnostics.
    Storage,
    /// Report an internal server failure and retain operator diagnostics.
    Internal,
}

/// The port's extension beyond the reference: a typed wallet fault beside its string.
///
/// The reference has no fault family. `message` remains the reference's string:
/// this type's `Display` writes it byte for byte. Wrapping it in
/// [`super::Error::WalletFault`] adds the same prefix as
/// [`super::Error::WalletError`], so both errors display identically for the
/// same message. This crate does not emit the new variant; a wallet host may
/// supply it without classifying message text.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{message}")]
#[non_exhaustive]
pub struct WalletFault {
    /// The failure family a host can match without parsing the message.
    pub family: WalletFaultFamily,
    /// The original `WalletError` string, without its SDK display prefix.
    pub message: String,
}

impl WalletFault {
    /// Attach a fault family to the original wallet error string unchanged.
    pub fn new(family: WalletFaultFamily, message: impl Into<String>) -> Self {
        Self {
            family,
            message: message.into(),
        }
    }
}

/// The port's extension beyond the reference: stored acceptance that refused an abort.
///
/// The reference's `WalletError` has no acceptance record; its string remains
/// the reference's. The presence of this record affirms stored acceptance,
/// not that the abort succeeded or that the transaction has a chain proof.
/// Only an abort refused on that evidence belongs here, not another status
/// refusal, a failed evidence read, or a retirement operation.
///
/// `message` is the toolbox guard's complete string, including its
/// `Invalid transaction status: ` prefix. Both this record and
/// [`super::Error::AbortAccepted`] display it byte for byte, just as
/// [`super::Error::WalletRefusal`] does. `class` retains the guard's existing
/// judgement: the status guard uses `InvalidParameter`, while the shared
/// stored-acceptance guard uses `InvalidOperation`. No class is inferred.
///
/// Optional fields carry only context the guard knows. An absent field does
/// not negate stored acceptance. Their text is boxed, and
/// [`super::Error::AbortAccepted`] boxes the whole record to keep the unified
/// error compact. On the wire it follows the same class code and message
/// rules as [`super::Error::WalletRefusal`]; the typed record stays in Rust.
/// This crate emits no acceptance records; the toolbox can supply one.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{message}")]
#[non_exhaustive]
pub struct AbortAcceptance {
    /// The action reference supplied to the abort call, unchanged.
    pub reference: String,
    /// The transaction ID, when the guard knows one.
    pub txid: Option<Box<str>>,
    /// The stored action status, when known (for example, `unproven`).
    pub status: Option<Box<str>>,
    /// The stored accepting word, when known, for diagnostics rather than parsing.
    pub accepting_word: Option<Box<str>>,
    /// The guard's original reference refusal class, preserved without reclassification.
    pub class: WalletRefusalClass,
    /// The guard's complete display string, unchanged byte for byte.
    pub message: String,
}

impl AbortAcceptance {
    /// Record confirmed stored acceptance, retaining the action, class and guard string.
    ///
    /// The caller has already checked the stored acceptance. Set `txid`,
    /// `status` and `accepting_word` when known; no value is derived from text.
    /// Wrap the record with `Error::AbortAccepted(Box::new(record))`.
    pub fn new(
        reference: impl Into<String>,
        class: WalletRefusalClass,
        message: impl Into<String>,
    ) -> Self {
        Self {
            reference: reference.into(),
            txid: None,
            status: None,
            accepting_word: None,
            class,
            message: message.into(),
        }
    }
}
