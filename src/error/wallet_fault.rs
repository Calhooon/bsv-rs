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

/// The port's extension beyond the reference: which fact refused an abort (#604).
///
/// A host matches the case instead of the message text. The reference has no
/// such type: its toolbox answers a chain-confirmed refusal with
/// `{ aborted: false }` (`ts-stack@edf6e03`,
/// `packages/wallet/wallet-toolbox/src/storage/StorageProvider.ts:878,889,927-932`),
/// an answer this crate's processor frames as code 8 (#206). An
/// [`super::Error::AbortAccepted`] record is framed by its `class` instead,
/// as the [`super::Error::WalletRefusal`] of that class and message, whatever
/// its kind: `OnChain` under `InvalidOperation` travels as code 1. The kind
/// moves no wire byte and no display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum AbortKind {
    /// The transaction is mined or known to the chain: the reference's
    /// predicate, `chainStatus === 'mined' || chainStatus === 'known'`
    /// (`StorageProvider.ts:878` at `edf6e03`), which the reference asks only
    /// of a `nosend` action with a txid and no expiry state (`:870`).
    OnChain,
    /// The store's accepting word refused the abort (the stored-acceptance
    /// guard, toolbox #165).
    AcceptedInStore,
    /// Every other abort guard refusal, the status guard among them, and the
    /// value [`AbortAcceptance::new`] leaves: an unset record claims no fact
    /// the guard did not set.
    #[default]
    Other,
}

/// The port's extension beyond the reference: an abort guard's refusal of an abort.
///
/// The reference's `WalletError` has no acceptance record; its string remains
/// the reference's. The presence of this record affirms that the abort guards
/// refused the abort, not that the abort succeeded or that the transaction has
/// a chain proof. Only a refusal by an abort guard belongs here, not a failed
/// evidence read or a retirement operation; [`AbortAcceptance::kind`] says
/// which guard's fact refused it (#604).
///
/// `message` is the toolbox guard's complete string, including its
/// `Invalid transaction status: ` prefix. Both this record and
/// [`super::Error::AbortAccepted`] display it byte for byte, just as
/// [`super::Error::WalletRefusal`] does. `class` retains the guard's existing
/// judgement: the status guard uses `InvalidParameter`, while the shared
/// stored-acceptance guard uses `InvalidOperation`. No class is inferred.
///
/// Optional fields carry only context the guard knows. An absent field does
/// not negate the guard's refusal. Their text is boxed, and
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
    /// Which fact refused the abort, set by the guard that knows it; never
    /// derived from text. [`AbortAcceptance::new`] leaves [`AbortKind::Other`].
    pub kind: AbortKind,
    /// The guard's original reference refusal class, preserved without reclassification.
    pub class: WalletRefusalClass,
    /// The guard's complete display string, unchanged byte for byte.
    pub message: String,
}

impl AbortAcceptance {
    /// Record an abort guard's refusal, retaining the action, class and guard string.
    ///
    /// The caller's guard has already established the fact that refused the abort. Set `txid`,
    /// `status`, `accepting_word` and `kind` when known; no value is derived
    /// from text, and `kind` stays [`AbortKind::Other`] until the guard sets it.
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
            kind: AbortKind::Other,
            class,
            message: message.into(),
        }
    }
}
