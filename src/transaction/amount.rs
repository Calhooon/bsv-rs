//! An amount read from a transaction's bytes (#844): the one judgment of
//! every reader of a transaction and of the raw-entry scan.
//!
//! The reference reads an output's amount and an EF input's source amount
//! through `readUInt64LEBn().toNumber()` (`ts-stack@edf6e03`
//! `Transaction.ts:388,409,497`), and `BigNumber.toNumber` throws `Number can
//! only safely store up to 53 bits` for a value past `Number.MAX_SAFE_INTEGER`
//! (`BigNumber.ts:624-628`), so its `fromBinary`, `fromHex`, `fromReader`,
//! `fromEF` and `fromHexEF` refuse an amount of 2^53 satoshis or more; this
//! crate's readers refuse it in those words. No such output is valid at the
//! node (an amount above `MAX_MONEY`, 2.1e15 satoshis, below 2^53, is
//! `bad-txns-vout-toolarge`, bitcoin-sv v1.2.2 `validation.cpp:548-551`,
//! `amount.h:130`), so the refusal moves no node verdict. The reference's
//! `parseScriptOffsets` skips the eight bytes unread (`Transaction.ts:456`)
//! and so does this crate's.

use crate::primitives::Reader;
use crate::Result;

/// The reference's words for an amount it cannot hold (`BigNumber.ts:628`).
pub(crate) const UNSAFE_AMOUNT: &str = "Number can only safely store up to 53 bits";

/// The reference's writer's words for an amount it cannot write
/// (`BigNumber.ts:462`, `#initNumber`'s assertion: `Transaction.toBinary`
/// builds a `BigNumber` from each output's `satoshis`). Its BEEF writers and
/// its `mergeTransaction` throw them for an entry holding a transaction whose
/// output carries 2^53 or more, ahead of every other refusal of theirs
/// (`Beef.ts:360-373`: the entries' transactions serialized by
/// `synchronizeNestedTransactionMutations` first); recorded by #844's fold
/// (`tests/vectors/transaction_numbers_844.json`, `writer_cells`).
pub(crate) const UNSAFE_WRITE: &str = "The number is larger than 2 ^ 53 (unsafe)";

/// The largest amount a JavaScript number holds exactly
/// (`Number.MAX_SAFE_INTEGER`, 2^53 - 1).
pub(crate) const MAX_SAFE_AMOUNT: u64 = (1 << 53) - 1;

/// `value` as an amount, else [`UNSAFE_AMOUNT`].
pub(crate) fn safe_amount(value: u64) -> std::result::Result<u64, &'static str> {
    if value > MAX_SAFE_AMOUNT {
        Err(UNSAFE_AMOUNT)
    } else {
        Ok(value)
    }
}

/// Reads an amount, eight bytes little-endian, refusing one of 2^53 or more
/// in the reference's words as `TransactionError`.
pub(crate) fn read_amount(reader: &mut Reader) -> Result<u64> {
    safe_amount(reader.read_u64_le()?)
        .map_err(|words| crate::Error::TransactionError(words.to_string()))
}

/// How a reader takes an output's amount: the reference's bound, or the
/// node's (#874).
///
/// [`Transaction::from_binary`](super::Transaction::from_binary) and every
/// public reader take [`AmountRule::Reference`]. The one-input door
/// (`spending.rs`) takes [`AmountRule::Node`]: the node's consensus library
/// deserializes an amount as any 64-bit value (bitcoin-sv v1.2.2
/// `primitives/transaction.h:190-194`, `amount.h:111`) and checks none
/// (`bitcoinconsensus.cpp:88-122`), so the door reads every amount and notes
/// one of 2^53 or more, the refusal the reference's mode answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AmountRule {
    /// An amount of 2^53 or more refused in the reference's words.
    Reference,
    /// Any 64-bit amount read; `unsafe_seen` notes one of 2^53 or more.
    Node {
        /// An amount the reference's reader refuses was read.
        unsafe_seen: bool,
    },
}

impl AmountRule {
    /// The node's rule, nothing seen yet.
    pub(crate) const fn node() -> Self {
        Self::Node { unsafe_seen: false }
    }

    /// Reads an amount, eight bytes little-endian, under this rule.
    pub(crate) fn read(&mut self, reader: &mut Reader) -> Result<u64> {
        match self {
            Self::Reference => read_amount(reader),
            Self::Node { unsafe_seen } => {
                let value = reader.read_u64_le()?;
                *unsafe_seen |= safe_amount(value).is_err();
                Ok(value)
            }
        }
    }

    /// The reference reader's refusal of what this rule read: `Some` when
    /// the node's rule read an amount of 2^53 or more, in
    /// [`read_amount`]'s words and type.
    pub(crate) fn reference_refusal(&self) -> Option<crate::Error> {
        match self {
            Self::Node { unsafe_seen: true } => {
                Some(crate::Error::TransactionError(UNSAFE_AMOUNT.to_string()))
            }
            _ => None,
        }
    }
}

/// The reference's bound on an amount and on a total, 21e14 satoshis
/// (`MAX_SATOSHIS`, `ts-stack@edf6e03` `Transaction.ts:65`), the node's
/// `MAX_MONEY` (bitcoin-sv v1.2.2 `amount.h:130`).
pub(crate) const MAX_SATOSHIS: u64 = 2_100_000_000_000_000;

/// A caller's amount (`Transaction::fee`, `get_fee`), refused when absent or
/// past 21e14 in the reference's `requireSatoshiAmount` words, `<label> must
/// be a non-negative safe integer no greater than 21e14.`
/// (`Transaction.ts:68-78`; #871: until then an absent amount was read as 0
/// and none was bounded).
pub(crate) fn require_satoshi_amount(value: Option<u64>, label: &str) -> Result<u64> {
    match value {
        Some(v) if v <= MAX_SATOSHIS => Ok(v),
        _ => Err(crate::Error::TransactionError(format!(
            "{label} must be a non-negative safe integer no greater than 21e14."
        ))),
    }
}

/// `total + value` for a sum of a caller's amounts (`Transaction::fee`,
/// `get_fee`), refused past 21e14 in the reference's `addSatoshiAmount`
/// words, `<label> exceeds the maximum valid monetary range.`
/// (`ts-stack@edf6e03` `Transaction.ts:80-86`); past `u64` until #871, and a
/// debug panic or a wrapped sum until #868. The one place for the bound on a
/// total.
pub(crate) fn add_amount(total: u64, value: u64, label: &str) -> Result<u64> {
    match total.checked_add(value) {
        Some(sum) if sum <= MAX_SATOSHIS => Ok(sum),
        _ => Err(crate::Error::TransactionError(format!(
            "{label} exceeds the maximum valid monetary range."
        ))),
    }
}
