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
