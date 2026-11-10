//! The sum of a caller's amounts (#868, cherry-picked from beta, where this
//! file also holds #844's judgment of an amount read from bytes).

use crate::Result;

/// `total + value` for a sum of a caller's amounts (`Transaction::fee`,
/// `get_fee`), refused past `u64` in the reference's `addSatoshiAmount` words,
/// `<label> exceeds the maximum valid monetary range.` (`ts-stack@edf6e03`
/// `Transaction.ts:80-86`), where it panicked in a debug build and wrapped in
/// a release build until #868. The reference refuses past 21e14 satoshis; this
/// crate only past `u64` (the stated row of #868).
pub(crate) fn add_amount(total: u64, value: u64, label: &str) -> Result<u64> {
    total.checked_add(value).ok_or_else(|| {
        crate::Error::TransactionError(format!("{label} exceeds the maximum valid monetary range."))
    })
}
