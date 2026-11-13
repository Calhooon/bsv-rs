//! `BigNumber`'s internal value, lent inside the crate alone (#843d23): no
//! public signature names `num_bigint::BigInt`, so a `num-bigint` major is
//! never this crate's break. The interpreter's arithmetic is the one caller
//! (`src/script/script_num.rs`, `src/script/spend/arithmetic.rs`,
//! `arithmetic_room.rs`); outside the crate a value crosses through its text
//! (`to_hex` and `from_hex`, `to_dec_string` and `from_dec_str`).

use super::BigNumber;
use num_bigint::BigInt;

impl BigNumber {
    /// The internal `BigInt`, borrowed. Crate-private (#843d23).
    pub(crate) fn as_bigint(&self) -> &BigInt {
        &self.inner
    }

    /// The internal `BigInt`, moved out (the interpreter's owned arithmetic,
    /// bsv-rs#374: no copy of the digits). Crate-private (#843d23).
    pub(crate) fn into_bigint(self) -> BigInt {
        self.inner
    }

    /// A `BigNumber` holding `inner`. Crate-private (#843d23).
    pub(crate) fn from_bigint(inner: BigInt) -> Self {
        Self { inner }
    }
}
