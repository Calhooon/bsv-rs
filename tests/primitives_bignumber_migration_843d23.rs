//! `BigNumber` hides its representation (#843d23, #843's freeze plan, row 2):
//! `as_bigint`, `from_bigint` and the two `From` impls between `BigNumber`
//! and `num_bigint::BigInt` left the public surface, so a `num-bigint` major
//! is never this crate's break. The migration crosses through the public
//! text; this test runs each Migration line of the CHANGELOG entry on both
//! signs, zero and a 300-bit value. No reference line: neither SDK exposes
//! a foreign number type.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use bsv_rs::primitives::BigNumber;
use num_bigint::BigInt;

/// `n.as_bigint()` / `BigInt::from(n)`
fn to_bigint(n: &BigNumber) -> BigInt {
    BigInt::parse_bytes(n.to_hex().as_bytes(), 16).unwrap()
}

/// `BigNumber::from(b)` / `BigNumber::from_bigint(b)`
fn from_bigint(b: &BigInt) -> BigNumber {
    BigNumber::from_hex(&b.to_str_radix(16)).unwrap()
}

#[test]
fn a_bignumber_crosses_to_a_bigint_by_its_public_text_843d23() {
    // 2^299 + 0xa5: 75 hex digits, the leading `8` its top bit, 300 bits
    let three_hundred_bits = format!("8{}a5", "0".repeat(72));
    let cases = [
        "0".to_string(),
        "1".to_string(),
        "-1".to_string(),
        "deadbeef".to_string(),
        "-deadbeef".to_string(),
        three_hundred_bits.clone(),
        format!("-{three_hundred_bits}"),
    ];
    for hex in &cases {
        let n = BigNumber::from_hex(hex).unwrap();
        let b = to_bigint(&n);
        // The same value on both sides, by its decimal text
        assert_eq!(b.to_string(), n.to_dec_string(), "{hex}");
        assert_eq!(from_bigint(&b), n, "{hex}");
        // The decimal form crosses too
        assert_eq!(BigNumber::from_dec_str(&b.to_string()).unwrap(), n, "{hex}");
        assert_eq!(n.to_dec_string().parse::<BigInt>().unwrap(), b, "{hex}");
    }
    let big = BigNumber::from_hex(&three_hundred_bits).unwrap();
    assert_eq!(big.bit_length(), 300);
    assert_eq!(to_bigint(&big).bits(), 300);
    assert!(to_bigint(&BigNumber::from_hex("-1").unwrap()) < BigInt::from(0));
}
