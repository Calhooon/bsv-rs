#![no_main]
//! The Shamir backup reader, `KeyShares::from_backup_format`, on arbitrary
//! text, one share per line; then `recover_private_key` on what it read (at
//! most `RECOVER` shares, the interpolation being quadratic in them). The
//! assertion is that each returns. A share's numbers are read modulo the
//! field prime and its base58 and threshold in more than one spelling, so
//! the round trip is the canonical form: the parsed shares write lines that
//! parse to the same points, threshold and integrity, and write the same
//! lines again. The writer's round trip: the input's hash as a key, split by
//! `split_private_key` (threshold and total from the leading byte) and
//! written, parses and recovers that key.
use bsv_rs::primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_rs::primitives::{sha256, PrivateKey};
use libfuzzer_sys::fuzz_target;

/// The most shares recovered from one input.
const RECOVER: usize = 32;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if let Ok(shares) = KeyShares::from_backup_format(&lines) {
            let written = shares.to_backup_format();
            let again = KeyShares::from_backup_format(&written).expect("its lines parse");
            assert_eq!(again.points, shares.points);
            assert_eq!(again.threshold, shares.threshold);
            assert_eq!(again.integrity, shares.integrity);
            assert_eq!(again.to_backup_format(), written);
            if shares.points.len() <= RECOVER {
                let _ = shares.recover_private_key();
            }
        }
    }

    let Ok(key) = PrivateKey::from_bytes(&sha256(data)) else {
        return;
    };
    let mode = data.first().copied().unwrap_or(0);
    let threshold = 2 + usize::from(mode & 3);
    let total = threshold + usize::from(mode >> 6);
    let shares = split_private_key(&key, threshold, total).expect("a split");
    let lines = shares.to_backup_format();
    let read = KeyShares::from_backup_format(&lines).expect("its lines parse");
    assert_eq!(read.to_backup_format(), lines);
    let recovered = read.recover_private_key().expect("recovers");
    assert_eq!(recovered.to_bytes(), key.to_bytes());
});
