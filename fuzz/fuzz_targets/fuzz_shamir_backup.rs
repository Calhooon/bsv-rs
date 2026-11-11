#![no_main]
//! The Shamir backup readers on arbitrary text, one share per line:
//! `KeyShares::from_backup_format` (BRC-140's, the reference's reader) then
//! `recover_private_key` on what it read (at most `RECOVER` shares, the
//! interpolation being quadratic in them), and the legacy reader,
//! `recover_private_key_from_legacy_backup`. The assertion is that each
//! returns. The standard reader takes only the canonical form, so what it
//! reads is written back as the very lines given (#854), and the two forms
//! are disjoint: the legacy reader refuses every set the standard reader
//! reads (an 8-hex-digit tag names `from_backup_format`). The writer's round
//! trip: the input's hash as a key, split by `split_private_key` (threshold
//! and total from the leading byte) and written, parses back to the same
//! lines and recovers that key.
use bsv_rs::primitives::bsv::shamir::{
    recover_private_key_from_legacy_backup, split_private_key, KeyShares,
};
use bsv_rs::primitives::{sha256, PrivateKey};
use libfuzzer_sys::fuzz_target;

/// The most shares recovered from one input.
const RECOVER: usize = 32;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if let Ok(shares) = KeyShares::from_backup_format(&lines) {
            let written = shares.to_backup_format().expect("what it read it writes");
            assert_eq!(written, lines, "the reader is canonical");
            assert!(recover_private_key_from_legacy_backup(&lines).is_err());
            if shares.points.len() <= RECOVER {
                let _ = shares.recover_private_key();
            }
        }
        if lines.len() <= RECOVER {
            if let Ok(key) = recover_private_key_from_legacy_backup(&lines) {
                assert!(KeyShares::from_backup_format(&lines).is_err());
                let _ = key.to_bytes();
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
    let lines = shares.to_backup_format().expect("written");
    let read = KeyShares::from_backup_format(&lines).expect("its lines parse");
    assert_eq!(read.to_backup_format().expect("written"), lines);
    let recovered = read.recover_private_key().expect("recovers");
    assert_eq!(recovered.to_bytes(), key.to_bytes());
});
