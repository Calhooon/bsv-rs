//! The legacy backup reader (#854): a backup written by bsv-rs 0.8.5 or
//! earlier (every published release from 0.2.0), whose integrity tag is the
//! first 4 characters of base58(sha256(the key's 32 bytes)), where BRC-140's
//! is 8 hex digits of HASH160 of the public key. No other SDK reads or
//! writes this form; it is read here by a deliberate call and never written
//! again (the function returns the key, never a `KeyShares`). Kept, not
//! deprecated.

use super::{four_fields, interpolate, is_integrity, threshold_of, InterpolationWords};
use crate::error::{Error, Result};
use crate::primitives::bsv::polynomial::PointInFiniteField;
use crate::primitives::encoding::to_base58;
use crate::primitives::hash::sha256;
use crate::primitives::PrivateKey;

/// The most shares the legacy reader takes (the old writer's threshold
/// bound; a holder needs only `threshold` of them).
const MAX_LEGACY_SHARES: usize = 255;

/// The longest share the old writer wrote, in bytes: x at most 11 base58
/// characters (it wrote x = 1, 2, ..., total for a `usize` total, and
/// base58 of 2^64 - 1 is 11 characters), y at most 44 (a value below p,
/// 32 bytes), the threshold at most 3 digits (it refused one above 255), the
/// tag 4, and three dots: 11 + 44 + 3 + 4 + 3 = 65. A longer text is refused
/// on its length before it is split.
const MAX_LEGACY_SHARE_LENGTH: usize = 65;

fn crypto(words: impl Into<String>) -> Error {
    Error::CryptoError(words.into())
}

/// The old tag: the leading 4 characters of base58(sha256(key bytes)).
fn legacy_integrity(key: &PrivateKey) -> String {
    let b58 = to_base58(&sha256(&key.to_bytes()));
    b58.chars().take(4).collect()
}

/// Exactly 4 base58 characters, the old tag's shape.
fn is_legacy_integrity(field: &str) -> bool {
    field.len() == 4 && super::is_base58_field(field)
}

/// Recovers a private key from a backup this crate wrote before #854
/// (bsv-rs 0.8.5 and every published release before it, from 0.2.0):
/// shares `x.y.threshold.tag` whose tag is 4 base58 characters. The crate
/// `bsv-sdk` on crates.io is another project; its shares carry BRC-140's tag
/// and are read by [`KeyShares::from_backup_format`](super::KeyShares::from_backup_format).
///
/// It reads only what the old writer wrote: 1 to 255 shares, each at most
/// 65 bytes (the longest the old writer could write) and of four
/// fields; x and y canonical base58 (the point read as
/// [`PointInFiniteField::from_string`] reads it, so a leading `1` or a
/// coordinate at or above p is refused); a threshold of 2 to 255 with no sign
/// or leading zero; a tag of exactly 4 base58 characters, the same on every
/// share; at least `threshold` shares, every share's x non-zero and distinct
/// in the whole set, past the threshold window (#854). The recovered key's
/// old tag is checked, and the key returned.
/// A share in BRC-140's form (an 8-hex-digit tag) is refused in words that
/// name [`KeyShares::from_backup_format`](super::KeyShares::from_backup_format).
///
/// This crate's addition, with no counterpart in any other SDK. It returns
/// the key, never a [`KeyShares`](super::KeyShares), so the old form can
/// never be written again: split the key anew with
/// [`split_private_key`](super::split_private_key) and replace the old
/// copies; the new shares are BRC-140's, read by `@bsv/sdk` and go-sdk.
///
/// # Errors
///
/// Every refusal names the share by its index, never its text:
/// `legacy backup must contain from 1 to 255 shares`, `Share N is longer
/// than any legacy share (65 bytes): check it for spaces or a line break
/// around or inside it; a share with an 8-hex-digit tag is BRC-140's, read
/// with KeyShares::from_backup_format` (a share's length in bytes judged
/// before it is split, so the work is bounded by 255 shares of 65 bytes;
/// whitespace that keeps a share within 65 bytes is refused as `Invalid
/// legacy share data in share N`), `Invalid legacy share
/// format in share N. Expected format: "x.y.t.i"`, `Share N is in the BRC-140
/// backup form; read it with KeyShares::from_backup_format`, `Invalid legacy
/// share data in share N`, `Threshold mismatch in legacy share N`, `Integrity
/// mismatch in legacy share N`, `At least T legacy shares are required to
/// recover the private key`, `Zero x coordinate in legacy share N`,
/// `Duplicate legacy share detected, each must be
/// unique.`, `Legacy integrity check failed`.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::bsv::shamir::recover_private_key_from_legacy_backup;
///
/// // Two of three shares of key 1, written by bsv-rs 0.8.5's `split_private_key(.., 2, 3)`
/// let old = vec![
///     "2.GUibg2QL6Zip4QDpTAiPhM5zaMAxoXJBWFxVszov1Wch.2.GuMr".to_string(),
///     "4.CyX42Vhnhbgu336cu9nahbewE4EEv9kMYfxqv9oJ4JDj.2.GuMr".to_string(),
/// ];
/// let key = recover_private_key_from_legacy_backup(&old).unwrap();
/// assert_eq!(key.to_hex(), format!("{:064x}", 1));
/// ```
pub fn recover_private_key_from_legacy_backup(shares: &[String]) -> Result<PrivateKey> {
    if shares.is_empty() || shares.len() > MAX_LEGACY_SHARES {
        return Err(crypto(format!(
            "legacy backup must contain from 1 to {MAX_LEGACY_SHARES} shares"
        )));
    }
    let mut threshold = 0;
    let mut integrity = "";
    let mut points = Vec::with_capacity(shares.len());
    for (idx, share) in shares.iter().enumerate() {
        if share.len() > MAX_LEGACY_SHARE_LENGTH {
            return Err(crypto(format!(
                "Share {idx} is longer than any legacy share ({MAX_LEGACY_SHARE_LENGTH} bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format"
            )));
        }
        let Some([x, y, t, i]) = four_fields(share) else {
            return Err(crypto(format!(
                "Invalid legacy share format in share {idx}. Expected format: \"x.y.t.i\""
            )));
        };
        if is_integrity(i) {
            return Err(crypto(format!(
                "Share {idx} is in the BRC-140 backup form; read it with KeyShares::from_backup_format"
            )));
        }
        let invalid = || crypto(format!("Invalid legacy share data in share {idx}"));
        let Some(t) = threshold_of(t).filter(|_| is_legacy_integrity(i)) else {
            return Err(invalid());
        };
        if idx != 0 && threshold != t {
            return Err(crypto(format!("Threshold mismatch in legacy share {idx}")));
        }
        if idx != 0 && integrity != i {
            return Err(crypto(format!("Integrity mismatch in legacy share {idx}")));
        }
        threshold = t;
        integrity = i;
        let point = PointInFiniteField::from_string(&share[..x.len() + 1 + y.len()])
            .map_err(|_| invalid())?;
        points.push(point);
    }
    let words = InterpolationWords {
        zero_x: |i| format!("Zero x coordinate in legacy share {i}"),
        duplicate: "Duplicate legacy share detected, each must be unique.",
        too_few: |t| format!("At least {t} legacy shares are required to recover the private key"),
    };
    let failed = || crypto("Legacy integrity check failed");
    let key = interpolate(&points, threshold, words)?.ok_or_else(failed)?;
    if legacy_integrity(&key) != integrity {
        return Err(failed());
    }
    Ok(key)
}
