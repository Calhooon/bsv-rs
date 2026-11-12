//! Shamir Secret Sharing for private key backup and recovery: BRC-140.
//!
//! A private key is split into shares of which any `threshold` recover it
//! and fewer reveal nothing about it. The shares and their text are
//! BRC-140's (`key-derivation/0140.md` at `f7f1520`) and the reference's
//! (`ts-stack@edf6e03` `PrivateKey.ts`, `Polynomial.ts`), so a backup written
//! here is read by `@bsv/sdk` and go-sdk and theirs here (#854).
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::primitives::bsv::shamir::{split_private_key, KeyShares};
//! use bsv_rs::primitives::ec::PrivateKey;
//!
//! // Generate a random private key
//! let key = PrivateKey::random();
//!
//! // Split into 5 shares with threshold of 3
//! let shares = split_private_key(&key, 3, 5).unwrap();
//!
//! // Export to backup format
//! let backup = shares.to_backup_format().unwrap();
//! assert_eq!(backup.len(), 5);
//!
//! // Recover from any 3 shares
//! let subset = KeyShares::from_backup_format(&backup[0..3]).unwrap();
//! let recovered = subset.recover_private_key().unwrap();
//!
//! assert_eq!(key.to_bytes(), recovered.to_bytes());
//! ```
//!
//! # Backup Format
//!
//! Each share is serialized as: `base58(x).base58(y).threshold.integrity`
//!
//! - `base58(x)` and `base58(y)` are the point's coordinates, canonical
//!   base58 of their minimal big-endian bytes (`1` for zero)
//! - `threshold` is the minimum number of shares needed for recovery, 2 to 255
//! - `integrity` is the leading 8 hex digits of HASH160 of the compressed
//!   public key
//!
//! A backup written by bsv-rs 0.8.5 or earlier (a 4-character tag after the
//! last `.`) is refused by [`KeyShares::from_backup_format`]; it is
//! recovered by [`recover_private_key_from_legacy_backup`].
//!
//! A set is read with every share's x non-zero and distinct, in the whole
//! set and past the threshold window (#854): a share standing at x = 0
//! carries the secret in its own y, so the set can substitute another key
//! for the holder's, and a repeated x divides by zero in the interpolation.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
use crate::primitives::encoding::to_hex;
use crate::primitives::hash::sha512_hmac;
use crate::primitives::BigNumber;
use crate::primitives::PrivateKey;
use rand::rngs::OsRng;
use rand::RngCore;

#[path = "shamir_legacy.rs"]
mod legacy;
pub use legacy::recover_private_key_from_legacy_backup;

/// The most shares a collection holds and the largest threshold
/// (`MAX_SHAMIR_SHARES`, `ts-stack@edf6e03` `Polynomial.ts:7`).
const MAX_SHARES: usize = 255;
/// The longest share text, in UTF-16 code units (`PrivateKey.ts:12`).
const MAX_SHARE_LENGTH: usize = 256;
/// The attempts BRC-140 allows a share's coordinate (`PrivateKey.ts:525-527`).
const MAX_COORDINATE_ATTEMPTS: usize = 5;

/// A collection of key shares that can be used to recover a private key.
///
/// Contains the share points, the threshold needed for recovery, and the
/// BRC-140 integrity tag that verifies a recovery.
///
/// Its `Debug` shows the threshold, the share count and the integrity tag
/// (which every backup string carries), never a share's value;
/// [`to_backup_format`](Self::to_backup_format) is the explicit conversion.
#[derive(Clone)]
pub struct KeyShares {
    /// The share points (x, y coordinates in the finite field).
    pub points: Vec<PointInFiniteField>,
    /// The minimum number of shares needed for recovery.
    pub threshold: usize,
    /// The integrity tag: the leading 8 hex digits of HASH160 of the
    /// compressed public key.
    pub integrity: String,
}

impl std::fmt::Debug for KeyShares {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShares")
            .field("shares", &self.points.len())
            .field("threshold", &self.threshold)
            .field("integrity", &self.integrity)
            .finish_non_exhaustive()
    }
}

fn crypto(words: impl Into<String>) -> Error {
    Error::CryptoError(words.into())
}

/// `assertKeyShareCollection` (`ts-stack@edf6e03` `PrivateKey.ts:17-27`).
fn assert_collection(points: usize, threshold: usize, integrity: &str) -> Result<()> {
    if points == 0 || points > MAX_SHARES {
        return Err(crypto(format!(
            "shares must contain from 1 to {MAX_SHARES} entries"
        )));
    }
    if !(2..=MAX_SHARES).contains(&threshold) {
        return Err(crypto(format!(
            "threshold must be a safe integer from 2 to {MAX_SHARES}"
        )));
    }
    if !is_integrity(integrity) {
        return Err(crypto(
            "integrity must be an 8-character lowercase hexadecimal string",
        ));
    }
    Ok(())
}

/// `/^[1-9A-HJ-NP-Za-km-z]{1,64}$/` (`PrivateKey.ts:13`, `Polynomial.ts:9`).
pub(crate) fn is_base58_field(field: &str) -> bool {
    (1..=64).contains(&field.len())
        && field.bytes().all(|b| {
            matches!(b, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
        })
}

/// `/^(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/` (`PrivateKey.ts:14`): a
/// threshold of 2 to 255, no sign, no leading zero.
pub(crate) fn threshold_of(field: &str) -> Option<usize> {
    if field.is_empty() || field.len() > 3 || field.starts_with('0') {
        return None;
    }
    if !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let t: usize = field.parse().ok()?;
    (2..=MAX_SHARES).contains(&t).then_some(t)
}

/// `/^[0-9a-f]{8}$/` (`PrivateKey.ts:15`).
pub(crate) fn is_integrity(field: &str) -> bool {
    field.len() == 8
        && field
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A share's four fields, or `None` for any other count (bounded: at most
/// five are split off).
pub(crate) fn four_fields(share: &str) -> Option<[&str; 4]> {
    let mut parts = share.splitn(5, '.');
    let fields = [parts.next()?, parts.next()?, parts.next()?, parts.next()?];
    parts.next().is_none().then_some(fields)
}

/// The BRC-140 tag: `hex(HASH160(compressed public key))[0:8]`
/// (`PrivateKey.ts:535`).
fn integrity_of(key: &PrivateKey) -> String {
    to_hex(&key.public_key().hash160()[..4])
}

impl KeyShares {
    /// Creates a new KeyShares instance.
    ///
    /// # Arguments
    ///
    /// * `points` - The share points
    /// * `threshold` - The minimum number of shares needed for recovery
    /// * `integrity` - The integrity tag (8 lowercase hex digits)
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize, integrity: String) -> Self {
        Self {
            points,
            threshold,
            integrity,
        }
    }

    /// Parses BRC-140 backup shares, the reference's `KeyShares.fromBackupFormat`
    /// (`ts-stack@edf6e03` `PrivateKey.ts:55-102`), verdict for verdict and in
    /// its words.
    ///
    /// Each share is `x.y.threshold.integrity`: x and y canonical base58 of 1
    /// to 64 characters (the point read by [`PointInFiniteField::from_string`]),
    /// the threshold 2 to 255 with no sign or leading zero, the integrity 8
    /// lowercase hex digits.
    ///
    /// # Errors
    ///
    /// Every refusal names the share by its index, never its text:
    /// - no shares or more than 255: `shares must contain from 1 to 255 entries`
    /// - a share over 256 characters: `Invalid share format in share N`
    /// - other than four fields: `Invalid share format in share N. Expected format: "x.y.t.i"`
    /// - a field outside its grammar: `Invalid canonical share data in share N`
    /// - `Threshold mismatch in share N`, then `Integrity mismatch in share N`
    /// - a point that does not round-trip: the point's sentence
    /// - a share at x = 0 (#854): `Zero x coordinate in share N`
    /// - two shares with one x (#854): `Duplicate share detected, each must be unique.`
    ///
    /// A backup written by bsv-rs 0.8.5 or earlier carries a 4-character tag
    /// and is refused here as `Invalid canonical share data in share 0`;
    /// recover it with
    /// [`recover_private_key_from_legacy_backup`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::KeyShares;
    ///
    /// // BRC-140's example shares (key-derivation/0140.md)
    /// let backup = vec![
    ///     "45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3.2f804d43".to_string(),
    ///     "7aPzkiGZgvU4Jira5PN9Qf9o7FEg6uwy1zcxd17NBhh3.CCt7NH1sPFgceb6phTRkfviim2WvmUycJCQd2BxauxP9.3.2f804d43".to_string(),
    /// ];
    /// let shares = KeyShares::from_backup_format(&backup).unwrap();
    /// assert_eq!(shares.threshold, 3);
    /// assert!(shares.recover_private_key().is_err()); // two of three
    /// ```
    pub fn from_backup_format(shares: &[String]) -> Result<Self> {
        if shares.is_empty() || shares.len() > MAX_SHARES {
            return Err(crypto(format!(
                "shares must contain from 1 to {MAX_SHARES} entries"
            )));
        }
        let mut threshold = 0;
        let mut integrity = "";
        let mut points = Vec::with_capacity(shares.len());
        for (idx, share) in shares.iter().enumerate() {
            // JavaScript's `length`: UTF-16 code units, counted to the bound.
            if share.encode_utf16().take(MAX_SHARE_LENGTH + 1).count() > MAX_SHARE_LENGTH {
                return Err(crypto(format!("Invalid share format in share {idx}")));
            }
            let Some([x, y, t, i]) = four_fields(share) else {
                return Err(crypto(format!(
                    "Invalid share format in share {idx}. Expected format: \"x.y.t.i\""
                )));
            };
            let t = match threshold_of(t) {
                Some(t) if is_base58_field(x) && is_base58_field(y) && is_integrity(i) => t,
                _ => {
                    return Err(crypto(format!(
                        "Invalid canonical share data in share {idx}"
                    )))
                }
            };
            if idx != 0 && threshold != t {
                return Err(crypto(format!("Threshold mismatch in share {idx}")));
            }
            if idx != 0 && integrity != i {
                return Err(crypto(format!("Integrity mismatch in share {idx}")));
            }
            threshold = t;
            integrity = i;
            points.push(PointInFiniteField::from_string(
                &share[..x.len() + 1 + y.len()],
            )?);
        }
        // #854: the x values of the whole set, read before the collection is
        // built, so a set the door builds carries no share at x = 0 and no
        // repeated x
        refuse_degenerate_xs(&points, &InterpolationWords::BRC140)?;
        assert_collection(points.len(), threshold, integrity)?;
        Ok(Self {
            points,
            threshold,
            integrity: integrity.to_string(),
        })
    }

    /// Writes the shares as BRC-140 backup strings, the reference's
    /// `toBackupFormat` (`ts-stack@edf6e03` `PrivateKey.ts:104-118`).
    /// Reveals every share's value, which `Debug` redacts.
    ///
    /// # Errors
    ///
    /// Refuses, before any string, a state the reader refuses, in the
    /// reference's words: no points or more than 255 (`shares must contain
    /// from 1 to 255 entries`), a threshold outside 2 to 255 (`threshold must
    /// be a safe integer from 2 to 255`), an integrity other than 8 lowercase
    /// hex digits (`integrity must be an 8-character lowercase hexadecimal
    /// string`), a point whose text [`PointInFiniteField::from_string`]
    /// refuses (a coordinate at or above p set through the public fields: its
    /// sentence) or that does not read back as itself (`shares must contain
    /// canonical finite-field points`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::split_private_key;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let shares = split_private_key(&key, 2, 3).unwrap();
    /// let backup = shares.to_backup_format().unwrap();
    /// assert_eq!(backup.len(), 3);
    /// ```
    pub fn to_backup_format(&self) -> Result<Vec<String>> {
        assert_collection(self.points.len(), self.threshold, &self.integrity)?;
        self.points
            .iter()
            .map(|point| {
                let serialized = point.to_point_string();
                if PointInFiniteField::from_string(&serialized)?.to_point_string() != serialized {
                    return Err(crypto("shares must contain canonical finite-field points"));
                }
                Ok(format!(
                    "{serialized}.{}.{}",
                    self.threshold, self.integrity
                ))
            })
            .collect()
    }

    /// Recovers the private key, the reference's `PrivateKey.fromKeyShares`
    /// (`ts-stack@edf6e03` `PrivateKey.ts:575-623`): the collection checked
    /// as [`to_backup_format`](Self::to_backup_format) checks it, then
    /// `At least T shares are required to reconstruct the private key`, the
    /// leading `threshold` points' coordinates canonical (`share coordinates
    /// must be canonical field elements`), every share's x non-zero and
    /// distinct in the whole set (#854: `Zero x coordinate in share N`,
    /// `Duplicate share detected, each must be unique.`), the secret
    /// interpolated at x = 0 and read modulo the group order, and its tag
    /// compared (`Integrity hash mismatch`). Shares past the threshold are
    /// not interpolated, but their x values are read.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::split_private_key;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let shares = split_private_key(&key, 3, 5).unwrap();
    ///
    /// let recovered = shares.recover_private_key().unwrap();
    /// assert_eq!(key.to_bytes(), recovered.to_bytes());
    /// ```
    pub fn recover_private_key(&self) -> Result<PrivateKey> {
        assert_collection(self.points.len(), self.threshold, &self.integrity)?;
        let mismatch = || crypto("Integrity hash mismatch");
        // A secret of 0 mod n is no key: refused in the words the reference
        // gives it, and never returned (#854's fold).
        let key = interpolate(&self.points, self.threshold, InterpolationWords::BRC140)?
            .ok_or_else(mismatch)?;
        if integrity_of(&key) != self.integrity {
            return Err(mismatch());
        }
        Ok(key)
    }
}

/// The words of the interpolation's refusals, the reader's or the legacy
/// reader's.
pub(crate) struct InterpolationWords {
    pub(crate) zero_x: fn(usize) -> String,
    pub(crate) duplicate: &'static str,
    pub(crate) too_few: fn(usize) -> String,
}

impl InterpolationWords {
    const BRC140: Self = Self {
        zero_x: |i| format!("Zero x coordinate in share {i}"),
        duplicate: "Duplicate share detected, each must be unique.",
        too_few: |t| format!("At least {t} shares are required to reconstruct the private key"),
    };
}

/// The secret through the leading `threshold` points (`PrivateKey.ts:587-620`):
/// at least `threshold` points, the leading `threshold`'s coordinates each in
/// `[0, p)`, every x non-zero and distinct in the whole set (#854), `f(0)`
/// read modulo the group order `n` (the reference's
/// `new PrivateKey(..)`, `modN` `'apply'`). `None` when that is 0: no key,
/// which each caller refuses in its integrity words (`Integrity hash
/// mismatch`, the words of the recording; a key of 0 is never returned).
pub(crate) fn interpolate(
    points: &[PointInFiniteField],
    threshold: usize,
    words: InterpolationWords,
) -> Result<Option<PrivateKey>> {
    if points.len() < threshold {
        return Err(crypto((words.too_few)(threshold)));
    }
    let used = &points[..threshold];
    let p = BigNumber::secp256k1_prime();
    let canonical = |v: &BigNumber| !v.is_negative() && v.compare(&p).is_lt();
    if !used.iter().all(|pt| canonical(&pt.x) && canonical(&pt.y)) {
        return Err(crypto("share coordinates must be canonical field elements"));
    }
    refuse_degenerate_xs(points, &words)?;
    let secret = Polynomial::new(used.to_vec(), threshold)
        .value_at(&BigNumber::zero())
        .modulo(&BigNumber::secp256k1_order());
    if secret.is_zero() {
        return Ok(None);
    }
    PrivateKey::from_bytes(&secret.to_bytes_be(32)).map(Some)
}

/// Refuses the x values interpolation cannot judge, before it runs, in the
/// whole set and past the threshold window (#854): an x of zero, where a
/// share's y is the secret itself and the whole set can substitute another
/// key for the holder's, and a repeated x, where the Lagrange weights divide
/// by zero. A set split by [`split_private_key`] carries neither (its x is
/// drawn non-zero and distinct).
pub(crate) fn refuse_degenerate_xs(
    points: &[PointInFiniteField],
    words: &InterpolationWords,
) -> Result<()> {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(points.len());
    for (idx, point) in points.iter().enumerate() {
        if point.x.is_zero() {
            return Err(crypto((words.zero_x)(idx)));
        }
        if !seen.insert(point.x.to_bytes_be_min()) {
            return Err(crypto(words.duplicate));
        }
    }
    Ok(())
}

/// Splits a private key into BRC-140 shares, the reference's `toKeyShares`
/// (`ts-stack@edf6e03` `PrivateKey.ts:478-538`).
///
/// The secret is the constant term of a random polynomial of degree
/// `threshold - 1`; each share's x coordinate is drawn by BRC-140's
/// procedure (a 64-byte seed per split, `x = HMAC-SHA-512(seed, [i, attempt,
/// 32 fresh bytes]) mod p`, drawn again when 0 or already used, at most 5
/// attempts), so two splits of one key share no coordinate.
///
/// # Arguments
///
/// * `key` - The private key to split
/// * `threshold` - The minimum number of shares needed for recovery, 2 to 255
/// * `total` - The total number of shares to generate, `threshold` to 255
///
/// # Errors
///
/// In the reference's words, in its order: `threshold must be at least 2`,
/// `totalShares must be at least 2`, `threshold should be less than or equal
/// to totalShares`, `threshold and totalShares cannot exceed 255`.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::bsv::shamir::split_private_key;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
///
/// // Create 5 shares where any 3 can recover the key
/// let shares = split_private_key(&key, 3, 5).unwrap();
///
/// assert_eq!(shares.points.len(), 5);
/// assert_eq!(shares.threshold, 3);
/// ```
pub fn split_private_key(key: &PrivateKey, threshold: usize, total: usize) -> Result<KeyShares> {
    // a_1..a_{t-1}: random scalars, never zero (the `_with` form checks)
    let draws = 1..threshold.clamp(1, MAX_SHARES);
    let coefficients: Vec<[u8; 32]> = draws.map(|_| PrivateKey::random().to_bytes()).collect();
    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    let fresh = || {
        let mut draw = [0u8; 32];
        OsRng.fill_bytes(&mut draw);
        Some(draw)
    };
    split(key, threshold, total, &coefficients, &seed, fresh)
}

/// [`split_private_key`] with its draws given: the coefficients a_1..a_{t-1}
/// (each 32 bytes big-endian, reduced modulo p), the split's 64-byte HMAC
/// `seed` and the 32-byte draws of the coordinate procedure, one per attempt
/// in order (`total` of them unless an attempt is drawn again). The plain
/// form draws them and calls the same code, so the same draws give the same
/// shares (a reproducible seed corpus, bsv-rs#180). This crate's addition:
/// TS draws inside `toKeyShares`. Refuses as the plain form does, a
/// coefficient count other than `threshold - 1` as `InvalidDataLength` (in
/// bytes), a coefficient 0 modulo p as `CryptoError` (a zero top one lowers
/// the degree), and `draws` running out as `CryptoError`. Production code
/// uses [`split_private_key`]: the draws and one share give the key.
pub fn split_private_key_with(
    key: &PrivateKey,
    threshold: usize,
    total: usize,
    coefficients: &[[u8; 32]],
    seed: &[u8; 64],
    draws: &[[u8; 32]],
) -> Result<KeyShares> {
    let mut draws = draws.iter().copied();
    split(key, threshold, total, coefficients, seed, move || {
        draws.next()
    })
}

fn split(
    key: &PrivateKey,
    threshold: usize,
    total: usize,
    coefficients: &[[u8; 32]],
    seed: &[u8; 64],
    mut draw: impl FnMut() -> Option<[u8; 32]>,
) -> Result<KeyShares> {
    if threshold < 2 {
        return Err(crypto("threshold must be at least 2"));
    }
    if total < 2 {
        return Err(crypto("totalShares must be at least 2"));
    }
    if threshold > total {
        return Err(crypto(
            "threshold should be less than or equal to totalShares",
        ));
    }
    if threshold > MAX_SHARES || total > MAX_SHARES {
        return Err(crypto(format!(
            "threshold and totalShares cannot exceed {MAX_SHARES}"
        )));
    }

    let p = BigNumber::secp256k1_prime();
    if coefficients.len() != threshold - 1 {
        let (expected, actual) = (32 * (threshold - 1), 32 * coefficients.len());
        return Err(Error::InvalidDataLength { expected, actual });
    }
    // The constant term a_0 is the secret, then a_1..a_{t-1}
    let mut terms = vec![BigNumber::from_bytes_be(&key.to_bytes())];
    terms.extend(
        coefficients
            .iter()
            .map(|c| BigNumber::from_bytes_be(c).modulo(&p)),
    );
    if terms[1..].iter().any(BigNumber::is_zero) {
        return Err(crypto("Shamir coefficient is zero modulo p"));
    }

    let mut points: Vec<PointInFiniteField> = Vec::with_capacity(total);
    for i in 0..total {
        let x = coordinate(i, seed, &mut draw, &points, &p)?;
        let y = evaluate_polynomial(&terms, &x, &p);
        points.push(PointInFiniteField::new(x, y));
    }

    Ok(KeyShares {
        points,
        threshold,
        integrity: integrity_of(key),
    })
}

/// Share `i`'s x coordinate by BRC-140's procedure (`PrivateKey.ts:513-531`):
/// `HMAC-SHA-512(seed, [i, attempt, r_0..r_31]) mod p`, drawn again when 0 or
/// already used; the attempt after the fifth refused before its value is
/// judged, as the reference's loop refuses it.
fn coordinate(
    i: usize,
    seed: &[u8; 64],
    draw: &mut impl FnMut() -> Option<[u8; 32]>,
    used: &[PointInFiniteField],
    p: &BigNumber,
) -> Result<BigNumber> {
    // i < 255 and the attempt <= 5: each one byte, as the reference's array
    let index = u8::try_from(i).map_err(|_| crypto("share index exceeds 255"))?;
    let mut attempt = 0u8;
    loop {
        let fresh = draw().ok_or_else(|| crypto("Shamir coordinate draws exhausted"))?;
        let mut counter = Vec::with_capacity(34);
        counter.extend_from_slice(&[index, attempt]);
        counter.extend_from_slice(&fresh);
        let x = BigNumber::from_bytes_be(&sha512_hmac(seed, &counter)).modulo(p);
        attempt += 1;
        if usize::from(attempt) > MAX_COORDINATE_ATTEMPTS {
            return Err(crypto(
                "Failed to generate unique x coordinate after 5 attempts",
            ));
        }
        if !x.is_zero() && !used.iter().any(|pt| pt.x == x) {
            return Ok(x);
        }
    }
}

/// Evaluates a polynomial at a given point.
///
/// Given coefficients [a_0, a_1, ..., a_{n-1}], computes:
/// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{n-1}*x^{n-1}
///
/// Uses Horner's method for efficiency.
fn evaluate_polynomial(
    coefficients: &[BigNumber],
    x: &BigNumber,
    modulus: &BigNumber,
) -> BigNumber {
    // Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_{n-1}))
    let mut result = BigNumber::zero();

    for coeff in coefficients.iter().rev() {
        result = result.mul(x).add(coeff).modulo(modulus);
    }

    result
}

#[cfg(test)]
#[path = "shamir_tests.rs"]
mod tests;
