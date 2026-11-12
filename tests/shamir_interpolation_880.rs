//! Shamir recovery interpolates with one modular inverse for the whole set
//! (#880), where it took one per pair of shares, and no answer moves: the
//! pairwise loop `Polynomial::value_at` ran until #880 (the reference's
//! `valueAt`, `ts-stack@edf6e03` `Polynomial.ts:120-136`) is kept here as the
//! oracle, and every key and every refusal the crate answers is compared with
//! the answer the oracle's field value gives through the same steps.
//!
//! The differential's 10,000 sets (set `k`, seeded by `k` alone):
//! - `k % 10 == 0` (1,000): the legacy door, x = 1, 2, ..., n and the old
//!   tag; four in five honest, the fifth a refusal in rotation (too few, a
//!   wrong tag, a repeated share, a share at x = 0); thresholds 2 to 6, and
//!   255 of 255 once.
//! - else `k % 4 == 3` (2,500): one refusal class of twelve in rotation, the
//!   x classes alternately as backup strings (the reader) and through the
//!   public fields (the recovery door).
//! - else (6,500): honest, read through `from_backup_format` and recovered,
//!   the shares rotated and, one time in two, cut to the threshold.
//! - thresholds: 2 to 6 in rotation; where `k % 100` is 97 (honest sets) or
//!   99 (refusal sets), one of 7 to 32 in rotation (100 sets each way, every
//!   threshold three times at least); and 64 of 64, 128 of 128, 254 of 255
//!   and 255 of 255 once each, honest. The share count is the threshold plus
//!   `k % 3`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::time::{Duration, Instant};

use bsv_rs::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
use bsv_rs::primitives::bsv::shamir::{
    recover_private_key_from_legacy_backup, split_private_key, split_private_key_with, KeyShares,
};
use bsv_rs::primitives::encoding::{to_base58, to_hex};
use bsv_rs::primitives::{sha256, BigNumber, PrivateKey};
use bsv_rs::Error;

/// SHA-256 over the 10,000 answers of the differential, in order: the same on
/// the base (`3e1ade84`, the pairwise interpolation) and on the tip.
const ANSWERS_DIGEST: &str = "347d8607aeb7840404e7e85a13f2c543658b13d482b59b51b1361f044936ef48";

// ---------------------------------------------------------------------------
// The oracle: `Polynomial::value_at` as it stood before #880
// (`src/primitives/bsv/polynomial.rs:259-297` at `3e1ade84`), one inverse per
// ordered pair, over `BigNumber`'s public methods.
// ---------------------------------------------------------------------------

fn oracle_value_at(points: &[PointInFiniteField], threshold: usize, x: &BigNumber) -> BigNumber {
    let p = BigNumber::secp256k1_prime();
    let mut y = BigNumber::zero();
    let num_points = std::cmp::min(points.len(), threshold);
    for i in 0..num_points {
        let mut term = points[i].y.clone();
        for j in 0..num_points {
            if i != j {
                let numerator = x.sub(&points[j].x).modulo(&p);
                let denominator = points[i].x.sub(&points[j].x).modulo(&p);
                let denominator_inv = denominator.mod_inverse(&p).unwrap_or_else(BigNumber::zero);
                let fraction = numerator.mul(&denominator_inv).modulo(&p);
                term = term.mul(&fraction).modulo(&p);
            }
        }
        y = y.add(&term).modulo(&p);
    }
    y
}

// ---------------------------------------------------------------------------
// The steps around the field value, as `shamir.rs` and `shamir_legacy.rs`
// take them, with the oracle's value in place of `value_at`'s.
// ---------------------------------------------------------------------------

type Answer = Result<[u8; 32], String>;

fn refusal(words: impl Into<String>) -> String {
    Error::CryptoError(words.into()).to_string()
}

struct Words {
    zero_x: fn(usize) -> String,
    duplicate: &'static str,
    too_few: fn(usize) -> String,
    mismatch: &'static str,
}

const BRC140: Words = Words {
    zero_x: |i| format!("Zero x coordinate in share {i}"),
    duplicate: "Duplicate share detected, each must be unique.",
    too_few: |t| format!("At least {t} shares are required to reconstruct the private key"),
    mismatch: "Integrity hash mismatch",
};

const LEGACY: Words = Words {
    zero_x: |i| format!("Zero x coordinate in legacy share {i}"),
    duplicate: "Duplicate legacy share detected, each must be unique.",
    too_few: |t| format!("At least {t} legacy shares are required to recover the private key"),
    mismatch: "Legacy integrity check failed",
};

/// `interpolate` (`shamir.rs:382-404`) over the oracle; `None` for a secret
/// of 0 modulo n.
fn oracle_interpolate(
    points: &[PointInFiniteField],
    threshold: usize,
    words: &Words,
) -> Result<Option<[u8; 32]>, String> {
    if points.len() < threshold {
        return Err(refusal((words.too_few)(threshold)));
    }
    let used = &points[..threshold];
    let p = BigNumber::secp256k1_prime();
    let canonical = |v: &BigNumber| !v.is_negative() && v.compare(&p).is_lt();
    if !used.iter().all(|pt| canonical(&pt.x) && canonical(&pt.y)) {
        return Err(refusal(
            "share coordinates must be canonical field elements",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for (idx, point) in points.iter().enumerate() {
        if point.x.is_zero() {
            return Err(refusal((words.zero_x)(idx)));
        }
        if !seen.insert(point.x.to_bytes_be_min()) {
            return Err(refusal(words.duplicate));
        }
    }
    let secret =
        oracle_value_at(used, threshold, &BigNumber::zero()).modulo(&BigNumber::secp256k1_order());
    if secret.is_zero() {
        return Ok(None);
    }
    Ok(Some(secret.to_bytes_be(32).try_into().unwrap()))
}

fn brc140_tag(key: &[u8; 32]) -> String {
    let key = PrivateKey::from_bytes(key).unwrap();
    to_hex(&key.public_key().hash160()[..4])
}

fn legacy_tag(key: &[u8; 32]) -> String {
    to_base58(&sha256(key)).chars().take(4).collect()
}

/// `KeyShares::recover_private_key` (`shamir.rs:345-356`) over the oracle.
fn oracle_recover(shares: &KeyShares) -> Answer {
    if shares.points.is_empty() || shares.points.len() > 255 {
        return Err(refusal("shares must contain from 1 to 255 entries"));
    }
    if !(2..=255).contains(&shares.threshold) {
        return Err(refusal("threshold must be a safe integer from 2 to 255"));
    }
    let tag = &shares.integrity;
    if tag.len() != 8 || !tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refusal(
            "integrity must be an 8-character lowercase hexadecimal string",
        ));
    }
    let key = oracle_interpolate(&shares.points, shares.threshold, &BRC140)?
        .ok_or_else(|| refusal(BRC140.mismatch))?;
    if brc140_tag(&key) != shares.integrity {
        return Err(refusal(BRC140.mismatch));
    }
    Ok(key)
}

/// `recover_private_key_from_legacy_backup` (`shamir_legacy.rs:99-150`) over
/// the oracle, for shares whose text is well formed (every legacy set here).
fn oracle_recover_legacy(shares: &[String]) -> Answer {
    let mut points = Vec::new();
    let (mut threshold, mut tag) = (0usize, "");
    for share in shares {
        let fields: Vec<&str> = share.split('.').collect();
        assert_eq!(fields.len(), 4, "a legacy set here is well formed");
        points.push(
            PointInFiniteField::from_string(&format!("{}.{}", fields[0], fields[1])).unwrap(),
        );
        threshold = fields[2].parse().unwrap();
        tag = fields[3];
    }
    let key =
        oracle_interpolate(&points, threshold, &LEGACY)?.ok_or_else(|| refusal(LEGACY.mismatch))?;
    if legacy_tag(&key) != tag {
        return Err(refusal(LEGACY.mismatch));
    }
    Ok(key)
}

fn answer_of(result: bsv_rs::Result<PrivateKey>) -> Answer {
    result.map(|key| key.to_bytes()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Seeded material
// ---------------------------------------------------------------------------

/// 32 bytes of set `k`'s stream `label`, item `i`.
fn draw(k: u64, label: u8, i: u64) -> [u8; 32] {
    let mut input = b"shamir_interpolation_880".to_vec();
    input.extend_from_slice(&k.to_be_bytes());
    input.push(label);
    input.extend_from_slice(&i.to_be_bytes());
    sha256(&input)
}

fn seeded_key(k: u64) -> PrivateKey {
    (0..)
        .find_map(|i| PrivateKey::from_bytes(&draw(k, b'k', i)).ok())
        .unwrap()
}

fn seeded_coefficients(k: u64, threshold: usize) -> Vec<[u8; 32]> {
    (0..threshold as u64 - 1)
        .map(|i| draw(k, b'c', i))
        .collect()
}

/// This crate's own split of `key`, every draw seeded by `k`.
fn seeded_split(k: u64, key: &PrivateKey, threshold: usize, total: usize) -> KeyShares {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&draw(k, b's', 0));
    seed[32..].copy_from_slice(&draw(k, b's', 1));
    // Five draws a share: more than the coordinate procedure can ask for.
    let draws: Vec<[u8; 32]> = (0..5 * total as u64).map(|i| draw(k, b'd', i)).collect();
    let coefficients = seeded_coefficients(k, threshold);
    split_private_key_with(key, threshold, total, &coefficients, &seed, &draws).unwrap()
}

/// `a_0 + a_1 x + ...` modulo p, by Horner.
fn evaluate(terms: &[BigNumber], x: &BigNumber) -> BigNumber {
    let p = BigNumber::secp256k1_prime();
    let mut y = BigNumber::zero();
    for term in terms.iter().rev() {
        y = y.mul(x).add(term).modulo(&p);
    }
    y
}

/// The points of the polynomial whose constant term is `constant` and whose
/// other coefficients are set `k`'s, at the given x values.
fn points_through(
    k: u64,
    constant: &BigNumber,
    threshold: usize,
    xs: &[BigNumber],
) -> Vec<PointInFiniteField> {
    let p = BigNumber::secp256k1_prime();
    let mut terms = vec![constant.clone()];
    for c in seeded_coefficients(k, threshold) {
        terms.push(BigNumber::from_bytes_be(&c).modulo(&p));
    }
    xs.iter()
        .map(|x| PointInFiniteField::new(x.clone(), evaluate(&terms, x)))
        .collect()
}

fn field_text(value: &BigNumber) -> String {
    let bytes = value.to_bytes_be_min();
    if bytes.is_empty() {
        "1".to_string()
    } else {
        to_base58(&bytes)
    }
}

/// A legacy backup of `key`: x = 1, 2, ..., `total`, the old 4-character tag.
fn legacy_backup(k: u64, key: &PrivateKey, threshold: usize, total: usize) -> Vec<String> {
    let xs: Vec<BigNumber> = (1..=total as u64).map(BigNumber::from_u64).collect();
    let constant = BigNumber::from_bytes_be(&key.to_bytes());
    let tag = legacy_tag(&key.to_bytes());
    points_through(k, &constant, threshold, &xs)
        .iter()
        .map(|pt| format!("{}.{threshold}.{tag}", pt.to_point_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// One set of the differential
// ---------------------------------------------------------------------------

/// Set `k`'s threshold and share count.
fn shape_of(k: u64) -> (usize, usize) {
    match k {
        1_001 => (64, 64),
        2_002 => (128, 128),
        3_005 => (254, 255),
        4_006 => (255, 255),
        5_000 => (255, 255), // the legacy door at its bound
        _ => {
            let threshold = if matches!(k % 100, 97 | 99) {
                7 + (k / 100 % 26) as usize
            } else {
                2 + (k % 5) as usize
            };
            (threshold, threshold + (k % 3) as usize)
        }
    }
}

/// What set `k` asserts beside the equality: that its class was reached.
enum Expect {
    Key,
    Words(&'static str),
}

/// Runs set `k` through the crate and through the oracle's steps.
fn run_set(k: u64) -> (Answer, Answer, Expect) {
    let (threshold, total) = shape_of(k);
    let key = seeded_key(k);
    if k.is_multiple_of(10) {
        return legacy_set(k, &key, threshold, total);
    }
    let large = threshold > 32;
    if k % 4 == 3 && !large {
        return refusal_set(k, &key, threshold, total);
    }
    // Honest: this crate's split and writer, read and recovered.
    let mut backup = seeded_split(k, &key, threshold, total)
        .to_backup_format()
        .unwrap();
    backup.rotate_left(k as usize % total);
    if k.is_multiple_of(2) {
        backup.truncate(threshold);
    }
    let read = KeyShares::from_backup_format(&backup).unwrap();
    let got = answer_of(read.recover_private_key());
    assert_eq!(got, Ok(key.to_bytes()), "set {k}: an honest set recovers");
    (got, oracle_recover(&read), Expect::Key)
}

fn legacy_set(
    k: u64,
    key: &PrivateKey,
    threshold: usize,
    total: usize,
) -> (Answer, Answer, Expect) {
    let mut backup = legacy_backup(k, key, threshold, total);
    backup.rotate_left(k as usize % total);
    let mut expect = Expect::Key;
    if k % 50 == 10 {
        match k / 50 % 4 {
            0 => {
                backup.truncate(threshold - 1);
                expect = Expect::Words("legacy shares are required");
            }
            1 => {
                let other = legacy_tag(&seeded_key(k + 1).to_bytes());
                for share in &mut backup {
                    let cut = share.rfind('.').unwrap();
                    share.replace_range(cut + 1.., &other);
                }
                expect = Expect::Words("Legacy integrity check failed");
            }
            2 => {
                backup.push(backup[0].clone());
                expect = Expect::Words("Duplicate legacy share detected");
            }
            _ => {
                let at = k as usize % backup.len();
                let cut = backup[at].find('.').unwrap();
                backup[at].replace_range(..cut, "1");
                expect = Expect::Words("Zero x coordinate in legacy share");
            }
        }
    }
    let got = answer_of(recover_private_key_from_legacy_backup(&backup));
    (got, oracle_recover_legacy(&backup), expect)
}

/// The twelve refusal classes, `(k / 4) % 12`.
fn refusal_set(
    k: u64,
    key: &PrivateKey,
    threshold: usize,
    total: usize,
) -> (Answer, Answer, Expect) {
    let class = k / 4 % 12;
    // The classes that need a share past the window get one.
    let total = if matches!(class, 3 | 5) {
        total.max(threshold + 1)
    } else {
        total
    };
    let shares = seeded_split(k, key, threshold, total);
    let p = BigNumber::secp256k1_prime();
    let n = BigNumber::secp256k1_order();
    // The x classes alternate between the reader (backup strings) and the
    // recovery door (the public fields).
    let as_strings = (k / 48).is_multiple_of(2);
    let inside = 1 + k as usize % (threshold - 1); // in 1..threshold
    let past = threshold + k as usize % (total - threshold).max(1);

    let both = |built: KeyShares, expect: &'static str| {
        let got = answer_of(built.recover_private_key());
        (got, oracle_recover(&built), Expect::Words(expect))
    };
    // Through the reader: its refusal is the answer on both sides (the
    // reader runs no interpolation), and a set it reads goes on to recovery.
    let read =
        |backup: Vec<String>, expect: &'static str| match KeyShares::from_backup_format(&backup) {
            Err(e) => (
                Err(e.to_string()),
                Err(e.to_string()),
                Expect::Words(expect),
            ),
            Ok(read) => both(read, expect),
        };
    let with_x = |at: usize, x: BigNumber, expect: &'static str| {
        if as_strings {
            let mut backup = shares.to_backup_format().unwrap();
            let cut = backup[at].find('.').unwrap();
            backup[at].replace_range(..cut, &field_text(&x));
            read(backup, expect)
        } else {
            let mut built = shares.clone();
            built.points[at].x = x;
            both(built, expect)
        }
    };

    match class {
        0 => {
            let mut backup = shares.to_backup_format().unwrap();
            backup.truncate(threshold - 1);
            read(backup, "shares are required to reconstruct")
        }
        1 => with_x(0, BigNumber::zero(), "Zero x coordinate in share 0"),
        2 => with_x(inside, BigNumber::zero(), "Zero x coordinate in share"),
        3 => with_x(past, BigNumber::zero(), "Zero x coordinate in share"),
        4 => with_x(
            inside,
            shares.points[0].x.clone(),
            "Duplicate share detected",
        ),
        5 => with_x(past, shares.points[0].x.clone(), "Duplicate share detected"),
        6 => {
            // A coordinate outside [0, p), through the fields.
            let mut built = shares.clone();
            let point = &mut built.points[inside - 1];
            match k / 48 % 3 {
                0 => point.x = point.x.add(&p),
                1 => point.y = point.y.add(&p),
                _ => point.y = point.y.sub(&p),
            }
            both(built, "share coordinates must be canonical field elements")
        }
        7 => {
            let mut backup = shares.to_backup_format().unwrap();
            let other = if threshold == 2 { 3 } else { threshold - 1 };
            let tag = shares.integrity.clone();
            let at = backup.len() - 1;
            let point = shares.points[at].to_point_string();
            backup[at] = format!("{point}.{other}.{tag}");
            read(backup, "Threshold mismatch in share")
        }
        8 => {
            let mut backup = shares.to_backup_format().unwrap();
            let at = backup.len() - 1;
            let cut = backup[at].rfind('.').unwrap();
            let other = brc140_tag(&seeded_key(k + 1).to_bytes());
            backup[at].replace_range(cut + 1.., &other);
            read(backup, "Integrity mismatch in share")
        }
        9 => {
            // Every share carries another key's tag: the interpolation runs.
            let mut built = shares.clone();
            built.integrity = brc140_tag(&seeded_key(k + 1).to_bytes());
            read(built.to_backup_format().unwrap(), "Integrity hash mismatch")
        }
        10 => {
            // f(0) is 0 modulo n (0 itself, or n, which is below p): no key.
            let constant = if (k / 48).is_multiple_of(2) {
                BigNumber::zero()
            } else {
                n
            };
            let xs: Vec<BigNumber> = shares.points.iter().map(|pt| pt.x.clone()).collect();
            let points = points_through(k, &constant, threshold, &xs);
            both(
                KeyShares::new(points, threshold, shares.integrity.clone()),
                "Integrity hash mismatch",
            )
        }
        _ => {
            // f(0) in [n, p): read modulo n, a key, its tag the reduced key's.
            let span = p.sub(&n);
            let offset = BigNumber::from_bytes_be(&draw(k, b'o', 0))
                .modulo(&span.sub(&BigNumber::one()))
                .add(&BigNumber::one()); // in [1, p - n)
            let xs: Vec<BigNumber> = shares.points.iter().map(|pt| pt.x.clone()).collect();
            let points = points_through(k, &n.add(&offset), threshold, &xs);
            let reduced: [u8; 32] = offset.to_bytes_be(32).try_into().unwrap();
            let built = KeyShares::new(points, threshold, brc140_tag(&reduced));
            let got = answer_of(built.recover_private_key());
            assert_eq!(got, Ok(reduced), "set {k}: f(0) in [n, p) is read modulo n");
            (got, oracle_recover(&built), Expect::Key)
        }
    }
}

/// The digest's bytes of one answer.
fn record(log: &mut Vec<u8>, answer: &Answer) {
    match answer {
        Ok(key) => {
            log.push(0);
            log.extend_from_slice(key);
        }
        Err(words) => {
            log.push(1);
            log.extend_from_slice(&(words.len() as u32).to_be_bytes());
            log.extend_from_slice(words.as_bytes());
        }
    }
}

#[test]
fn the_batched_interpolation_answers_as_the_pairwise_one_on_10000_sets_880() {
    let mut log = Vec::new();
    let (mut keys, mut refusals) = (0, 0);
    for k in 0..10_000u64 {
        let (got, oracle, expect) = run_set(k);
        assert_eq!(got, oracle, "set {k}: the crate's answer and the oracle's");
        match (&got, expect) {
            (Ok(_), Expect::Key) => keys += 1,
            (Err(words), Expect::Words(class)) => {
                assert!(words.contains(class), "set {k}: {words:?} is not {class:?}");
                refusals += 1;
            }
            (Ok(_), Expect::Words(class)) => panic!("set {k}: a key where {class:?} was due"),
            (Err(words), Expect::Key) => panic!("set {k}: {words:?} where a key was due"),
        }
        record(&mut log, &got);
    }
    println!("880 differential: {keys} keys, {refusals} refusals");
    assert_eq!(keys + refusals, 10_000);
    assert_eq!(to_hex(&sha256(&log)), ANSWERS_DIGEST);
}

// ---------------------------------------------------------------------------
// The public door: `Polynomial::value_at` on hand-built points
// ---------------------------------------------------------------------------

fn point(x: BigNumber, y: BigNumber) -> PointInFiniteField {
    // Through the fields: `new` would reduce the coordinates.
    PointInFiniteField { x, y }
}

fn assert_value(points: Vec<PointInFiniteField>, threshold: usize, x: &BigNumber, cell: &str) {
    let want = oracle_value_at(&points, threshold, x);
    let got = Polynomial::new(points, threshold).value_at(x);
    assert_eq!(got, want, "{cell}");
}

#[test]
fn value_at_answers_as_the_pairwise_one_on_hand_built_points_880() {
    let p = BigNumber::secp256k1_prime();
    let n = |v: u64| BigNumber::from_u64(v);
    let zero = BigNumber::zero();

    // The oracle anchored: f(x) = 3x + 5 through (1, 8) and (2, 11).
    let line = vec![point(n(1), n(8)), point(n(2), n(11))];
    assert_eq!(oracle_value_at(&line, 2, &zero), n(5));
    assert_eq!(Polynomial::new(line.clone(), 2).value_at(&zero), n(5));
    assert_eq!(Polynomial::new(line.clone(), 2).value_at(&n(7)), n(26));

    // Thresholds 0 and 1, and no points at all.
    assert_eq!(Polynomial::new(line.clone(), 0).value_at(&zero), zero);
    assert_eq!(Polynomial::new(vec![], 3).value_at(&zero), zero);
    assert_eq!(Polynomial::new(line.clone(), 1).value_at(&n(9)), n(8));
    let unreduced = vec![point(n(1), p.add(&n(4))), point(n(2), n(11))];
    assert_eq!(Polynomial::new(unreduced, 1).value_at(&zero), n(4));
    let negative = vec![point(n(1), BigNumber::from_i64(-4))];
    assert_eq!(Polynomial::new(negative, 1).value_at(&zero), p.sub(&n(4)));

    // A repeated x among the points used: both terms 0, the third's kept.
    let repeated = vec![point(n(3), n(10)), point(n(3), n(20)), point(n(5), n(30))];
    assert_value(repeated.clone(), 3, &zero, "a repeated x, at 0");
    assert_value(repeated.clone(), 3, &n(4), "a repeated x, at 4");
    assert_value(repeated.clone(), 2, &zero, "every x repeated");
    assert_eq!(Polynomial::new(repeated, 2).value_at(&zero), zero);
    // The same x in two representatives (3 and p + 3) is a repeat too.
    let aliased = vec![
        point(n(3), n(10)),
        point(p.add(&n(3)), n(20)),
        point(n(5), n(30)),
    ];
    assert_value(aliased, 3, &zero, "a repeated x modulo p");

    // Seeded cells: 2,000 small point lists with every departure mixed in.
    for k in 0..2_000u64 {
        let count = (k % 7) as usize; // 0 to 6 points
        let threshold = (k / 7 % 9) as usize; // 0 to 8: short lists and long
        let mut points: Vec<PointInFiniteField> = (0..count as u64)
            .map(|i| {
                point(
                    BigNumber::from_bytes_be(&draw(k, b'x', i)).modulo(&p),
                    BigNumber::from_bytes_be(&draw(k, b'y', i)).modulo(&p),
                )
            })
            .collect();
        let pick = |i: u64| draw(k, b'p', i)[0] as usize;
        if count >= 2 {
            let (a, b) = (pick(0) % count, pick(1) % count);
            match k % 6 {
                0 if a != b => points[a].x = points[b].x.clone(),
                1 if a != b => points[a].x = points[b].x.add(&p),
                2 => points[a].x = points[a].x.add(&p).add(&p),
                3 => points[a].y = points[a].y.sub(&p).sub(&p),
                4 => points[a].x = points[a].x.sub(&p),
                _ => {}
            }
        }
        let x = match k % 5 {
            0 => zero.clone(),
            1 => BigNumber::from_bytes_be(&draw(k, b'e', 0)), // may pass p
            2 if count > 0 => points[pick(2) % count].x.clone(), // a point's own x
            3 => BigNumber::from_i64(-(k as i64) - 1),
            _ => p.add(&n(k)),
        };
        assert_value(points, threshold, &x, &format!("seeded cell {k}"));
    }
}

// ---------------------------------------------------------------------------
// The cost (#880): RED on the pairwise interpolation, where the two take the
// same time.
// ---------------------------------------------------------------------------

fn least_of_three(mut run: impl FnMut()) -> Duration {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed()
        })
        .min()
        .unwrap()
}

#[test]
fn recovery_at_128_of_128_costs_a_fraction_of_the_pairwise_oracle_880() {
    let key = seeded_key(880);
    let shares = seeded_split(880, &key, 128, 128);
    let zero = BigNumber::zero();
    let polynomial = Polynomial::new(shares.points.clone(), 128);
    let mut values = Vec::new();
    let batched = least_of_three(|| values.push(polynomial.value_at(&zero)));
    let pairwise = least_of_three(|| values.push(oracle_value_at(&shares.points, 128, &zero)));
    assert!(values.iter().all(|v| v.to_bytes_be(32) == key.to_bytes()));
    println!("880 cost at 128 of 128: value_at {batched:?}, the pairwise oracle {pairwise:?}");
    assert!(
        pairwise >= batched * 5,
        "value_at took {batched:?} where the pairwise oracle took {pairwise:?}: \
         one inverse per pair of shares again (#880)?"
    );
}

// ---------------------------------------------------------------------------
// By hand, release
// ---------------------------------------------------------------------------

/// Every threshold, t of t, honest. `SHAMIR_880_RANGE=a-b` runs a piece;
/// each piece prints its own digest (the lane record carries them).
/// `cargo test --release --test shamir_interpolation_880 every_threshold -- --ignored --nocapture`
#[test]
#[ignore = "release, by hand, in pieces: SHAMIR_880_RANGE=a-b"]
fn every_threshold_from_2_to_255_answers_as_the_pairwise_one_880() {
    let range = std::env::var("SHAMIR_880_RANGE").unwrap_or_else(|_| "2-255".to_string());
    let (from, to) = range.split_once('-').unwrap();
    let (from, to): (usize, usize) = (from.parse().unwrap(), to.parse().unwrap());
    assert!(2 <= from && from <= to && to <= 255);
    let mut log = Vec::new();
    for threshold in from..=to {
        let k = 880_000 + threshold as u64;
        let key = seeded_key(k);
        let backup = seeded_split(k, &key, threshold, threshold)
            .to_backup_format()
            .unwrap();
        let read = KeyShares::from_backup_format(&backup).unwrap();
        let got = answer_of(read.recover_private_key());
        assert_eq!(got, Ok(key.to_bytes()), "{threshold} of {threshold}");
        assert_eq!(got, oracle_recover(&read), "{threshold} of {threshold}");
        record(&mut log, &got);
    }
    println!(
        "880 every threshold {from}-{to}: {} sets, sha256 {}",
        to - from + 1,
        to_hex(&sha256(&log))
    );
}

/// The CHANGELOG's figures: the median of five timings of each row.
/// `cargo test --release --test shamir_interpolation_880 figures -- --ignored --nocapture`
#[test]
#[ignore = "release, by hand: prints the figures of the CHANGELOG's table"]
fn figures_880() {
    fn median_of_five(iterations: u32, mut run: impl FnMut()) -> Duration {
        let mut timings: Vec<Duration> = (0..5)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..iterations {
                    run();
                }
                start.elapsed() / iterations
            })
            .collect();
        timings.sort();
        timings[2]
    }
    let key = seeded_key(881);
    for (threshold, total, iterations) in
        [(255, 255, 1), (10, 20, 200), (2, 3, 2_000), (3, 5, 2_000)]
    {
        let backup = seeded_split(881, &key, threshold, total)
            .to_backup_format()
            .unwrap();
        let subset = &backup[..threshold];
        let time = median_of_five(iterations, || {
            let read = KeyShares::from_backup_format(subset).unwrap();
            assert_eq!(
                read.recover_private_key().unwrap().to_bytes(),
                key.to_bytes()
            );
        });
        println!("880 figure: read and recover {threshold} of {total}: {time:?}");
    }
    let time = median_of_five(2_000, || {
        split_private_key(&key, 3, 5).unwrap();
    });
    println!("880 figure: split 3 of 5: {time:?}");
    for (threshold, total, iterations) in [(3, 5, 2_000), (255, 255, 1)] {
        let backup = legacy_backup(881, &key, threshold, total);
        let subset = &backup[..threshold];
        let time = median_of_five(iterations, || {
            let recovered = recover_private_key_from_legacy_backup(subset).unwrap();
            assert_eq!(recovered.to_bytes(), key.to_bytes());
        });
        println!("880 figure: legacy read and recover {threshold} of {total}: {time:?}");
    }
}
