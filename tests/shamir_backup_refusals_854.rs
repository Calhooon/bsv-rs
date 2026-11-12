//! The Shamir backup doors refuse a share set that would substitute the
//! recovered key for the holder's (#854): a share whose x is zero (the
//! base58 `1`, or the field prime as a non-canonical zero), any coordinate at
//! or above the field prime, a duplicate x, and a non-canonical or overlong
//! coordinate field — at `KeyShares::from_backup_format` and at
//! `KeyShares::recover_private_key` (a hand-built set), before interpolating;
//! the legacy door, `recover_private_key_from_legacy_backup`, through the same
//! scans. Every refusal cell is paired with honest controls built by this
//! crate's own writer, at several thresholds and in several orders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::time::Instant;

use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
use bsv_rs::primitives::bsv::shamir::{
    recover_private_key_from_legacy_backup, split_private_key, split_private_key_with, KeyShares,
};
use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::{sha256, BigNumber, PrivateKey};

/// A fixed key, so every cell is deterministic.
fn fixed_key() -> PrivateKey {
    PrivateKey::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .unwrap()
}

/// The canonical base58 text of a coordinate: its minimal bytes, `1` for zero.
fn field_text(value: &BigNumber) -> String {
    let bytes = value.to_bytes_be_min();
    if bytes.is_empty() {
        "1".to_string()
    } else {
        to_base58(&bytes)
    }
}

/// Splits `key` with fixed coefficients, seed and draws, so every cell is
/// deterministic.
fn deterministic_split(key: &PrivateKey, threshold: usize, total: usize) -> KeyShares {
    let coefficients: Vec<[u8; 32]> = (0..threshold - 1).map(|i| [0x42 + i as u8; 32]).collect();
    let draws: Vec<[u8; 32]> = (0..total).map(|i| [0xa0 + i as u8; 32]).collect();
    split_private_key_with(key, threshold, total, &coefficients, &[0x5e; 64], &draws).unwrap()
}

/// The legacy door's tag of a key: the first 4 characters of
/// base58(sha256(key bytes)).
fn legacy_tag(key: &PrivateKey) -> String {
    to_base58(&sha256(&key.to_bytes()))
        .chars()
        .take(4)
        .collect()
}

/// A two-share set for the backup door: the first share with the given x
/// field and y = `attacker`'s own key, the second an honest share of the
/// attacker's split (threshold 2 of 3, so every threshold and integrity tag
/// in the set agrees).
fn set_with_x_field(attacker: &PrivateKey, x_field: &str) -> Vec<String> {
    let shares = deterministic_split(attacker, 2, 3);
    let backup = shares.to_backup_format().unwrap();
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let forged = format!(
        "{}.{}.2.{}",
        x_field,
        field_text(&key_value),
        shares.integrity
    );
    vec![forged, backup[1].clone()]
}

/// A two-share legacy set: the first share standing at `x_field` with y =
/// `attacker`'s own key, the second a share at x = 1 whose y is immaterial
/// (through a share at x = 0 the interpolation answers that share's y
/// alone), the tag the attacker's own on both, so the recovery succeeds and
/// answers the attacker's key where the door allows it.
fn legacy_set_with_x_field(attacker: &PrivateKey, x_field: &str) -> Vec<String> {
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let tag = legacy_tag(attacker);
    vec![
        format!("{}.{}.2.{}", x_field, field_text(&key_value), tag),
        format!("2.{}.2.{}", field_text(&BigNumber::from_u64(5)), tag),
    ]
}

#[test]
fn honest_share_sets_round_trip_at_several_thresholds_854() {
    let key = fixed_key();
    for (threshold, total) in [(2usize, 3usize), (3, 5), (5, 10), (10, 10)] {
        let shares = deterministic_split(&key, threshold, total);
        let backup = shares.to_backup_format().unwrap();
        assert_eq!(backup.len(), total);

        let read = KeyShares::from_backup_format(&backup).unwrap();
        assert_eq!(read.threshold, threshold);
        assert_eq!(
            read.recover_private_key().unwrap().to_bytes(),
            key.to_bytes()
        );

        let first: Vec<String> = backup[..threshold].to_vec();
        assert_eq!(
            KeyShares::from_backup_format(&first)
                .unwrap()
                .recover_private_key()
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );

        let last: Vec<String> = backup[total - threshold..].to_vec();
        assert_eq!(
            KeyShares::from_backup_format(&last)
                .unwrap()
                .recover_private_key()
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
    }
}

#[test]
fn honest_share_sets_round_trip_in_any_order_and_from_the_random_split_854() {
    let key = PrivateKey::random();
    let shares = split_private_key(&key, 3, 5).unwrap();
    let backup = shares.to_backup_format().unwrap();

    // Several orders of the same whole set.
    let reversed: Vec<String> = backup.iter().rev().cloned().collect();
    let rotated: Vec<String> = backup[2..].iter().chain(&backup[..2]).cloned().collect();
    for set in [&backup, &reversed, &rotated] {
        assert_eq!(
            KeyShares::from_backup_format(set)
                .unwrap()
                .recover_private_key()
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
    }

    // A scattered subset of the exact threshold size.
    let scattered: Vec<String> = [4usize, 0, 2].iter().map(|&i| backup[i].clone()).collect();
    assert_eq!(
        KeyShares::from_backup_format(&scattered)
            .unwrap()
            .recover_private_key()
            .unwrap()
            .to_bytes(),
        key.to_bytes()
    );
}

#[test]
fn a_zero_x_share_is_refused_by_the_backup_door_854() {
    let set = set_with_x_field(&fixed_key(), "1");
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a set whose first share has x = 0"
    );
}

#[test]
fn a_zero_x_share_second_is_refused_by_the_backup_door_854() {
    // The same forged set, the zero-x share second: the refusal must not
    // depend on where in the set the share stands.
    let attacker = fixed_key();
    let shares = deterministic_split(&attacker, 2, 3);
    let backup = shares.to_backup_format().unwrap();
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let forged = format!("1.{}.2.{}", field_text(&key_value), shares.integrity);
    let set = vec![backup[1].clone(), forged];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a zero-x share wherever it stands"
    );
}

#[test]
fn a_zero_x_share_third_is_refused_by_the_backup_door_854() {
    // The same forged set, the zero-x share third of three (threshold 2): a
    // check that reads only the first two shares of a set would miss it.
    let attacker = fixed_key();
    let shares = deterministic_split(&attacker, 2, 3);
    let backup = shares.to_backup_format().unwrap();
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let forged = format!("1.{}.2.{}", field_text(&key_value), shares.integrity);
    let set = vec![backup[0].clone(), backup[1].clone(), forged];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a zero-x share third of three"
    );
}

#[test]
fn a_zero_x_point_is_refused_at_recovery_854() {
    let attacker = fixed_key();
    let shares = deterministic_split(&attacker, 2, 3);

    // The same share set, hand-built, bypassing the backup door: a point at
    // x = 0 whose y is the attacker's key, beside an honest share of the
    // attacker's own split.
    let zero = PointInFiniteField::new(
        BigNumber::zero(),
        BigNumber::from_bytes_be(&attacker.to_bytes()),
    );
    let mixed = KeyShares::new(
        vec![zero, shares.points[1].clone()],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a hand-built set whose first point has x = 0"
    );
}

#[test]
fn a_zero_x_point_second_is_refused_at_recovery_854() {
    // The same hand-built set, the zero-x point second: the refusal must not
    // depend on where in the set the point stands.
    let attacker = fixed_key();
    let shares = deterministic_split(&attacker, 2, 3);
    let zero = PointInFiniteField::new(
        BigNumber::zero(),
        BigNumber::from_bytes_be(&attacker.to_bytes()),
    );
    let mixed = KeyShares::new(
        vec![shares.points[1].clone(), zero],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a zero-x point wherever it stands"
    );
}

#[test]
fn a_zero_x_point_last_is_refused_at_recovery_854() {
    // The same hand-built set, the zero-x point last of four (threshold 2):
    // the base's interpolation reads only the first two points, so the
    // recovery would otherwise succeed through the honest leading pair.
    let attacker = fixed_key();
    let shares = deterministic_split(&attacker, 2, 4);
    let zero = PointInFiniteField::new(
        BigNumber::zero(),
        BigNumber::from_bytes_be(&attacker.to_bytes()),
    );
    let mixed = KeyShares::new(
        vec![
            shares.points[0].clone(),
            shares.points[1].clone(),
            shares.points[2].clone(),
            zero,
        ],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a zero-x point last of four"
    );
}

#[test]
fn a_zero_x_point_built_by_from_string_is_refused_at_recovery_854() {
    // The point built by `PointInFiniteField::from_string` from the text
    // `1.<y>` (the base58 `1` alone is zero's canonical text): composed into
    // recovery it must be refused like any other zero-x point.
    let attacker = fixed_key();
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let zero = PointInFiniteField::from_string(&format!("1.{}", field_text(&key_value))).unwrap();
    let shares = deterministic_split(&attacker, 2, 3);
    let mixed = KeyShares::new(
        vec![zero, shares.points[1].clone()],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a zero-x point however the set was built"
    );
}

#[test]
fn a_non_canonical_zero_x_field_is_refused_by_the_backup_door_854() {
    // The field prime as an x field reduces to zero on read: the same
    // substitution as the base58 `1` share, through a non-canonical text.
    let p = BigNumber::secp256k1_prime();
    let set = set_with_x_field(&fixed_key(), &field_text(&p));
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse an x field that reduces to zero"
    );
}

#[test]
fn a_duplicate_share_is_refused_by_the_backup_door_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 3, 5);
    let backup = shares.to_backup_format().unwrap();

    let set = vec![backup[0].clone(), backup[1].clone(), backup[1].clone()];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse the same share twice"
    );
}

#[test]
fn a_duplicate_share_not_adjacent_to_its_twin_is_refused_by_the_backup_door_854() {
    // A 3-of-5 split's first three honest shares, the first repeated at the
    // end: the twins are not adjacent, so a neighbour-pairing check alone
    // would miss them.
    let key = fixed_key();
    let shares = deterministic_split(&key, 3, 5);
    let backup = shares.to_backup_format().unwrap();

    let set = vec![
        backup[0].clone(),
        backup[1].clone(),
        backup[2].clone(),
        backup[0].clone(),
    ];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a repeated x whose twins are not adjacent"
    );
}

#[test]
fn a_duplicate_x_with_another_y_is_refused_by_the_backup_door_854() {
    // Two shares at the same x with two different y values: the duplicate
    // arm is keyed on the x coordinate alone, so a seen-set keyed on the
    // whole point or on y would miss the pair.
    let key = fixed_key();
    let shares = deterministic_split(&key, 3, 5);
    let backup = shares.to_backup_format().unwrap();
    let parts: Vec<&str> = backup[0].split('.').collect();
    let p = BigNumber::secp256k1_prime();
    let y_other = shares.points[0].y.add(&BigNumber::from_u64(1)).modulo(&p);

    let forged = format!(
        "{}.{}.{}.{}",
        parts[0],
        field_text(&y_other),
        parts[2],
        parts[3]
    );
    let set = vec![backup[0].clone(), backup[1].clone(), forged];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a repeated x whatever the y values"
    );
}

#[test]
fn a_duplicate_x_beyond_the_interpolation_window_is_refused_at_recovery_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 2, 3);

    // A duplicate past the first `threshold` points, where the interpolation
    // never reads it: only the first two points are used, and they are a
    // whole threshold subset of the split, so the recovery would otherwise
    // succeed.
    let mixed = KeyShares::new(
        vec![
            shares.points[0].clone(),
            shares.points[1].clone(),
            shares.points[1].clone(),
        ],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a duplicate x even past the points it reads"
    );
}

#[test]
fn a_duplicate_x_not_adjacent_to_its_twin_is_refused_at_recovery_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 3, 5);

    // The first share repeated at the end of a threshold subset: the twins are
    // not adjacent, so a neighbour-pairing check alone would miss them, and
    // the first three points alone are an honest threshold subset, so the
    // recovery would otherwise succeed.
    let mixed = KeyShares::new(
        vec![
            shares.points[0].clone(),
            shares.points[1].clone(),
            shares.points[2].clone(),
            shares.points[0].clone(),
        ],
        3,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a repeated x whose twins are not adjacent"
    );
}

#[test]
fn a_duplicate_x_with_another_y_is_refused_at_recovery_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 2, 3);
    let p = BigNumber::secp256k1_prime();

    // A second share at the first share's x with a different y: the duplicate
    // arm is keyed on the x coordinate alone, so a seen-set keyed on the
    // whole point or on y would miss the pair. The first two points are an
    // honest threshold subset, so the recovery would otherwise succeed.
    let shifted = PointInFiniteField::new(
        shares.points[0].x.clone(),
        shares.points[0].y.add(&BigNumber::from_u64(1)).modulo(&p),
    );
    let mixed = KeyShares::new(
        vec![shares.points[0].clone(), shares.points[1].clone(), shifted],
        2,
        shares.integrity.clone(),
    );
    let result = mixed.recover_private_key();
    assert!(
        result.is_err(),
        "recovery must refuse a repeated x whatever the y values"
    );
}

#[test]
fn an_overlong_coordinate_field_is_refused_by_the_backup_door_854() {
    let set = set_with_x_field(&fixed_key(), &"2".repeat(65));
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a coordinate field over 64 base58 characters"
    );
}

#[test]
fn a_non_canonical_coordinate_field_is_refused_by_the_backup_door_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 2, 3);
    let backup = shares.to_backup_format().unwrap();
    let parts: Vec<&str> = backup[0].split('.').collect();

    // A leading '1' on the x field decodes to the same value: the same share,
    // written non-canonically.
    let x_padded = format!("1{}", parts[0]);
    let with_x = vec![
        format!("{}.{}.{}.{}", x_padded, parts[1], parts[2], parts[3]),
        backup[1].clone(),
    ];
    let e = KeyShares::from_backup_format(&with_x).unwrap_err();
    assert!(
        e.to_string()
            .contains("Finite-field point must use a bounded canonical Base58 representation"),
        "the refusal's words must tell the holder what to check on the x field: {e:?}"
    );

    // The same on the y field.
    let y_padded = format!("1{}", parts[1]);
    let with_y = vec![
        format!("{}.{}.{}.{}", parts[0], y_padded, parts[2], parts[3]),
        backup[1].clone(),
    ];
    let e = KeyShares::from_backup_format(&with_y).unwrap_err();
    assert!(
        e.to_string()
            .contains("Finite-field point must use a bounded canonical Base58 representation"),
        "the refusal's words must tell the holder what to check on the y field: {e:?}"
    );
}

#[test]
fn a_coordinate_at_or_above_the_field_prime_is_refused_by_the_backup_door_854() {
    let key = fixed_key();
    let shares = deterministic_split(&key, 2, 3);
    let backup = shares.to_backup_format().unwrap();
    let parts: Vec<&str> = backup[0].split('.').collect();
    let p = BigNumber::secp256k1_prime();

    // x = p + x0 reduces to x0 on read: the same share, written at or above
    // the field prime.
    let x_above = field_text(&p.add(&shares.points[0].x));
    let with_x = vec![
        format!("{}.{}.{}.{}", x_above, parts[1], parts[2], parts[3]),
        backup[1].clone(),
    ];
    let result = KeyShares::from_backup_format(&with_x);
    assert!(
        result.is_err(),
        "the backup door must refuse an x at or above the field prime"
    );

    // The same on the y field.
    let y_above = field_text(&p.add(&shares.points[0].y));
    let with_y = vec![
        format!("{}.{}.{}.{}", parts[0], y_above, parts[2], parts[3]),
        backup[1].clone(),
    ];
    let result = KeyShares::from_backup_format(&with_y);
    assert!(
        result.is_err(),
        "the backup door must refuse a y at or above the field prime"
    );
}

#[test]
fn a_very_long_coordinate_field_is_refused_in_bounded_time_854() {
    // A 400,000-character coordinate field: refused on its length before any
    // of it is decoded, so the door's cost does not grow with a field's text.
    let set = set_with_x_field(&fixed_key(), &"2".repeat(400_000));
    let before = Instant::now();
    let result = KeyShares::from_backup_format(&set);
    let elapsed = before.elapsed();
    assert!(
        result.is_err(),
        "the backup door must refuse an overlong coordinate field"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the refusal must be bounded, took {elapsed:?}"
    );
}

#[test]
fn a_zero_x_share_is_refused_by_the_legacy_door_854() {
    let set = legacy_set_with_x_field(&fixed_key(), "1");
    let result = recover_private_key_from_legacy_backup(&set);
    let e = result.unwrap_err();
    assert!(
        e.to_string()
            .contains("Zero x coordinate in legacy share 0"),
        "the legacy door's refusal must name the zero-x share in its words: {e:?}"
    );
}

#[test]
fn a_zero_x_share_second_is_refused_by_the_legacy_door_854() {
    // The same forged legacy set, the zero-x share second.
    let mut set = legacy_set_with_x_field(&fixed_key(), "1");
    set.reverse();
    let result = recover_private_key_from_legacy_backup(&set);
    assert!(
        result.is_err(),
        "the legacy door must refuse a zero-x share wherever it stands"
    );
}

#[test]
fn a_zero_x_share_third_is_refused_by_the_legacy_door_854() {
    // The line f(x) = a + 7x at threshold 2, the zero-x share third of
    // three: the base reads only the first two, so the recovery would
    // otherwise succeed.
    let attacker = fixed_key();
    let a = BigNumber::from_bytes_be(&attacker.to_bytes());
    let p = BigNumber::secp256k1_prime();
    let tag = legacy_tag(&attacker);
    let y1 = a.add(&BigNumber::from_u64(7)).modulo(&p);
    let y2 = a.add(&BigNumber::from_u64(14)).modulo(&p);
    let set = vec![
        format!("2.{}.2.{}", field_text(&y1), tag),
        format!("3.{}.2.{}", field_text(&y2), tag),
        format!("1.{}.2.{}", field_text(&a), tag),
    ];
    let result = recover_private_key_from_legacy_backup(&set);
    assert!(
        result.is_err(),
        "the legacy door must refuse a zero-x share third of three"
    );
}

#[test]
fn a_duplicate_x_beyond_the_interpolation_window_is_refused_by_the_legacy_door_854() {
    let attacker = fixed_key();
    let a = BigNumber::from_bytes_be(&attacker.to_bytes());
    let p = BigNumber::secp256k1_prime();
    let tag = legacy_tag(&attacker);

    // The line f(x) = a + 7x: the first two shares recover the attacker's
    // key, the third repeats the second past the threshold window. The x
    // fields are canonical base58 of the values 1 and 2 ("2" and "3"; "1"
    // alone is the canonical text of zero).
    let y1 = a.add(&BigNumber::from_u64(7)).modulo(&p);
    let y2 = a.add(&BigNumber::from_u64(14)).modulo(&p);
    let set = vec![
        format!("2.{}.2.{}", field_text(&y1), tag),
        format!("3.{}.2.{}", field_text(&y2), tag),
        format!("3.{}.2.{}", field_text(&y2), tag),
    ];
    let result = recover_private_key_from_legacy_backup(&set);
    assert!(
        result.is_err(),
        "the legacy door must refuse a repeated x even past the points it reads"
    );
}

#[test]
fn a_duplicate_x_not_adjacent_to_its_twin_is_refused_by_the_legacy_door_854() {
    // The same line at threshold 3, the first of four shares repeated at the
    // end: the base reads only the first three, so the recovery would
    // otherwise succeed, and the twins are not adjacent.
    let attacker = fixed_key();
    let a = BigNumber::from_bytes_be(&attacker.to_bytes());
    let p = BigNumber::secp256k1_prime();
    let tag = legacy_tag(&attacker);
    let y1 = a.add(&BigNumber::from_u64(7)).modulo(&p);
    let y2 = a.add(&BigNumber::from_u64(14)).modulo(&p);
    let y3 = a.add(&BigNumber::from_u64(21)).modulo(&p);
    let share1 = format!("2.{}.3.{}", field_text(&y1), tag);
    let set = vec![
        share1.clone(),
        format!("3.{}.3.{}", field_text(&y2), tag),
        format!("4.{}.3.{}", field_text(&y3), tag),
        share1,
    ];
    let result = recover_private_key_from_legacy_backup(&set);
    assert!(
        result.is_err(),
        "the legacy door must refuse a repeated x whose twins are not adjacent"
    );
}

#[test]
fn an_honest_legacy_split_round_trips_854() {
    let attacker = fixed_key();
    let a = BigNumber::from_bytes_be(&attacker.to_bytes());
    let p = BigNumber::secp256k1_prime();
    let tag = legacy_tag(&attacker);

    // The same line as the duplicate cell above, without the repeated share.
    let y1 = a.add(&BigNumber::from_u64(7)).modulo(&p);
    let y2 = a.add(&BigNumber::from_u64(14)).modulo(&p);
    let set = vec![
        format!("2.{}.2.{}", field_text(&y1), tag),
        format!("3.{}.2.{}", field_text(&y2), tag),
    ];
    let key = recover_private_key_from_legacy_backup(&set).unwrap();
    assert_eq!(key.to_bytes(), attacker.to_bytes());
}

#[test]
fn an_honest_boundary_share_set_round_trips_854() {
    // The honest boundaries of the grammar: x = 1 (the smallest x any writer
    // draws) and x = p - 1 (the largest canonical field element). Both are
    // accepted at every door: the recovery door on a hand-built two-point set,
    // and both text doors with a share whose x field is the canonical text of
    // p - 1.
    let key = fixed_key();
    let a = BigNumber::from_bytes_be(&key.to_bytes());
    let p = BigNumber::secp256k1_prime();
    let seven = BigNumber::from_u64(7);
    let y1 = a.add(&seven).modulo(&p);
    let y2 = a.sub(&seven).modulo(&p);
    let x_boundary = p.sub(&BigNumber::from_u64(1));

    // Recovery: the line f(x) = a + 7x through (1, a + 7) and (p - 1, a - 7)
    // (p - 1 is -1 in the field) answers f(0) = a, and the tag is the key's
    // own, taken from an honest split of it.
    let tag = deterministic_split(&key, 2, 3).integrity;
    let set = KeyShares::new(
        vec![
            PointInFiniteField::new(BigNumber::from_u64(1), y1.clone()),
            PointInFiniteField::new(x_boundary.clone(), y2.clone()),
        ],
        2,
        tag.clone(),
    );
    assert_eq!(
        set.recover_private_key().unwrap().to_bytes(),
        key.to_bytes()
    );

    // The BRC-140 text door: the same line as backup strings, the boundary
    // share's x field the canonical text of p - 1.
    let strings = vec![
        format!("2.{}.2.{}", field_text(&y1), tag),
        format!("{}.{}.2.{}", field_text(&x_boundary), field_text(&y2), tag),
    ];
    let read = KeyShares::from_backup_format(&strings).unwrap();
    assert_eq!(
        read.recover_private_key().unwrap().to_bytes(),
        key.to_bytes()
    );

    // The legacy text door caps a whole share at 65 bytes, so the boundary
    // share's y must be short there: the line f(x) = a + (a - 5)x answers
    // f(-1) = 5 and f(0) = a, both shares 53 bytes.
    let legacy = legacy_tag(&key);
    let five = BigNumber::from_u64(5);
    let y1_short = a.add(&a).sub(&five).modulo(&p);
    let legacy_strings = vec![
        format!("2.{}.2.{}", field_text(&y1_short), legacy),
        format!(
            "{}.{}.2.{}",
            field_text(&x_boundary),
            field_text(&five),
            legacy
        ),
    ];
    let recovered = recover_private_key_from_legacy_backup(&legacy_strings).unwrap();
    assert_eq!(recovered.to_bytes(), key.to_bytes());
}
