//! The Shamir backup doors refuse a share set that would substitute the
//! recovered key for the holder's (#854): a share whose x is zero (the
//! base58 `1`, or the field prime as a non-canonical zero), any coordinate at
//! or above the field prime, a duplicate x — the same share twice, twins
//! not adjacent, one x under another y — and a non-canonical or overlong
//! coordinate field on either coordinate — at `KeyShares::from_backup_format`
//! and at `KeyShares::recover_private_key` (a hand-built set, one built by
//! `PointInFiniteField::from_string`, one by a struct literal at the field
//! prime), before interpolating; the polynomial's own arithmetic and the
//! honest boundaries of the grammar (x = 1 and x = p - 1) are pinned too.
//! Every refusal cell is paired with honest controls built by this crate's own
//! writer, at several thresholds and in several orders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
use bsv_rs::primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::{BigNumber, PrivateKey};

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

/// Splits `key` with the crate's own writer (this line has no fixed-coefficient
/// split): every cell's outcome holds for any split the writer draws.
fn writer_split(key: &PrivateKey, threshold: usize, total: usize) -> KeyShares {
    split_private_key(key, threshold, total).unwrap()
}

/// A two-share set for the backup door: the first share with the given x
/// field and y = `attacker`'s own key, the second an honest share of the
/// attacker's split (threshold 2 of 3, so every threshold and integrity tag
/// in the set agrees).
fn set_with_x_field(attacker: &PrivateKey, x_field: &str) -> Vec<String> {
    let shares = writer_split(attacker, 2, 3);
    let backup = shares.to_backup_format();
    let key_value = BigNumber::from_bytes_be(&attacker.to_bytes());
    let forged = format!(
        "{}.{}.2.{}",
        x_field,
        field_text(&key_value),
        shares.integrity
    );
    vec![forged, backup[1].clone()]
}

#[test]
fn honest_share_sets_round_trip_at_several_thresholds_854() {
    let key = fixed_key();
    for (threshold, total) in [(2usize, 3usize), (3, 5), (5, 10), (10, 10)] {
        let shares = writer_split(&key, threshold, total);
        let backup = shares.to_backup_format();
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
    let backup = shares.to_backup_format();

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
fn honest_boundary_shares_round_trip_854() {
    // The honest boundaries of the grammar: x = 1 (the smallest x any writer
    // draws) and x = p - 1 (the largest canonical field element). Both are
    // accepted at the recovery door on a hand-built two-point set, and at the
    // backup door with a share whose x field is the canonical text of p - 1.
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
    let tag = writer_split(&key, 2, 3).integrity;
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

    // The backup door: the same line as backup strings, the boundary share's
    // x field the canonical text of p - 1.
    let strings = vec![
        format!("2.{}.2.{}", field_text(&y1), tag),
        format!("{}.{}.2.{}", field_text(&x_boundary), field_text(&y2), tag),
    ];
    let read = KeyShares::from_backup_format(&strings).unwrap();
    assert_eq!(
        read.recover_private_key().unwrap().to_bytes(),
        key.to_bytes()
    );
}

#[test]
fn a_zero_x_share_is_refused_by_the_backup_door_854() {
    let set = set_with_x_field(&fixed_key(), "1");
    let e = KeyShares::from_backup_format(&set).unwrap_err();
    assert!(
        e.to_string().contains("Zero x coordinate in share 0"),
        "the backup door's refusal must name the zero-x share in its words: {e:?}"
    );
}

#[test]
fn a_zero_x_share_third_is_refused_by_the_backup_door_854() {
    // A threshold-2 set of three, the zero-x share third: the interpolation
    // reads only the first two, an honest pair, so the scan must be the one
    // that refuses it.
    let key = fixed_key();
    let shares = writer_split(&key, 2, 3);
    let backup = shares.to_backup_format();
    let key_value = BigNumber::from_bytes_be(&key.to_bytes());
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
    let shares = writer_split(&attacker, 2, 3);

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
fn a_zero_x_share_second_is_refused_by_the_backup_door_854() {
    // The same forged set, the zero-x share second.
    let mut set = set_with_x_field(&fixed_key(), "1");
    set.reverse();
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a zero-x share wherever it stands"
    );
}

#[test]
fn a_zero_x_point_second_is_refused_at_recovery_854() {
    let attacker = fixed_key();
    let shares = writer_split(&attacker, 2, 3);

    // The same hand-built set, the zero-x point second.
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
    // the interpolation reads only the first two points, so the recovery would
    // otherwise succeed through the honest leading pair.
    let attacker = fixed_key();
    let shares = writer_split(&attacker, 2, 4);
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
    let shares = writer_split(&attacker, 2, 3);
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
    let shares = writer_split(&key, 3, 5);
    let backup = shares.to_backup_format();

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
    let shares = writer_split(&key, 3, 5);
    let backup = shares.to_backup_format();

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
    let shares = writer_split(&key, 3, 5);
    let backup = shares.to_backup_format();
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
    let shares = writer_split(&key, 2, 3);

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
    let shares = writer_split(&key, 3, 5);

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
    let shares = writer_split(&key, 2, 3);
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
fn an_overlong_y_field_is_refused_by_the_backup_door_854() {
    // The same bound on the y field.
    let key = fixed_key();
    let shares = writer_split(&key, 2, 3);
    let backup = shares.to_backup_format();
    let parts: Vec<&str> = backup[0].split('.').collect();
    let set = vec![
        format!("{}.{}.{}.{}", parts[0], "2".repeat(65), parts[2], parts[3]),
        backup[1].clone(),
    ];
    let result = KeyShares::from_backup_format(&set);
    assert!(
        result.is_err(),
        "the backup door must refuse a y field over 64 base58 characters"
    );
}

#[test]
fn a_very_long_coordinate_field_is_refused_in_bounded_time_854() {
    // A 400,000-character field: the door refuses it on its length, before
    // the field is decoded, in well under a second. Without the length
    // bound the decode of this field is the reader's whole cost.
    let x_field = "2".repeat(400_000);
    let set = set_with_x_field(&fixed_key(), &x_field);
    let start = std::time::Instant::now();
    let result = KeyShares::from_backup_format(&set);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "the backup door must refuse a 400,000-character coordinate field"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a 400,000-character field refused in {elapsed:?}"
    );
}

#[test]
fn a_very_long_y_field_is_refused_in_bounded_time_854() {
    // The same on the y field: a 400,000-character field refused on its
    // length, before it is decoded, in well under a second.
    let key = fixed_key();
    let shares = writer_split(&key, 2, 3);
    let backup = shares.to_backup_format();
    let parts: Vec<&str> = backup[0].split('.').collect();
    let set = vec![
        format!(
            "{}.{}.{}.{}",
            parts[0],
            "2".repeat(400_000),
            parts[2],
            parts[3]
        ),
        backup[1].clone(),
    ];
    let start = std::time::Instant::now();
    let result = KeyShares::from_backup_format(&set);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "the backup door must refuse a 400,000-character y field"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a 400,000-character y field refused in {elapsed:?}"
    );
}

#[test]
fn a_non_canonical_coordinate_field_is_refused_by_the_backup_door_854() {
    let key = fixed_key();
    let shares = writer_split(&key, 2, 3);
    let backup = shares.to_backup_format();
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
    let shares = writer_split(&key, 2, 3);
    let backup = shares.to_backup_format();
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
fn a_hand_built_point_at_the_field_prime_is_refused_by_integrity_854() {
    // A struct-literal point bypasses `PointInFiniteField::new`'s reduction:
    // x = p stands as written, and the interpolation reads it as zero, the
    // weight-1 substitution of another key for the holder's. The integrity
    // tag is the guard that refuses it.
    let holder = fixed_key();
    let shares = writer_split(&holder, 2, 3);
    let other_key =
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let forged = PointInFiniteField {
        x: BigNumber::secp256k1_prime(),
        y: BigNumber::from_bytes_be(&other_key.to_bytes()),
    };
    let mixed = KeyShares::new(
        vec![forged, shares.points[1].clone()],
        2,
        shares.integrity.clone(),
    );
    let e = mixed.recover_private_key().unwrap_err();
    assert!(
        e.to_string().contains("Integrity check failed"),
        "the tag must refuse a substituted key: {e:?}"
    );
}

#[test]
fn polynomial_value_at_interpolates_the_line_854() {
    // The interpolation arithmetic itself: a line through x = 1 and x = p - 1
    // answers its intercept at zero, the honest boundary in both coordinates.
    let a = BigNumber::from_bytes_be(&fixed_key().to_bytes());
    let p = BigNumber::secp256k1_prime();
    let seven = BigNumber::from_u64(7);
    let line = Polynomial::new(
        vec![
            PointInFiniteField::new(BigNumber::from_u64(1), a.add(&seven).modulo(&p)),
            PointInFiniteField::new(p.sub(&BigNumber::from_u64(1)), a.sub(&seven).modulo(&p)),
        ],
        2,
    );
    assert_eq!(line.value_at(&BigNumber::zero()), a);
}
