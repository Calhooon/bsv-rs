//! The ECDH bytes through the crate-owned `SharedSecret` (#843d6): no wire
//! byte, file byte or derived key moves. Against
//! `vectors/shared_secret_843d6.json` (`support/shared_secret_843d6.mjs`,
//! `ts-stack@edf6e03` under Node v22.18.0): for five pairs of fixed small
//! scalars, the reference's `deriveSharedSecret(..).encode(true)` from both
//! doors (`PrivateKey.ts:397-402`, `PublicKey.ts:113-118`),
//! `revealCounterpartySecret` (`KeyDeriver.ts:407-422`) and BRC-42's
//! `deriveChild` from both sides for two invoice numbers
//! (`PrivateKey.ts:460`), each read here byte for byte through this crate's
//! doors (the inherent `reveal_counterparty_secret` and the trait's through
//! `KeyDeriver` and `CachedKeyDeriver`). Green before the type changed and
//! after it: the differential, not a RED.
#![cfg(feature = "wallet")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use bsv_rs::primitives::{to_hex, PrivateKey, PublicKey};
use bsv_rs::wallet::{CachedKeyDeriver, Counterparty, KeyDeriver, KeyDeriverApi};
use serde_json::Value;

fn scalar(n: u64) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    PrivateKey::from_bytes(&bytes).expect("a small scalar")
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/shared_secret_843d6.json")).expect("the vector")
}

#[test]
fn the_shared_secret_bytes_are_the_references_from_every_door_843d6() {
    let v = vector();
    let cases = v["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 5);
    for case in cases {
        let (a, b) = (case["a"].as_u64().unwrap(), case["b"].as_u64().unwrap());
        let (priv_a, priv_b) = (scalar(a), scalar(b));
        let pub_b = priv_b.public_key();
        assert_eq!(
            pub_b.to_hex(),
            case["public_b"].as_str().unwrap(),
            "({a}, {b})"
        );
        let expected = case["point_from_private"].as_str().unwrap();
        assert_eq!(case["point_from_public"].as_str().unwrap(), expected);
        assert_eq!(case["point_revealed"].as_str().unwrap(), expected);

        let from_private = priv_a.derive_shared_secret(&pub_b).unwrap();
        let from_public = priv_a.public_key().derive_shared_secret(&priv_b).unwrap();
        let other = Counterparty::Other(pub_b.clone());
        let deriver = KeyDeriver::new(Some(priv_a.clone()));
        let cached = CachedKeyDeriver::new(Some(priv_a.clone()), None);
        let doors = [
            (
                "PrivateKey::derive_shared_secret",
                from_private.to_compressed(),
            ),
            (
                "PublicKey::derive_shared_secret",
                from_public.to_compressed(),
            ),
            (
                "KeyDeriver::reveal_counterparty_secret",
                deriver
                    .reveal_counterparty_secret(&other)
                    .unwrap()
                    .to_compressed(),
            ),
            (
                "KeyDeriverApi (KeyDeriver)",
                KeyDeriverApi::reveal_counterparty_secret(&deriver, &other)
                    .unwrap()
                    .to_compressed(),
            ),
            (
                "KeyDeriverApi (CachedKeyDeriver)",
                KeyDeriverApi::reveal_counterparty_secret(&cached, &other)
                    .unwrap()
                    .to_compressed(),
            ),
        ];
        for (door, bytes) in doors {
            assert_eq!(to_hex(&bytes), expected, "{door} at ({a}, {b})");
        }
        // x is the compressed form's last 32 bytes.
        assert_eq!(to_hex(&from_private.x()), expected[2..], "x at ({a}, {b})");
        // The two doors' values are equal (constant-time equality).
        assert!(from_private == from_public);

        for child in case["children"].as_array().unwrap() {
            let invoice = child["invoice"].as_str().unwrap();
            assert_eq!(
                priv_a.derive_child(&pub_b, invoice).unwrap().to_hex(),
                child["private_child"].as_str().unwrap(),
                "private child of ({a}, {b}) at {invoice}"
            );
            let public_child: PublicKey = pub_b.derive_child(&priv_a, invoice).unwrap();
            assert_eq!(
                public_child.to_hex(),
                child["public_child"].as_str().unwrap(),
                "public child of ({a}, {b}) at {invoice}"
            );
        }
    }
}

/// The comparison answers both ways (#843d6's fold, the strength read's S2):
/// one pair computed through both doors and both sides is equal, and two
/// different pairs are not, by `==` and by `!=`.
#[test]
fn two_different_pairs_are_unequal_and_one_pair_is_equal_both_ways_843d6() {
    let pairs = [(2u64, 3u64), (5, 7), (11, 13)];
    let secrets: Vec<_> = pairs
        .iter()
        .map(|&(a, b)| {
            let (priv_a, priv_b) = (scalar(a), scalar(b));
            let from_private = priv_a.derive_shared_secret(&priv_b.public_key()).unwrap();
            let from_public = priv_a.public_key().derive_shared_secret(&priv_b).unwrap();
            let other_side = priv_b.derive_shared_secret(&priv_a.public_key()).unwrap();
            // The same pair, computed both ways and from both sides.
            assert!(from_private == from_public, "({a}, {b}): the two doors");
            assert!(from_private == other_side, "({a}, {b}): the two sides");
            assert!(!(from_private != from_public), "({a}, {b}): != on equals");
            assert!(from_private == from_private.clone(), "({a}, {b}): a clone");
            from_private
        })
        .collect();
    for (i, left) in secrets.iter().enumerate() {
        for (j, right) in secrets.iter().enumerate().skip(i + 1) {
            assert_ne!(
                left.to_compressed(),
                right.to_compressed(),
                "pairs {i} and {j} are different points"
            );
            assert!(left != right, "pairs {i} and {j} compare equal");
            assert!(!(left == right), "pairs {i} and {j}: == on unequals");
            assert!(right != left, "pairs {j} and {i} compare equal");
        }
    }
    // Two secrets sharing x and differing in y's parity are different: a
    // point and its negation (the pair (a, b) and (n - a, b)).
    let n_minus_2 =
        PrivateKey::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f")
            .expect("n - 2");
    let negated = n_minus_2
        .derive_shared_secret(&scalar(3).public_key())
        .unwrap();
    assert_eq!(negated.x(), secrets[0].x(), "the negation shares x");
    assert!(negated != secrets[0], "a point equals its negation");
}
