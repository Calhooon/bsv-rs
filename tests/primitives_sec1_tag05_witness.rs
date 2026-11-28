//! A SEC 1 tag `05` key (the compact form k256 reads as `02 || x`) is refused at
//! `PublicKey::from_bytes` and at every site that reads a key through it, as the
//! reference's `Point.fromDER` refuses it (`ts-stack@edf6e03` `Point.ts:303-325`;
//! the node's `src/pubkey.h` `GetLen` returns 0 for a `05` header). Pinned against
//! `tests/vectors/sec1_tag_05_550.json` (reference-recorded by
//! `tests/support/sec1_tag_05_550.mjs`, Node v22.18.0; #550). Each refusal here
//! forwards this crate's primitives-root words (`unknown point format`); the 0.9
//! line's per-site error wording and its raw-bytes recipient comparison are not
//! carried on the stable line (shown absent below).
#![cfg(all(feature = "compat", feature = "messages", feature = "auth"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::Certificate;
use bsv_rs::compat::ecies;
use bsv_rs::messages::{decrypt, encrypt};
use bsv_rs::primitives::{from_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::Error;
use serde_json::Value;

/// The X of the generator, a real curve point; a `02 || x` of it is a valid key.
const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn case_input(name: &str) -> Vec<u8> {
    let v: Value = serde_json::from_str(include_str!("vectors/sec1_tag_05_550.json")).unwrap();
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("vector case {name} missing"));
    assert_eq!(
        c["accepted"],
        Value::Bool(false),
        "the reference refuses {name}"
    );
    from_hex(c["input"].as_str().unwrap()).unwrap()
}

fn refused(words: &str) -> bool {
    words.to_lowercase().contains("unknown point format")
}

// ---- the primitives root (the finding's door) ----

#[test]
fn from_bytes_refuses_a_tag_05_compact_key_not_reinterpreting_it_as_02() {
    let x = from_hex(GX).unwrap();
    let mut key02 = vec![0x02u8];
    key02.extend_from_slice(&x);
    let mut key05 = vec![0x05u8];
    key05.extend_from_slice(&x);

    // the genuine compressed key parses
    assert!(PublicKey::from_bytes(&key02).is_ok());
    // the same X behind a `05` tag is refused, not silently read as `02 || x`
    let r = PublicKey::from_bytes(&key05);
    assert!(r.is_err(), "a 05-tag compact key must be refused");
    assert!(refused(&r.unwrap_err().to_string()));
}

#[test]
fn from_bytes_and_from_hex_refuse_the_recorded_tag_05_key() {
    let bytes = case_input("from_bytes");
    let r = PublicKey::from_bytes(&bytes);
    assert!(r.is_err() && refused(&r.unwrap_err().to_string()));

    let r = PublicKey::from_hex(&hex::encode(case_input("from_hex")));
    assert!(r.is_err() && refused(&r.unwrap_err().to_string()));
}

// ---- script templates (the finding's door) ----

#[test]
fn pushdrop_decode_refuses_a_tag_05_locking_key_in_both_layouts() {
    for name in ["pushdrop_lock_before", "pushdrop_lock_after"] {
        let script = LockingScript::from_hex(&hex::encode(case_input(name))).unwrap();
        let r = PushDrop::decode(&script);
        assert!(r.is_err(), "{name}: a 05-tag locking key must be refused");
        assert!(refused(&r.unwrap_err().to_string()), "{name}");
    }
}

// ---- compat ECIES (the finding's door) ----

#[test]
fn bitcore_decrypt_refuses_a_tag_05_sender_key_before_reading_it() {
    let env = case_input("ecies_bitcore_sender");
    // any recipient: the sender key is read first, from data[0..33]
    let to = PrivateKey::from_bytes(&[9u8; 32]).unwrap();
    let r = ecies::bitcore_decrypt(&env, &to);
    assert!(r.is_err(), "a 05-tag sender key must be refused");
    assert!(refused(&r.unwrap_err().to_string()));
}

// ---- a sibling module closed by the same root: auth certificate ----
// Shows S1 reaches another module through the one root, and that the 0.9 line's
// certificate-specific wording did NOT travel (the stable door forwards the root words).

#[test]
fn certificate_from_binary_refuses_a_tag_05_party_with_the_root_words() {
    for name in ["certificate_subject", "certificate_certifier"] {
        let r = Certificate::from_binary(&case_input(name));
        assert!(r.is_err(), "{name}: a 05-tag party must be refused");
        let msg = r.unwrap_err().to_string();
        assert!(refused(&msg), "{name}: {msg}");
        // left out on the stable line: the reference's certificate-specific words
        assert!(
            !msg.to_lowercase().contains("expected a compressed"),
            "{name}: the 0.9 line's wording must not travel: {msg}"
        );
    }
}

// ---- a sibling module closed by the same root: encrypted message ----
// A crate-written fixture: encrypt to an even-Y recipient (compressed `02 || x`),
// then forge the recipient field's tag to `05`. Before the root guard, k256 reads
// `05 || x` as that very `02 || x`, so the forged ciphertext is accepted and
// decrypted (the identity malleability). After it, the read is refused at the root.

fn even_y_key() -> PrivateKey {
    for b in 1u8..=255 {
        let mut s = [0u8; 32];
        s[31] = b;
        let k = PrivateKey::from_bytes(&s).unwrap();
        if k.public_key().y_is_even() {
            return k;
        }
    }
    panic!("no even-Y key in the small range");
}

#[test]
fn encrypted_message_refuses_a_forged_tag_05_recipient_field_at_the_root() {
    let recipient = even_y_key();
    let sender = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let mut ct = encrypt(b"secret", &sender, &recipient.public_key()).unwrap();

    // fixture precondition: the recipient field (after version(4)+sender(33)) is a `02` key
    assert_eq!(ct[4 + 33], 0x02, "recipient field must be an even-Y key");
    ct[4 + 33] = 0x05; // forge the compact tag

    let r = decrypt(&ct, &recipient);
    assert!(r.is_err(), "a forged 05-tag recipient must not decrypt");
    let err = r.unwrap_err();
    assert!(refused(&err.to_string()), "root refusal: {err}");
    // left out on the stable line: the 0.9 line's raw-bytes recipient comparison
    assert!(
        !matches!(err, Error::MessageRecipientMismatch { .. }),
        "the stable line refuses at the root, it does not reach the comparison"
    );
}
