//! `electrum_decrypt` finds an embedded key the reference's way (#109): by
//! the byte after the magic and the bytes left over, as `ts-stack@edf6e03`
//! `packages/sdk/src/compat/ECIES.ts:607-656` does, never by the length
//! alone. Until #109 an envelope over 69 bytes was read as embedding a key,
//! so a no-key envelope of a plaintext of 32 bytes or more lost 33 bytes of
//! its ciphertext to a key and failed AES unpadding after its MAC passed.
//!
//! The witnesses are `tests/vectors/compat_ecies_envelope_109.json`, written
//! by `tests/support/compat_ecies_envelope_109.mjs` under Node v22.18.0: the
//! reference's envelopes for fixed keys with the key and without, its
//! verdicts on each with the expected sender and without, its refusals, an
//! envelope embedding the uncompressed key, and its verdicts on the envelopes
//! this crate sealed (the ignored `record_this_crates_envelopes_for_the_reference`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "compat")]

use bsv_rs::compat::ecies::{electrum_decrypt, electrum_encrypt};
use bsv_rs::primitives::{from_base64, from_hex, to_hex, PrivateKey, PublicKey};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/compat_ecies_envelope_109.json");
const ISSUE_INPUT: &str = "r68gn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+9z8I=";
const LENGTHS: [usize; 11] = [1, 15, 16, 17, 31, 32, 33, 47, 48, 64, 96];

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

fn recipient() -> PrivateKey {
    key(1)
}

fn sender() -> PrivateKey {
    key(2)
}

fn other() -> PublicKey {
    key(3).public_key()
}

/// The script's plaintexts: the issue's input at 32 bytes, a pattern elsewhere
fn plaintext(n: usize) -> Vec<u8> {
    if n == 32 {
        return from_base64(ISSUE_INPUT).unwrap();
    }
    (0..n).map(|i| ((i * 31 + n) & 0xff) as u8).collect()
}

fn seal(pt: &[u8], no_key: bool) -> Vec<u8> {
    electrum_encrypt(pt, &recipient().public_key(), &sender(), no_key).unwrap()
}

fn refused(reason: &str) -> Error {
    Error::EciesDecryptionFailed(reason.to_string())
}

#[test]
fn a_no_key_envelope_of_any_length_opens_with_its_sender() {
    let from = sender().public_key();
    for n in LENGTHS {
        let pt = plaintext(n);
        let sealed = seal(&pt, true);
        assert_eq!(
            electrum_decrypt(&sealed, &recipient(), Some(&from)).unwrap(),
            pt,
            "{n} bytes"
        );
    }
}

#[test]
fn the_issue_input_sealed_without_a_key_opens() {
    let pt = from_base64(ISSUE_INPUT).unwrap();
    assert_eq!(pt.len(), 32);
    let sealed = seal(&pt, true);
    assert_eq!(sealed.len(), 4 + 48 + 32, "past the old length rule's 69");
    let from = sender().public_key();
    assert_eq!(electrum_decrypt(&sealed, &recipient(), Some(&from)), Ok(pt));
}

#[test]
fn an_envelope_with_a_key_opens_with_and_without_its_sender() {
    let from = sender().public_key();
    for n in LENGTHS {
        let pt = plaintext(n);
        let sealed = seal(&pt, false);
        assert_eq!(
            electrum_decrypt(&sealed, &recipient(), Some(&from)).unwrap(),
            pt
        );
        assert_eq!(electrum_decrypt(&sealed, &recipient(), None).unwrap(), pt);
    }
}

#[test]
fn a_no_key_envelope_without_a_sender_is_refused_in_the_references_words() {
    for n in LENGTHS {
        let sealed = seal(&plaintext(n), true);
        assert_eq!(
            electrum_decrypt(&sealed, &recipient(), None),
            Err(refused("Sender public key is required")),
            "{n} bytes"
        );
    }
}

#[test]
fn an_embedded_key_beside_another_expected_sender_is_refused() {
    let sealed = seal(&plaintext(32), false);
    assert_eq!(
        electrum_decrypt(&sealed, &recipient(), Some(&other())),
        Err(refused(
            "Embedded sender public key does not match the expected sender"
        ))
    );
}

#[test]
fn a_ciphertext_out_of_framing_is_refused_before_the_mac() {
    let from = sender().public_key();
    let mut short = b"BIE1".to_vec();
    short.extend([0u8; 17 + 32]);
    let mut key_alone = b"BIE1".to_vec();
    key_alone.extend(from.to_compressed());
    key_alone.extend([0u8; 32]);
    for envelope in [short, key_alone] {
        assert_eq!(
            electrum_decrypt(&envelope, &recipient(), Some(&from)),
            Err(refused("Invalid Electrum ECIES ciphertext framing"))
        );
    }
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    from_hex(value.as_str().unwrap()).unwrap()
}

/// This crate's reading of the reference's verdict: its plaintext, or the
/// error each of its words is here
fn expected(verdict: &Value) -> Result<Vec<u8>, Error> {
    if let Some(pt) = verdict.get("plaintext_hex") {
        return Ok(bytes(pt));
    }
    Err(match verdict["error"].as_str().unwrap() {
        "Invalid checksum" => Error::EciesHmacMismatch,
        words => refused(words),
    })
}

fn expectation(name: &str) -> Option<PublicKey> {
    match name {
        "sender" => Some(sender().public_key()),
        "other" => Some(other()),
        "none" => None,
        _ => panic!("expectation {name}"),
    }
}

#[test]
fn this_crates_envelopes_are_the_references_byte_for_byte() {
    let v = vector();
    assert_eq!(v["keys"]["recipient"], to_hex(&recipient().to_bytes()));
    assert_eq!(v["keys"]["sender"], to_hex(&sender().to_bytes()));
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), LENGTHS.len());
    for (case, n) in cases.iter().zip(LENGTHS) {
        let pt = plaintext(n);
        assert_eq!(bytes(&case["plaintext_hex"]), pt, "{}", case["name"]);
        for (kind, no_key) in [("with_key", false), ("no_key", true)] {
            let sealed = seal(&pt, no_key);
            assert_eq!(
                sealed,
                bytes(&case[kind]["envelope_hex"]),
                "{} {kind}",
                case["name"]
            );
            assert_eq!(
                sealed,
                bytes(&case[kind]["crate_envelope_hex"]),
                "{} {kind}",
                case["name"]
            );
        }
    }
}

#[test]
fn the_references_envelopes_open_here_to_its_verdicts() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        for kind in ["with_key", "no_key"] {
            let envelope = bytes(&case[kind]["envelope_hex"]);
            let opened = &case[kind]["opened"];
            for (column, from) in [("with_sender", "sender"), ("without_sender", "none")] {
                assert_eq!(
                    electrum_decrypt(&envelope, &recipient(), expectation(from).as_ref()),
                    expected(&opened[column]),
                    "{} {kind} {column}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn the_reference_opens_this_crates_envelopes() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        for kind in ["with_key", "no_key"] {
            let opened = &case[kind]["crate_opened"];
            let with = &opened["with_sender"];
            assert_eq!(
                with["plaintext_hex"], case["plaintext_hex"],
                "{}",
                case["name"]
            );
            let without = &opened["without_sender"];
            if kind == "with_key" {
                assert_eq!(
                    without["plaintext_hex"], case["plaintext_hex"],
                    "{}",
                    case["name"]
                );
            } else {
                assert_eq!(
                    without["error"], "Sender public key is required",
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

/// The off-curve key (x at or above the field prime): the reference's
/// `PublicKey.fromString` reduces x modulo p and refuses later (the mismatch,
/// or the MAC); `PublicKey::from_bytes` refuses it here, a stated difference
/// (CLAUDE.md, the #109 line)
const OFF_CURVE: &str = "a-compressed-key-off-the-curve";

#[test]
fn the_references_refusals_and_the_uncompressed_key_read_here_as_there() {
    let v = vector();
    let refusals = v["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 10);
    for r in refusals {
        let name = r["name"].as_str().unwrap();
        let got = electrum_decrypt(
            &bytes(&r["envelope_hex"]),
            &recipient(),
            expectation(r["expected"].as_str().unwrap()).as_ref(),
        );
        if name.starts_with(OFF_CURVE) {
            assert!(r["verdict"].get("error").is_some(), "{name}");
            assert!(
                matches!(got, Err(Error::InvalidPublicKey(_))),
                "{name}: {got:?}"
            );
        } else {
            assert_eq!(got, expected(&r["verdict"]), "{name}");
        }
    }
}

/// Writes this crate's envelopes for `verify` in the script (the module docs)
#[test]
#[ignore]
fn record_this_crates_envelopes_for_the_reference() {
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("ECIES_109_REFERENCE").unwrap()).unwrap(),
    )
    .unwrap();
    let mut cases = serde_json::Map::new();
    for case in reference["cases"].as_array().unwrap() {
        let pt = bytes(&case["plaintext_hex"]);
        cases.insert(
            case["name"].as_str().unwrap().to_string(),
            serde_json::json!({
                "with_key": to_hex(&seal(&pt, false)),
                "no_key": to_hex(&seal(&pt, true)),
            }),
        );
    }
    std::fs::write(
        std::env::var("ECIES_109_CRATE_OUT").unwrap(),
        serde_json::to_string_pretty(&serde_json::json!({ "cases": cases })).unwrap(),
    )
    .unwrap();
}
