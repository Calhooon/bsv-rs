//! #463: the reference's minimum envelope lengths use its bounded-array words.
//! `ts-stack@edf6e03` `ECIES.ts:589-594,704-709`, `CompatValidation.ts:10-15`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test assertions
#![cfg(feature = "compat")]

use bsv_rs::compat::ecies::{bitcore_decrypt, bitcore_encrypt, electrum_decrypt, electrum_encrypt};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

fn bounded_refusal(error: Error, label: &str) {
    let words = format!("{label} must be a bounded dense byte array");
    assert_eq!(
        (error.to_string(), error),
        (
            format!("ECIES decryption failed: {words}"),
            Error::EciesDecryptionFailed(words)
        )
    );
}

#[test]
fn an_electrum_envelope_one_byte_under_the_reference_minimum_uses_bounded_words() {
    let to = key(1);
    let from = key(2);
    let mut data = electrum_encrypt(b"", &to.public_key(), &from, true).unwrap();
    assert_eq!(data.len(), 4 + 16 + 32);
    data.pop();
    for sender in [None, Some(from.public_key())] {
        bounded_refusal(
            electrum_decrypt(&data, &to, sender.as_ref()).unwrap_err(),
            "Electrum ECIES envelope",
        );
    }
}

#[test]
fn a_bitcore_envelope_one_byte_under_the_reference_minimum_uses_bounded_words() {
    let to = key(1);
    let mut data = bitcore_encrypt(b"", &to.public_key(), &key(2), Some(&[0x42; 16])).unwrap();
    assert_eq!(data.len(), 33 + 16 + 16 + 32);
    data.pop();
    bounded_refusal(
        bitcore_decrypt(&data, &to).unwrap_err(),
        "Bitcore ECIES envelope",
    );
}

#[test]
fn an_electrum_envelope_at_the_reference_minimum_reaches_the_mac() {
    let to = key(1);
    let from = key(2);
    let mut data = electrum_encrypt(b"", &to.public_key(), &from, true).unwrap();
    assert_eq!(data.len(), 4 + 16 + 32);
    assert_eq!(
        electrum_decrypt(&data, &to, Some(&from.public_key())).unwrap(),
        b""
    );
    data[51] ^= 1;
    assert_eq!(
        electrum_decrypt(&data, &to, Some(&from.public_key())).unwrap_err(),
        Error::EciesHmacMismatch
    );
}

#[test]
fn a_bitcore_envelope_at_the_reference_minimum_reaches_the_mac() {
    let to = key(1);
    let mut data = bitcore_encrypt(b"", &to.public_key(), &key(2), Some(&[0x42; 16])).unwrap();
    assert_eq!(data.len(), 33 + 16 + 16 + 32);
    assert_eq!(bitcore_decrypt(&data, &to).unwrap(), b"");
    data[96] ^= 1;
    assert_eq!(
        bitcore_decrypt(&data, &to).unwrap_err(),
        Error::EciesHmacMismatch
    );
}
