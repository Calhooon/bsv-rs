//! #333: the reference's ECIES byte bounds precede envelope reads and encryption.
//! `ts-stack@edf6e03`: ECIES.ts:12,551,589-594,673,704-709 and
//! CompatValidation.ts:1-15. Large forged envelopes keep a writer's header,
//! with zero padding and a bogus MAC; no large envelope MAC is computed here.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test assertions
#![cfg(feature = "compat")]

use bsv_rs::compat::ecies::{
    bitcore_decrypt, bitcore_encrypt, electrum_decrypt, electrum_encrypt, encrypt_shared_base64,
    encrypt_single, encrypt_single_base64,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use std::sync::OnceLock;

const PLAINTEXT_BOUND: usize = 16 * 1024 * 1024;
const ENVELOPE_BOUND: usize = PLAINTEXT_BOUND + 160;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

fn envelope_refused(label: &str) -> Error {
    Error::EciesDecryptionFailed(format!("{label} must be a bounded dense byte array"))
}

fn plaintext_refused(error: Error, label: &str) {
    let words = format!("{label} must be a bounded dense byte array");
    assert_eq!(
        (error.to_string(), error),
        (words.clone(), Error::EciesInvalidPlaintext(words))
    );
}

fn electrum_envelope() -> &'static [u8] {
    static ENVELOPE: OnceLock<Vec<u8>> = OnceLock::new();
    ENVELOPE.get_or_init(|| {
        let mut data = electrum_encrypt(b"", &key(1).public_key(), &key(2), false).unwrap();
        data.truncate(4 + 33);
        // The nearest framed embedded-key envelope above the cap is cap + 5.
        data.resize(ENVELOPE_BOUND + 5, 0);
        data
    })
}

fn bitcore_envelope() -> &'static [u8] {
    static ENVELOPE: OnceLock<Vec<u8>> = OnceLock::new();
    ENVELOPE.get_or_init(|| {
        let mut data = bitcore_encrypt(b"", &key(1).public_key(), &key(2), None).unwrap();
        data.truncate(33);
        data.resize(ENVELOPE_BOUND + 1, 0);
        data
    })
}

fn plaintext() -> &'static [u8] {
    static PLAINTEXT: OnceLock<Vec<u8>> = OnceLock::new();
    PLAINTEXT.get_or_init(|| vec![0x5a; PLAINTEXT_BOUND + 1])
}

#[test]
fn an_electrum_envelope_one_byte_over_the_reference_bound_is_refused_before_reading() {
    let data = &electrum_envelope()[..ENVELOPE_BOUND + 1];
    for sender in [None, Some(key(2).public_key())] {
        assert_eq!(
            electrum_decrypt(data, &key(1), sender.as_ref()).err(),
            Some(envelope_refused("Electrum ECIES envelope"))
        );
    }
}

#[test]
fn a_framed_electrum_envelope_over_the_reference_bound_is_refused_before_the_mac() {
    assert_eq!(
        electrum_decrypt(electrum_envelope(), &key(1), None).err(),
        Some(envelope_refused("Electrum ECIES envelope"))
    );
}

#[test]
fn an_electrum_envelope_at_the_reference_bound_is_read_as_before() {
    let data = electrum_envelope();
    // The cap itself is not an Electrum frame size; it must still reach framing.
    assert_eq!(
        electrum_decrypt(&data[..ENVELOPE_BOUND], &key(1), Some(&key(2).public_key())).err(),
        Some(Error::EciesDecryptionFailed(
            "Invalid Electrum ECIES ciphertext framing".into()
        ))
    );
    // A framed envelope just below the cap must still reach the MAC.
    assert_eq!(
        electrum_decrypt(&data[..ENVELOPE_BOUND - 11], &key(1), None).err(),
        Some(Error::EciesHmacMismatch)
    );
}

#[test]
fn a_bitcore_envelope_one_byte_over_the_reference_bound_is_refused_before_the_mac() {
    assert_eq!(
        bitcore_decrypt(bitcore_envelope(), &key(1)).err(),
        Some(envelope_refused("Bitcore ECIES envelope"))
    );
}

#[test]
fn a_bitcore_envelope_at_the_reference_bound_is_read_as_before() {
    let data = bitcore_envelope();
    for len in [ENVELOPE_BOUND, ENVELOPE_BOUND - 15] {
        assert_eq!(
            bitcore_decrypt(&data[..len], &key(1)).err(),
            Some(Error::EciesHmacMismatch)
        );
    }
}

#[test]
fn electrum_plaintext_one_byte_over_the_reference_bound_is_refused_before_encryption() {
    let from = key(2);
    let to = key(1).public_key();
    for no_key in [false, true] {
        plaintext_refused(
            electrum_encrypt(plaintext(), &to, &from, no_key).unwrap_err(),
            "Electrum ECIES plaintext",
        );
    }
    plaintext_refused(
        encrypt_single(plaintext(), &from).unwrap_err(),
        "Electrum ECIES plaintext",
    );
    plaintext_refused(
        encrypt_single_base64(plaintext(), &from).unwrap_err(),
        "Electrum ECIES plaintext",
    );
    plaintext_refused(
        encrypt_shared_base64(plaintext(), &to, &from).unwrap_err(),
        "Electrum ECIES plaintext",
    );
}

#[test]
fn bitcore_plaintext_one_byte_over_the_reference_bound_is_refused_before_encryption() {
    plaintext_refused(
        bitcore_encrypt(plaintext(), &key(1).public_key(), &key(2), None).unwrap_err(),
        "Bitcore ECIES plaintext",
    );
}

#[test]
fn plaintext_at_the_reference_bound_round_trips_in_each_format() {
    let message = &plaintext()[..PLAINTEXT_BOUND];
    let from = key(2);
    let to = key(1);
    for no_key in [false, true] {
        let data = electrum_encrypt(message, &to.public_key(), &from, no_key).unwrap();
        assert!(data.len() < ENVELOPE_BOUND);
        assert_eq!(
            electrum_decrypt(&data, &to, Some(&from.public_key())).unwrap(),
            message
        );
    }
    let data = bitcore_encrypt(message, &to.public_key(), &from, Some(&[0x42; 16])).unwrap();
    assert!(data.len() < ENVELOPE_BOUND);
    assert_eq!(bitcore_decrypt(&data, &to).unwrap(), message);
}
