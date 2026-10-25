#![no_main]
//! The BRC-78 encrypted message reader, `messages::decrypt`, on arbitrary
//! ciphertext bytes, for the fixed recipient and for another key. The
//! assertion is that each returns; a plaintext the reader returns has the
//! length its frame implies (the input less the 102-byte header, the 32-byte
//! IV and the 16-byte tag). The writer encrypts under a random key id and IV,
//! so its bytes are not compared; its round trip is the input as a plaintext:
//! `encrypt` to the recipient, then `decrypt` returns the input.
use bsv_rs::messages::{decrypt, encrypt, ENCRYPTED_VERSION};
use bsv_rs::primitives::PrivateKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The header: version, sender, recipient, key id.
const HEADER: usize = 4 + 33 + 33 + 32;

/// Fixed test keys from constants, never a real key: the sender, the
/// recipient, and another.
fn keys() -> &'static [PrivateKey; 3] {
    static KEYS: OnceLock<[PrivateKey; 3]> = OnceLock::new();
    KEYS.get_or_init(|| [6u8, 7, 8].map(|b| PrivateKey::from_bytes(&[b; 32]).expect("a fixed key")))
}

fuzz_target!(|data: &[u8]| {
    let [sender, recipient, other] = keys();
    if let Ok(plaintext) = decrypt(data, recipient) {
        assert_eq!(plaintext.len() + HEADER + 32 + 16, data.len());
    }
    let _ = decrypt(data, other);

    let sealed = encrypt(data, sender, &recipient.public_key()).expect("a fixed key encrypts");
    assert_eq!(&sealed[..4], &ENCRYPTED_VERSION);
    assert_eq!(sealed.len(), data.len() + HEADER + 32 + 16);
    assert_eq!(decrypt(&sealed, recipient).ok().as_deref(), Some(data));
});
