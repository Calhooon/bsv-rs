#![no_main]
//! ECIES (`compat::ecies`, Electrum and Bitcore) on arbitrary input: every
//! decryptor on the input as a ciphertext (binary and base64). The assertion
//! is that each returns; the target also checks a round trip: the input as a
//! plaintext, encrypted by each scheme, decrypts to itself.
use bsv_rs::compat::ecies::{
    bitcore_decrypt, bitcore_encrypt, decrypt_shared_base64, decrypt_single, decrypt_single_base64,
    electrum_decrypt, electrum_encrypt, encrypt_shared_base64, encrypt_single,
};
use bsv_rs::primitives::PrivateKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn keys() -> &'static (PrivateKey, PrivateKey) {
    static KEYS: OnceLock<(PrivateKey, PrivateKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        (
            PrivateKey::from_bytes(&[1; 32]).expect("a fixed key"),
            PrivateKey::from_bytes(&[2; 32]).expect("a fixed key"),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let (to, from) = keys();
    let from_public = from.public_key();

    let _ = electrum_decrypt(data, to, None);
    let _ = electrum_decrypt(data, to, Some(&from_public));
    let _ = bitcore_decrypt(data, to);
    let _ = decrypt_single(data, to);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decrypt_single_base64(text, to);
        let _ = decrypt_shared_base64(text, to, &from_public);
    }

    let to_public = to.public_key();
    for no_key in [false, true] {
        let sealed = electrum_encrypt(data, &to_public, from, no_key).expect("electrum seals");
        if no_key && sealed.len() > 69 {
            // bsv-rs#109: a no-key envelope over 69 bytes reads as one that
            // embeds a key; skipped until the ruling, so the rest is fuzzed.
            continue;
        }
        let sender = no_key.then_some(&from_public);
        assert_eq!(
            electrum_decrypt(&sealed, to, sender).expect("electrum opens"),
            data
        );
    }
    let iv: Option<[u8; 16]> = data.get(..16).map(|b| b.try_into().expect("sixteen bytes"));
    let sealed = bitcore_encrypt(data, &to_public, from, iv.as_ref()).expect("bitcore seals");
    assert_eq!(bitcore_decrypt(&sealed, to).expect("bitcore opens"), data);
    let sealed = encrypt_single(data, to).expect("single seals");
    assert_eq!(decrypt_single(&sealed, to).expect("single opens"), data);
    let sealed = encrypt_shared_base64(data, &to_public, from).expect("shared seals");
    assert_eq!(
        decrypt_shared_base64(&sealed, to, &from_public).expect("shared opens"),
        data
    );
});
