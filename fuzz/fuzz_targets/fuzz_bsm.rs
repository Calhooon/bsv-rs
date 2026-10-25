#![no_main]
//! The Bitcoin Signed Message envelope's readers (`compat::bsm`) on arbitrary
//! input: the leading 65 bytes as a compact signature over the rest as the
//! message (`recover_public_key_from_signature`, `verify_message` for the
//! fixed key's address), the input as a DER signature (`verify_message_der`),
//! and the text before a newline as a base64 compact signature over the text
//! after it, as an envelope travels. The assertion is that each returns; a
//! signature that recovers a key verifies for that key's address (the
//! envelope's canonical reading). The writer's round trip is the input as a
//! message: `sign_message_with_compression` with the fixed key, both
//! compressions, recovers that key with the compression it wrote and
//! verifies; the signer is deterministic (RFC 6979), so it writes the same
//! bytes twice.
use bsv_rs::compat::bsm::{
    recover_public_key_from_signature, sign_message_with_compression, verify_message,
    verify_message_der,
};
use bsv_rs::primitives::hash::hash160;
use bsv_rs::primitives::{from_base64, to_base58_check, PrivateKey, PublicKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A fixed test key from a constant, never a real key.
fn key() -> &'static PrivateKey {
    static KEY: OnceLock<PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| PrivateKey::from_bytes(&[9; 32]).expect("a fixed key"))
}

fn address(key: &PublicKey, compressed: bool) -> String {
    if compressed {
        key.to_address()
    } else {
        to_base58_check(&hash160(&key.to_uncompressed()), &[0x00])
    }
}

fn compact(signature: &[u8], message: &[u8]) {
    if let Ok((recovered, compressed)) = recover_public_key_from_signature(signature, message) {
        let ours = address(&recovered, compressed);
        assert_eq!(verify_message(&ours, signature, message).ok(), Some(true));
    }
    let _ = verify_message(&key().public_key().to_address(), signature, message);
}

fuzz_target!(|data: &[u8]| {
    if data.len() >= 65 {
        let (signature, message) = data.split_at(65);
        compact(signature, message);
    }
    let _ = verify_message_der(data, &key().public_key(), b"");
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some((signature, message)) = text.split_once('\n') {
            if let Ok(signature) = from_base64(signature) {
                compact(&signature, message.as_bytes());
            }
        }
    }

    for compressed in [true, false] {
        let signature = sign_message_with_compression(key(), data, compressed).expect("signs");
        assert_eq!(signature.len(), 65);
        assert_eq!(
            sign_message_with_compression(key(), data, compressed)
                .ok()
                .as_deref(),
            Some(&signature[..])
        );
        let (recovered, was) =
            recover_public_key_from_signature(&signature, data).expect("its own signature");
        assert_eq!(
            recovered.to_compressed(),
            key().public_key().to_compressed()
        );
        assert_eq!(was, compressed);
        let ours = address(&recovered, compressed);
        assert_eq!(verify_message(&ours, &signature, data).ok(), Some(true));
    }
});
