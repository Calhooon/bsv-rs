#![no_main]
//! The BRC-77 signed message reader, `messages::verify`, on arbitrary
//! signature bytes: verified for the fixed recipient, for no recipient (the
//! anyone form) and for a recipient other than the one named. The message is
//! the fixed `MESSAGE` (the one the seeds sign), so a seed reaches the
//! signature check. The assertion is that each returns. The reader decodes no
//! value to write again; the writer's round trip is the input as a message:
//! `sign` for the recipient and for anyone, each verified as true by its
//! verifier and as the sender's, the version at the head.
use bsv_rs::messages::{sign, verify, SIGNED_VERSION};
use bsv_rs::primitives::PrivateKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The message the seeds sign (`fuzz/corpus-gen`).
const MESSAGE: &[u8] = b"fuzz_messages_signed";

/// Fixed test keys from constants, never a real key: the sender, the
/// recipient, and another.
fn keys() -> &'static [PrivateKey; 3] {
    static KEYS: OnceLock<[PrivateKey; 3]> = OnceLock::new();
    KEYS.get_or_init(|| [6u8, 7, 8].map(|b| PrivateKey::from_bytes(&[b; 32]).expect("a fixed key")))
}

fuzz_target!(|data: &[u8]| {
    let [sender, recipient, other] = keys();
    let _ = verify(MESSAGE, data, None);
    let _ = verify(data, data, None);
    // A short signature naming the given key panics until bsv-rs#173 is
    // fixed; a panic inside the crate is never skipped (#108).
    let _ = verify(MESSAGE, data, Some(recipient));
    let _ = verify(MESSAGE, data, Some(other));

    for verifier in [Some(recipient), None] {
        let signed = sign(data, sender, verifier.map(|k| k.public_key()).as_ref())
            .expect("a fixed key signs");
        assert_eq!(&signed[..4], &SIGNED_VERSION);
        assert_eq!(&signed[4..37], &sender.public_key().to_compressed()[..]);
        assert_eq!(verify(data, &signed, verifier).ok(), Some(true));
    }
});
