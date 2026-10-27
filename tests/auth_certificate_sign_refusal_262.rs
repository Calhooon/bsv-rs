//! `Certificate::sign` on a certificate already signed (#262): refused in
//! the reference's words, the present signature's hex in them
//! (`ts-stack@edf6e03` `Certificate.ts:450-453`), the certificate unchanged;
//! cleared with `set_signature(None)`, it signs to a single signing's bytes.
//! Go refuses too, in its own words (`go-sdk@2ca481c`
//! `auth/certificates/certificate.go:22,209-211`, `ErrAlreadySigned`).
//!
//! The witness is `tests/vectors/auth_certificate_sign_refusal_262.json`,
//! recorded by `tests/support/certificate_sign_refusal_262.mjs` under Node
//! v22.18.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::primitives::{to_base64, to_hex, PrivateKey};
use bsv_rs::Error;
use serde::Deserialize;

#[derive(Deserialize)]
struct Witness {
    signed_once: String,
    refusal: String,
    unchanged_by_refusal: bool,
    signed_after_clearing: String,
}

fn witness() -> Witness {
    let data = std::fs::read_to_string("tests/vectors/auth_certificate_sign_refusal_262.json")
        .expect("read the #262 witness");
    serde_json::from_str(&data).expect("parse the #262 witness")
}

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", scalar)).unwrap()
}

/// #251's one-field `email` certificate, unsigned.
fn email(certifier: &PrivateKey) -> Certificate {
    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        key(9).public_key(),
        certifier.public_key(),
    );
    cert.fields.insert("email".into(), to_base64(b"v-email"));
    cert
}

#[test]
fn a_signed_certificate_signed_again_is_refused_in_the_reference_words() {
    let w = witness();
    assert!(w.unchanged_by_refusal);
    let certifier = key(7);
    let mut cert = email(&certifier);
    cert.sign(&certifier).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true).unwrap()), w.signed_once);

    assert_eq!(
        cert.sign(&certifier),
        Err(Error::CertificateValidationError(w.refusal))
    );
    assert_eq!(to_hex(&cert.to_binary(true).unwrap()), w.signed_once);
    assert_eq!(cert.verify(), Ok(true));
}

#[test]
fn a_signed_certificate_is_refused_before_the_certifier_key_is_read() {
    // The reference reads the signature ahead of anything else
    // (`Certificate.ts:450-453`): another key is refused for the signature.
    let w = witness();
    let certifier = key(7);
    let mut cert = email(&certifier);
    cert.sign(&certifier).unwrap();
    assert_eq!(
        cert.sign(&key(8)),
        Err(Error::CertificateValidationError(w.refusal))
    );
}

#[test]
fn a_cleared_signature_signs_to_a_single_signing_bytes() {
    let w = witness();
    let certifier = key(7);
    let mut cert = email(&certifier);
    cert.sign(&certifier).unwrap();
    cert.set_signature(None);
    cert.sign(&certifier).unwrap();
    assert_eq!(
        to_hex(&cert.to_binary(true).unwrap()),
        w.signed_after_clearing
    );
    assert_eq!(w.signed_after_clearing, w.signed_once);
}

#[test]
fn an_empty_signature_is_no_signature_to_sign() {
    // The reference refuses a signature of length above 0 only
    // (`this.signature.length > 0`, `Certificate.ts:450`).
    let w = witness();
    let certifier = key(7);
    let mut cert = email(&certifier).with_signature(Some(Vec::new()));
    cert.sign(&certifier).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true).unwrap()), w.signed_once);
}
