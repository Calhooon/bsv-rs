//! `Certificate::verify` answers `false`, never an error (#299), as the
//! reference's `verify` does: it catches every failure under it and returns
//! `false`, "the historical boolean verification contract. Malformed or
//! absent signatures are invalid credentials, not exceptional control flow"
//! (`ts-stack@edf6e03` `packages/sdk/src/auth/certificates/Certificate.ts:425-440`).
//! go-sdk@2ca481c's `Verify` returns an error instead (`ErrNotSigned`,
//! `failed to parse signature`, `ErrInvalidSignature`;
//! `auth/certificates/certificate.go:150-204`).
//!
//! The witnesses are `tests/vectors/auth_certificate_verify_false_299.json`:
//! one certificate under nine signatures, each with the reference's verdict,
//! recorded by `tests/support/certificate_verify_false_299.mjs` under Node
//! v22.18.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::auth::{validate_certificates, AuthMessage, MessageType};
use bsv_rs::primitives::{from_hex, to_base64, to_hex, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Witnesses {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    signature_hex: Option<String>,
    reference_verify: bool,
    threw: bool,
}

fn witnesses() -> Vec<Witness> {
    let data = std::fs::read_to_string("tests/vectors/auth_certificate_verify_false_299.json")
        .expect("read the #299 witnesses");
    let file: Witnesses = serde_json::from_str(&data).expect("parse the #299 witnesses");
    file.witnesses
}

fn witness(name: &str) -> Witness {
    witnesses()
        .into_iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("no witness {name}"))
}

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", scalar)).unwrap()
}

/// The script's certificate: certifier 7, subject 9, type 32 x 1, serial
/// 32 x 2, the zero outpoint, `email` = base64 of "v-email".
fn certificate(signature: Option<Vec<u8>>) -> Certificate {
    let fields = HashMap::from([("email".to_string(), to_base64(b"v-email"))]);
    Certificate::new([1; 32], [2; 32], key(9).public_key(), key(7).public_key())
        .with_fields(fields)
        .with_signature(signature)
}

fn witness_certificate(w: &Witness) -> Certificate {
    certificate(w.signature_hex.as_deref().map(|h| from_hex(h).unwrap()))
}

#[test]
fn every_witness_this_crate_can_hold_verifies_to_the_references_verdict() {
    let all = witnesses();
    assert_eq!(all.len(), 9);
    for w in all.iter().filter(|w| w.name != "not_hex") {
        assert!(!w.threw, "{}: the reference threw", w.name);
        assert_eq!(
            witness_certificate(w).verify(),
            Ok(w.reference_verify),
            "{}",
            w.name
        );
    }
}

#[test]
fn the_valid_witness_is_this_crates_own_signature() {
    let mut cert = certificate(None);
    cert.sign(&key(7)).unwrap();
    assert_eq!(
        Some(to_hex(cert.signature.as_ref().unwrap())),
        witness("valid").signature_hex
    );
}

#[test]
fn an_unsigned_certificate_verifies_false_not_an_error() {
    let w = witness("absent");
    assert!(!w.reference_verify);
    assert_eq!(certificate(None).verify(), Ok(false));
}

#[test]
fn an_empty_signature_verifies_false_not_an_error() {
    assert_eq!(witness("empty").signature_hex.as_deref(), Some(""));
    assert_eq!(certificate(Some(Vec::new())).verify(), Ok(false));
}

#[test]
fn a_non_der_signature_verifies_false_not_an_error() {
    for name in ["not_der", "truncated_der", "zero_r"] {
        let w = witness(name);
        assert!(!w.reference_verify, "{name}");
        assert_eq!(witness_certificate(&w).verify(), Ok(false), "{name}");
    }
}

#[test]
fn a_certificate_signed_by_another_key_verifies_false() {
    let w = witness("other_key");
    assert!(!w.reference_verify);
    assert_eq!(witness_certificate(&w).verify(), Ok(false));
}

/// The reference holds the signature as hex text and answers `false` to
/// text that is not hex; this crate holds bytes, so that text is refused
/// where it is read, at the certificate's JSON, before any verdict.
#[test]
fn a_non_hex_signature_is_refused_at_the_json_this_crate_reads_it_from() {
    let w = witness("not_hex");
    assert!(!w.reference_verify && !w.threw);
    let mut json = serde_json::to_value(certificate(None)).unwrap();
    json["signature"] = serde_json::Value::String(w.signature_hex.unwrap());
    assert!(serde_json::from_value::<Certificate>(json).is_err());
}

#[test]
fn the_master_and_verifiable_certificates_verify_false_not_an_error() {
    let keyring = HashMap::from([("email".to_string(), to_base64(&[0x41; 48]))]);
    let master = MasterCertificate::new(certificate(None), keyring.clone()).unwrap();
    assert_eq!(master.verify(), Ok(false));
    let verifiable = VerifiableCertificate::new(certificate(None), keyring);
    assert_eq!(verifiable.verify(), Ok(false));
    let not_der = VerifiableCertificate::new(
        certificate(Some(vec![0x30, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
        HashMap::new(),
    );
    assert_eq!(not_der.verify(), Ok(false));
}

/// `validateCertificates` throws its own words on a `false` verdict
/// (`ts-stack@edf6e03` `packages/sdk/src/auth/utils/validateCertificates.ts:99-104`),
/// the serial number its base64 text.
#[tokio::test]
async fn validate_certificates_refuses_an_unsigned_certificate_in_the_references_words() {
    let serial = to_base64(&[2; 32]);
    for signature in [
        None,
        Some(vec![0x30, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ] {
        let mut message = AuthMessage::new(MessageType::CertificateResponse, key(9).public_key());
        message.set_certificates(vec![VerifiableCertificate::new(
            certificate(signature),
            HashMap::new(),
        )]);
        let verifier = ProtoWallet::new(Some(key(5)));
        assert_eq!(
            validate_certificates(&verifier, &message, None, Some("test")).await,
            Err(Error::AuthError(format!(
                "The signature for the certificate with serial number {serial} is invalid!"
            )))
        );
    }
}
