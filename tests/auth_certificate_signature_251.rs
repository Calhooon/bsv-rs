//! BRC-52's certificate signature (#251): `Certificate::sign` and `verify`
//! use the certifier's child under protocol `[2, "certificate signature"]`,
//! keyID `"<type> <serialNumber>"` and counterparty anyone (BRC-52 at
//! `5119a9b` `0052.md:77,115-117`), as the reference does
//! (`ts-stack@edf6e03` `Certificate.ts:428-431,458-462`) and Go
//! (`go-sdk@2ca481c` `auth/certificates/certificate.go:176-186,227-240`).
//!
//! The witnesses are `tests/vectors/auth_certificate_signature_251.json`;
//! each carries the reference's verdict, recorded by
//! `tests/support/certificate_signature_251.mjs` under Node v22.18.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::primitives::{from_hex, to_base64, to_hex, PrivateKey, Signature};
use bsv_rs::wallet::types::Outpoint;
use serde::Deserialize;

#[derive(Deserialize)]
struct Witnesses {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    reference_verify: bool,
    hex: String,
}

fn witness(name: &str) -> Witness {
    let data = std::fs::read_to_string("tests/vectors/auth_certificate_signature_251.json")
        .expect("read the #251 witnesses");
    let file: Witnesses = serde_json::from_str(&data).expect("parse the #251 witnesses");
    file.witnesses
        .into_iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("no witness {name}"))
}

fn certificate(w: &Witness) -> Certificate {
    Certificate::from_binary(&from_hex(&w.hex).unwrap()).unwrap()
}

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", scalar)).unwrap()
}

/// The certifier's raw key over the preimage: 0.9.0-beta.1's reading.
fn verifies_under_raw_key(cert: &Certificate) -> bool {
    let sig = Signature::from_der(cert.signature.as_ref().unwrap()).unwrap();
    cert.certifier.verify(&cert.signing_hash(), &sig)
}

#[test]
fn a_reference_signed_certificate_verifies_under_the_brc52_derivation() {
    let w = witness("reference_signed_email");
    assert!(w.reference_verify);
    let cert = certificate(&w);
    assert_eq!(cert.verify(), Ok(true));
    assert!(!verifies_under_raw_key(&cert));
}

#[test]
fn a_certificate_signed_here_is_the_reference_signed_bytes() {
    let w = witness("reference_signed_email");
    let certifier = key(7);
    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        key(9).public_key(),
        certifier.public_key(),
    );
    cert.set_field("email", to_base64(b"v-email"));
    cert.sign(&certifier).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true)), w.hex);
}

#[test]
fn a_certificate_signed_here_verifies_in_the_reference() {
    let w = witness("rust_signed_name");
    assert!(w.reference_verify);
    let certifier = key(11);
    let mut cert = Certificate::new(
        [3u8; 32],
        [4u8; 32],
        key(13).public_key(),
        certifier.public_key(),
    );
    cert.revocation_outpoint = Some(Outpoint::new([5u8; 32], 1));
    cert.set_field("name", to_base64(b"v-name"));
    cert.sign(&certifier).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true)), w.hex);
    assert_eq!(certificate(&w).verify(), Ok(true));
}

#[test]
fn a_wrong_certificate_signature_is_false() {
    let w = witness("wrong_signature");
    assert!(!w.reference_verify);
    assert_eq!(certificate(&w).verify(), Ok(false));
}

#[test]
fn a_certificate_signed_under_the_raw_key_by_0_9_0_beta_1_no_longer_verifies() {
    let w = witness("raw_key_signed_email");
    assert!(!w.reference_verify);
    let cert = certificate(&w);
    assert!(verifies_under_raw_key(&cert));
    assert_eq!(cert.verify(), Ok(false));
}

#[test]
fn the_signature_key_id_is_type_and_serial_with_one_space() {
    let cert = certificate(&witness("reference_signed_email"));
    assert_eq!(
        cert.signature_key_id(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    );
}
