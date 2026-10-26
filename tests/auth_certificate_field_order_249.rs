//! A certificate's field order (#249).
//!
//! The reference orders the field names by `localeCompare` under Node's
//! default collation (`ts-stack@edf6e03` `Certificate.ts:282`), and BRC-52
//! asks a binary reader to keep the issuer's bytes (`brcs@5119a9b`
//! `peer-to-peer/0052.md:99-103`). The witnesses
//! (`tests/vectors/auth_certificate_field_order_249.json`) are written by
//! `tests/support/certificate_field_order_249.mjs` against the reference at
//! `ts-stack@edf6e03` under Node v22.18.0, each with the reference's verdict.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::Certificate;
use bsv_rs::primitives::{from_hex, to_hex, PrivateKey};
use bsv_rs::Error;
use serde::Deserialize;

#[derive(Deserialize)]
struct Witnesses {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    reference_verify: Option<bool>,
    reference_from_binary: Option<String>,
    hex: String,
}

fn witness(name: &str) -> Witness {
    let data = std::fs::read_to_string("tests/vectors/auth_certificate_field_order_249.json")
        .expect("read the #249 witnesses");
    let file: Witnesses = serde_json::from_str(&data).expect("parse the #249 witnesses");
    file.witnesses
        .into_iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("no witness {name}"))
}

fn bytes(w: &Witness) -> Vec<u8> {
    from_hex(&w.hex).unwrap()
}

#[test]
fn a_reference_signed_certificate_over_mixed_case_names_verifies_over_the_bytes_received() {
    let w = witness("reference_signed_mixed_names");
    assert_eq!(w.reference_verify, Some(true));
    let cert = Certificate::from_binary(&bytes(&w)).unwrap();
    assert_eq!(cert.verify(), Ok(true));
}

#[test]
fn a_byte_order_signed_certificate_verifies_over_the_bytes_received_where_the_reference_re_sorts() {
    let w = witness("byte_order_signed_mixed_names");
    assert_eq!(w.reference_verify, Some(false));
    let cert = Certificate::from_binary(&bytes(&w)).unwrap();
    assert_eq!(cert.verify(), Ok(true));
}

#[test]
fn from_binary_then_to_binary_writes_the_issuers_bytes_unchanged() {
    for name in [
        "reference_signed_mixed_names",
        "byte_order_signed_mixed_names",
    ] {
        let w = witness(name);
        let cert = Certificate::from_binary(&bytes(&w)).unwrap();
        assert_eq!(to_hex(&cert.to_binary(true)), w.hex, "{name}");
        let unsigned = cert.to_binary(false);
        assert_eq!(cert.received_unsigned.as_deref(), Some(&unsigned[..]));
        assert_eq!(
            unsigned.len() + cert.signature.as_ref().unwrap().len(),
            bytes(&w).len()
        );
    }
}

#[test]
fn a_repeated_field_name_is_refused_as_the_reference_refuses_it() {
    let w = witness("repeated_field_name");
    let words = w.reference_from_binary.clone().unwrap();
    assert_eq!(
        Certificate::from_binary(&bytes(&w)).unwrap_err(),
        Error::CertificateValidationError(words)
    );
}

#[test]
fn a_field_changed_after_from_binary_unbinds_the_received_bytes() {
    let w = witness("byte_order_signed_mixed_names");
    let mut cert = Certificate::from_binary(&bytes(&w)).unwrap();
    let original = cert.fields["f"].clone();

    // Through the public field: the retained bytes no longer carry the
    // value, so they authenticate nothing and are not written.
    cert.fields.insert("f".into(), b"dGFtcGVyZWQ=".to_vec());
    assert_eq!(cert.verify(), Ok(false));
    assert_ne!(to_hex(&cert.to_binary(true)), w.hex);

    // The value restored: the bytes bind again.
    cert.fields.insert("f".into(), original.clone());
    assert_eq!(cert.verify(), Ok(true));
    assert_eq!(to_hex(&cert.to_binary(true)), w.hex);

    // A setter that changes a value in the preimage clears them, even to
    // the same value.
    cert.set_field("f", original);
    assert_eq!(cert.received_unsigned, None);

    // The signature is outside the preimage: its setter keeps them.
    let mut cert = Certificate::from_binary(&bytes(&w)).unwrap();
    let sig = cert.signature.clone();
    cert.set_signature(sig);
    assert!(cert.received_unsigned.is_some());
    assert_eq!(cert.verify(), Ok(true));
}

#[test]
fn received_bytes_carrying_other_values_are_never_used() {
    // Bytes set by hand that do not read back to the certificate's values
    // are ignored: verify and to_binary use the serializer.
    let a = Certificate::from_binary(&bytes(&witness("reference_signed_mixed_names"))).unwrap();
    let mut b = Certificate::from_binary(&bytes(&witness("byte_order_signed_mixed_names")))
        .unwrap()
        .with_fields(Default::default());
    b.received_unsigned = a.received_unsigned.clone();
    assert_eq!(b.to_binary(false).last(), Some(&0u8)); // a field count of 0
    assert_eq!(b.verify(), Ok(false));
}

#[test]
fn a_certificate_signed_here_keeps_the_preimage_it_signed() {
    let certifier = PrivateKey::from_hex(&format!("{:064x}", 21)).unwrap();
    let w = witness("byte_order_signed_mixed_names");
    let read = Certificate::from_binary(&bytes(&w)).unwrap();
    let mut cert = Certificate::new(
        read.cert_type,
        read.serial_number,
        read.subject.clone(),
        read.certifier.clone(),
    )
    .with_fields(read.fields.clone());
    cert.sign(&certifier).unwrap();
    assert_eq!(
        cert.received_unsigned.as_deref(),
        Some(&cert.to_binary(false)[..])
    );
    assert_eq!(cert.verify(), Ok(true));
}
