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
use bsv_rs::wallet::types::Outpoint;
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
    cert.fields.insert("f".into(), "dGFtcGVyZWQ=".to_string());
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
    let certifier = key(21);
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

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", scalar)).unwrap()
}

#[test]
fn a_certificate_signed_here_over_mixed_case_names_verifies_in_the_reference() {
    let w = witness("rust_signed_mixed_names");
    assert_eq!(w.reference_verify, Some(true));
    let names = Certificate::from_binary(&bytes(&witness("reference_signed_mixed_names")))
        .unwrap()
        .fields;
    let mut cert = Certificate::new(
        [8u8; 32],
        [9u8; 32],
        key(27).public_key(),
        key(25).public_key(),
    )
    .with_revocation_outpoint(Some(Outpoint::new([10u8; 32], 1)))
    .with_fields(names);
    cert.sign(&key(25)).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true)), w.hex);
}

#[test]
fn a_certificate_rebuilt_from_json_signs_in_the_reference_order() {
    let w = witness("reference_signed_mixed_names");
    let read = Certificate::from_binary(&bytes(&w)).unwrap();
    let json = serde_json::to_string(&read).unwrap();
    let mut rebuilt: Certificate = serde_json::from_str(&json).unwrap();
    assert_eq!(rebuilt.received_unsigned, None);

    // Its signature verifies over the serializer's order, the reference's.
    assert_eq!(rebuilt.verify(), Ok(true));
    assert_eq!(to_hex(&rebuilt.to_binary(true)), w.hex);

    // Signed again here, it is the reference's bytes.
    rebuilt.set_signature(None);
    rebuilt.sign(&key(21)).unwrap();
    assert_eq!(to_hex(&rebuilt.to_binary(true)), w.hex);
}

#[test]
fn a_byte_order_certificate_signed_again_signs_in_the_reference_order() {
    // A certificate read in byte order (Go's, or this crate's before #249),
    // its signature cleared and signed again: the reference's `sign`
    // serializes afresh (`ts-stack@edf6e03` `Certificate.ts:458`), so the
    // received byte order is not the preimage.
    let mut cert =
        Certificate::from_binary(&bytes(&witness("byte_order_signed_mixed_names"))).unwrap();
    cert.set_signature(None);
    cert.sign(&key(21)).unwrap();
    assert_eq!(
        to_hex(&cert.to_binary(true)),
        witness("reference_signed_mixed_names").hex
    );
    assert_eq!(cert.verify(), Ok(true));
}

/// The field names of an unsigned prefix, in the order written.
fn names_written(unsigned: &[u8]) -> Vec<String> {
    fn varint(b: &[u8], at: &mut usize) -> usize {
        let lead = b[*at];
        *at += 1;
        match lead {
            0xfd => {
                let n = u16::from_le_bytes([b[*at], b[*at + 1]]) as usize;
                *at += 2;
                n
            }
            0xfe | 0xff => panic!("no name list this long"),
            n => n as usize,
        }
    }
    let mut at = 32 + 32 + 33 + 33 + 32;
    varint(unsigned, &mut at); // the revocation index
    let count = varint(unsigned, &mut at);
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let n = varint(unsigned, &mut at);
        names.push(String::from_utf8(unsigned[at..at + n].to_vec()).unwrap());
        at += n;
        let v = varint(unsigned, &mut at);
        at += v;
    }
    assert_eq!(at, unsigned.len());
    names
}

#[test]
fn the_serializer_orders_names_as_local_compare_does_on_the_latin_1_corpus() {
    #[derive(Deserialize)]
    struct Corpus {
        collation_corpus: Vec<String>,
    }
    let data = std::fs::read_to_string("tests/vectors/auth_certificate_field_order_249.json")
        .expect("read the #249 witnesses");
    let corpus: Corpus = serde_json::from_str(&data).unwrap();
    assert_eq!(corpus.collation_corpus.len(), 1402);

    let fields: HashMap<String, String> = corpus
        .collation_corpus
        .iter()
        .map(|n| (n.clone(), String::new()))
        .collect();
    let cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        key(3).public_key(),
        key(5).public_key(),
    )
    .with_fields(fields);
    assert_eq!(
        names_written(&cert.to_binary(false)),
        corpus.collation_corpus
    );
}

#[test]
fn the_six_witness_names_are_written_a_b_a0_age_ea_f_name() {
    let read = Certificate::from_binary(&bytes(&witness("byte_order_signed_mixed_names"))).unwrap();
    let rebuilt = Certificate::new(
        read.cert_type,
        read.serial_number,
        read.subject.clone(),
        read.certifier.clone(),
    )
    .with_fields(read.fields.clone());
    assert_eq!(
        names_written(&rebuilt.to_binary(false)),
        ["a_b", "a0", "age", "éa", "f", "Name"]
    );
    // The byte order it was received in is kept for the received bytes.
    assert_eq!(
        names_written(&read.to_binary(false)),
        ["Name", "a0", "a_b", "age", "f", "éa"]
    );
}
