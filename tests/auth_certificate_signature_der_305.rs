//! A certificate signature's DER, parsed and re-encoded on `Certificate` as
//! the reference does (#305), each case's verdict the reference's at
//! `ts-stack@edf6e03` under Node v22.18.0
//! (`tests/support/certificate_signature_der_305.mjs`,
//! `tests/vectors/auth_certificate_signature_der_305.json`):
//!
//! - `toBinary` parses the signature with `Signature.fromDER` and writes the
//!   bytes it was given (`Certificate.ts:309-311`): a DER `fromDER` refuses
//!   is refused in its words, one it reads out of DER's form is written as
//!   given;
//! - `fromBinary` parses the bytes after the fields with `fromDER` and keeps
//!   `toDER`'s re-encoding (`:395-397`): a refused DER refuses the frame, one
//!   out of form is held re-encoded (a zero byte before a high bit restored,
//!   an empty integer `02 01 00`, which `toBinary` then refuses: `fromDER`
//!   refuses the zero byte its own `toDER` wrote for a zero `r`);
//! - `verify` parses the held signature with `fromDER` and verifies its
//!   `(r, s)` (`:432-435`): `false` for a DER it refuses, the ECDSA verdict
//!   for one it reads, whatever its form.
//!
//! One certificate: certifier 43, subject 47, type 32 bytes of 1, serial 32
//! bytes of 2, the zero outpoint, one field `f00`; the frames are this crate's
//! unsigned prefix with the signature's bytes appended, the prefix checked
//! against the reference's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::primitives::{from_hex, to_hex, PrivateKey};
use bsv_rs::Error;
use indexmap::IndexMap;
use serde_json::Value;
use std::sync::OnceLock;

/// The cases' ids, in the vector's order.
const IDS: [&str; 13] = [
    "canonical",
    "r_without_its_zero_byte",
    "high_s",
    "empty_r",
    "s_excessively_padded",
    "r_excessively_padded",
    "long_form_length",
    "trailing_byte",
    "sequence_length_short",
    "s_length_long",
    "s_length_missing",
    "set_tag",
    "r_tag",
];

fn vector() -> &'static Value {
    static VECTOR: OnceLock<Value> = OnceLock::new();
    VECTOR.get_or_init(|| {
        let text = include_str!("vectors/auth_certificate_signature_der_305.json");
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["reference"], "ts-stack@edf6e03 packages/sdk");
        v
    })
}

fn cases() -> &'static Vec<Value> {
    vector()["cases"].as_array().unwrap()
}

fn case(id: &str) -> &'static Value {
    cases().iter().find(|c| c["id"] == id).unwrap()
}

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

fn certificate(signature: Option<Vec<u8>>) -> Certificate {
    let value = vector()["field_value"].as_str().unwrap().to_string();
    Certificate::new([1; 32], [2; 32], key(47).public_key(), key(43).public_key())
        .with_fields(IndexMap::from([("f00".to_string(), value)]))
        .with_signature(signature)
}

fn signature(c: &Value) -> Vec<u8> {
    from_hex(c["signature"].as_str().unwrap()).unwrap()
}

fn frame(c: &Value) -> Vec<u8> {
    let mut bytes = certificate(None).to_binary(false).unwrap();
    bytes.extend_from_slice(&signature(c));
    bytes
}

/// The reference's words, refused as this crate's other certificate
/// refusals are (#297, #301).
fn refusal(verdict: &Value) -> Option<Error> {
    verdict["error"]
        .as_str()
        .map(|w| Error::CertificateValidationError(w.to_string()))
}

#[test]
fn the_vector_holds_the_thirteen_cases_and_this_crates_unsigned_prefix() {
    let ids: Vec<&str> = cases().iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids, IDS);
    assert_eq!(
        to_hex(&certificate(None).to_binary(false).unwrap()),
        vector()["unsigned_prefix"].as_str().unwrap()
    );
    // The canonical signature is this crate's signer's too (RFC 6979).
    let mut signed = certificate(None);
    signed.sign(&key(43)).unwrap();
    assert_eq!(signed.signature.unwrap(), signature(case("canonical")));
}

#[test]
fn a_canonical_der_signature_round_trips_unchanged() {
    let c = case("canonical");
    let read = Certificate::from_binary(&frame(c)).unwrap();
    assert_eq!(read.signature.as_deref(), Some(&signature(c)[..]));
    assert_eq!(read.to_binary(true).unwrap(), frame(c));
    assert_eq!(read.verify(), Ok(true));
}

#[test]
fn from_binary_keeps_the_signature_to_der_re_encodes_or_refuses_in_from_der_words() {
    for c in cases() {
        let id = c["id"].as_str().unwrap();
        let expected = &c["from_binary"];
        match (Certificate::from_binary(&frame(c)), refusal(expected)) {
            (Ok(read), None) => {
                let ok = &expected["ok"];
                assert_eq!(
                    to_hex(read.signature.as_deref().unwrap()),
                    ok["signature"].as_str().unwrap(),
                    "{id}: the signature held"
                );
                assert_eq!(read.verify(), Ok(ok["verify"].as_bool().unwrap()), "{id}");
                // Written back as held, or refused where the reference's
                // own `toDER` wrote a form its `fromDER` refuses (`02 01 00`).
                let unsigned = read.to_binary(false).unwrap();
                match (read.to_binary(true), refusal(&ok["written"])) {
                    (Ok(written), None) => assert_eq!(
                        to_hex(&written[unsigned.len()..]),
                        ok["written"]["ok"].as_str().unwrap(),
                        "{id}: written back"
                    ),
                    (Err(got), Some(want)) => assert_eq!(got, want, "{id}: written back"),
                    (got, want) => panic!("{id}: written back {got:?}, the reference {want:?}"),
                }
            }
            (Err(got), Some(want)) => assert_eq!(got, want, "{id}"),
            (got, want) => panic!("{id}: got {got:?}, the reference {want:?}"),
        }
    }
}

#[test]
fn to_binary_writes_the_signature_as_given_or_refuses_in_from_der_words() {
    for c in cases() {
        let id = c["id"].as_str().unwrap();
        let expected = &c["to_binary"];
        let cert = certificate(Some(signature(c)));
        match (cert.to_binary(true), refusal(expected)) {
            (Ok(bytes), None) => {
                let unsigned = cert.to_binary(false).unwrap();
                assert_eq!(
                    to_hex(&bytes[unsigned.len()..]),
                    expected["ok"].as_str().unwrap(),
                    "{id}"
                );
                assert_eq!(bytes[unsigned.len()..], signature(c)[..], "{id}: as given");
            }
            (Err(got), Some(want)) => assert_eq!(got, want, "{id}"),
            (got, want) => panic!("{id}: got {got:?}, the reference {want:?}"),
        }
        // The prefix alone never reads the signature.
        assert!(cert.to_binary(false).is_ok(), "{id}");
    }
}

#[test]
fn verify_answers_the_reference_verdict_on_every_der() {
    for c in cases() {
        let id = c["id"].as_str().unwrap();
        let want = c["verify"]["ok"].as_bool().unwrap();
        assert_eq!(certificate(Some(signature(c))).verify(), Ok(want), "{id}");
    }
}

#[test]
fn a_der_out_of_form_written_as_given_reads_back_re_encoded() {
    // `r` without its zero byte: `toBinary` writes it, `fromBinary` restores
    // the byte, and the certificate verifies either way.
    let c = case("r_without_its_zero_byte");
    let given = certificate(Some(signature(c)));
    let written = given.to_binary(true).unwrap();
    assert!(written.ends_with(&signature(c)));
    let read = Certificate::from_binary(&written).unwrap();
    assert_eq!(read.signature.unwrap(), signature(case("canonical")));
    assert_eq!(given.verify(), Ok(true));
}

#[test]
fn a_der_cut_after_its_second_tag_is_refused_in_the_reference_words() {
    // `getLength` reads past the end (`undefined`), and the length check
    // after it throws (`Signature.ts:76-78`), at every site.
    let c = case("s_length_missing");
    let words = Error::CertificateValidationError("Invalid R-length in signature DER".into());
    assert_eq!(c["from_der"]["error"], "Invalid R-length in signature DER");
    assert_eq!(
        Certificate::from_binary(&frame(c)).err(),
        Some(words.clone())
    );
    assert_eq!(
        certificate(Some(signature(c))).to_binary(true).err(),
        Some(words)
    );
    assert_eq!(certificate(Some(signature(c))).verify(), Ok(false));
}

#[test]
fn an_empty_signature_is_written_as_nothing() {
    // `toBinary` writes no signature for an empty one and checks nothing
    // (`(this.signature ?? '').length > 0`, `Certificate.ts:300`).
    let cert = certificate(Some(Vec::new()));
    assert_eq!(
        cert.to_binary(true).unwrap(),
        cert.to_binary(false).unwrap()
    );
    assert_eq!(cert.verify(), Ok(false));
}
