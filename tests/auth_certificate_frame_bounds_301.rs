//! The reference's certificate frame and signature bounds on `Certificate`
//! (#301), each case's verdict the reference's at `ts-stack@edf6e03` under
//! Node v22.18.0 (`tests/support/certificate_frame_bounds_301.mjs`,
//! `tests/vectors/auth_certificate_frame_bounds_301.json`):
//!
//! - `toBinary` refuses a signature over 72 bytes before it writes it
//!   (`Invalid certificate signature encoding`, `Certificate.ts:300-307`)
//!   and a frame over 16 MiB once it has its length (`Certificate binary
//!   exceeds the maximum of 16777216 bytes`, `:315-319`), with or without the
//!   signature, so `sign` refuses an unsigned prefix over the bound (`:458`)
//!   and `verify` answers `false` to it (`:427`, `:435-439`);
//! - `fromBinary` refuses a frame over 16 MiB before it reads (`Certificate
//!   binary must be a byte array of at most 16777216 bytes`,
//!   `snapshotCertificateBinary`, `:87-91`) and more than 72 bytes after the
//!   fields (`Certificate signature exceeds the DER size limit`, `:390-394`).
//!
//! The fields are `f00`, `f01`, ... in `A`; the 1 MiB text is built once and
//! each case's values sliced from it. go-sdk@2ca481c bounds neither
//! (`auth/certificates/certificate.go:114-146`, the serializer at
//! `wallet/serializer/certificate.go:27-69`, `:71-125`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::primitives::{from_hex, sha256, to_hex, PrivateKey};
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
use bsv_rs::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

const MIB: usize = 1024 * 1024;
const FRAME_BOUND: usize = 16 * MIB;

const SITES: [(&str, usize); 4] = [
    ("to_binary", 7),
    ("from_binary", 4),
    ("verify", 1),
    ("sign", 1),
];

fn vector() -> &'static Vec<Value> {
    static VECTOR: OnceLock<Vec<Value>> = OnceLock::new();
    VECTOR.get_or_init(|| {
        let text = include_str!("vectors/auth_certificate_frame_bounds_301.json");
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["reference"], "ts-stack@edf6e03 packages/sdk");
        v["cases"].as_array().unwrap().clone()
    })
}

fn cases(site: &str) -> Vec<&'static Value> {
    vector().iter().filter(|c| c["site"] == site).collect()
}

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

/// Certifier 43, subject 47.
fn certifier() -> PrivateKey {
    key(43)
}

/// One MiB of `A`, built once: every value is a slice of it.
fn a_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| "A".repeat(MIB))
}

fn lengths(input: &Value) -> Vec<usize> {
    input["value_lengths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as usize)
        .collect()
}

fn certificate(lengths: &[usize], signature: Option<Vec<u8>>) -> Certificate {
    let fields: HashMap<String, String> = lengths
        .iter()
        .enumerate()
        .map(|(i, &n)| (format!("f{i:02}"), a_text()[..n].to_string()))
        .collect();
    Certificate::new(
        [1; 32],
        [2; 32],
        key(47).public_key(),
        certifier().public_key(),
    )
    .with_fields(fields)
    .with_signature(signature)
}

fn signature(input: &Value) -> Vec<u8> {
    from_hex(input["signature"].as_str().unwrap()).unwrap()
}

/// The reference's verdict shape: `{"ok": ..}` or `{"error": words}`.
fn verdict<T: Into<Value>>(result: bsv_rs::Result<T>) -> Value {
    match result {
        Ok(ok) => serde_json::json!({ "ok": ok.into() }),
        Err(Error::CertificateValidationError(words)) => serde_json::json!({ "error": words }),
        Err(other) => panic!("not a certificate refusal: {other:?}"),
    }
}

#[test]
fn the_vector_holds_each_site_s_cases() {
    for (site, count) in SITES {
        assert_eq!(cases(site).len(), count, "{site}");
    }
    assert_eq!(vector().len(), SITES.iter().map(|(_, n)| n).sum::<usize>());
}

#[test]
fn to_binary_bounds_the_frame_and_signature_as_the_reference_does() {
    for case in cases("to_binary") {
        let input = &case["input"];
        let cert = certificate(&lengths(input), Some(signature(input)));
        let include = input["include_signature"].as_bool().unwrap();
        let got = verdict(cert.to_binary(include).map(|b| to_hex(&sha256(&b))));
        assert_eq!(got, case["verdict"], "{}", case["id"]);
    }
}

#[test]
fn from_binary_bounds_the_frame_and_signature_as_the_reference_does() {
    for case in cases("from_binary") {
        let input = &case["input"];
        let mut bytes = certificate(&lengths(input), None).to_binary(false).unwrap();
        bytes.extend_from_slice(&signature(input));
        let got = verdict(Certificate::from_binary(&bytes).map(|c| c.fields.len() as u64));
        assert_eq!(got, case["verdict"], "{}", case["id"]);
    }
}

#[test]
fn a_frame_of_exactly_16_mib_is_written_and_read_back_byte_for_byte() {
    let case = cases("to_binary")[0];
    assert_eq!(case["id"], "frame_of_16777216_bytes");
    let input = &case["input"];
    let cert = certificate(&lengths(input), Some(signature(input)));
    let bytes = cert.to_binary(true).unwrap();
    assert_eq!(bytes.len(), FRAME_BOUND);
    let read = Certificate::from_binary(&bytes).unwrap();
    assert_eq!(read.signature.as_deref(), Some(&signature(input)[..]));
    assert_eq!(read.to_binary(true).unwrap(), bytes);

    // One byte more, the 72-byte signature kept: refused before a byte is read
    let mut over = bytes;
    over.insert(0, 0);
    assert_eq!(
        Certificate::from_binary(&over).unwrap_err(),
        Error::CertificateValidationError(
            "Certificate binary must be a byte array of at most 16777216 bytes".into()
        )
    );
}

#[test]
fn a_signature_of_73_bytes_is_refused_on_write_and_read_and_72_is_not() {
    let sig72 = signature(&cases("to_binary")[0]["input"]);
    assert_eq!(sig72.len(), 72);
    let mut sig73 = sig72.clone();
    sig73.push(0);

    let cert = certificate(&[4], Some(sig72.clone()));
    let bytes = cert.to_binary(true).unwrap();
    assert_eq!(
        Certificate::from_binary(&bytes).unwrap().signature,
        Some(sig72)
    );

    let cert = certificate(&[4], Some(sig73));
    assert_eq!(
        cert.to_binary(true).unwrap_err(),
        Error::CertificateValidationError("Invalid certificate signature encoding".into())
    );
    let mut long = cert.to_binary(false).unwrap();
    long.extend_from_slice(cert.signature.as_ref().unwrap());
    assert_eq!(
        Certificate::from_binary(&long).unwrap_err(),
        Error::CertificateValidationError(
            "Certificate signature exceeds the DER size limit".into()
        )
    );
}

/// The certifier's BRC-52 child signs the over-bound preimage, built by hand:
/// the reference's RFC 6979 signature, so `false` is the bound's.
#[test]
fn verify_answers_false_to_an_unsigned_prefix_over_the_bound_signed_by_the_child() {
    let case = cases("verify")[0];
    let input = &case["input"];
    let lengths = lengths(input);

    let mut preimage = certificate(&[], None).to_binary(false).unwrap();
    preimage.pop(); // the field count
    preimage.push(lengths.len() as u8);
    for (i, &n) in lengths.iter().enumerate() {
        preimage.push(3);
        preimage.extend_from_slice(format!("f{i:02}").as_bytes());
        preimage.push(0xfe);
        preimage.extend_from_slice(&(n as u32).to_le_bytes());
        preimage.extend_from_slice(&a_text().as_bytes()[..n]);
    }
    assert_eq!(preimage.len() as u64, input["preimage_length"]);
    assert_eq!(to_hex(&sha256(&preimage)), input["preimage_sha256"]);

    let cert = certificate(&lengths, None);
    let child = KeyDeriver::new(Some(certifier()))
        .derive_private_key(
            &Protocol::new(SecurityLevel::Counterparty, "certificate signature"),
            &cert.signature_key_id(),
            &Counterparty::Anyone,
        )
        .unwrap();
    let sig = child.sign(&sha256(&preimage)).unwrap().to_der();
    assert_eq!(sig, signature(input));

    let cert = cert.with_signature(Some(sig));
    assert_eq!(verdict(cert.verify()), case["verdict"]);
    assert_eq!(
        cert.signing_hash().unwrap_err(),
        Error::CertificateValidationError(
            "Certificate binary exceeds the maximum of 16777216 bytes".into()
        )
    );
}

#[test]
fn sign_refuses_an_unsigned_prefix_over_the_bound_and_signs_nothing() {
    let case = cases("sign")[0];
    let mut cert = certificate(&lengths(&case["input"]), None);
    let got = verdict(cert.sign(&certifier()).map(|()| "signed"));
    assert_eq!(got, case["verdict"]);
    assert_eq!(cert.signature, None);
    assert_eq!(cert.received_unsigned, None);
}
