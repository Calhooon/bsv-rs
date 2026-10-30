//! #375: the Go certificate adapter rewrites a valid high-S signature.
//! `ts-stack@edf6e03` accepts both S forms (`Certificate.ts:425-439`,
//! `ECDSA.ts:236-239`) and preserves these DER encodings on write/read
//! (`Certificate.ts:309-311,395-397`; `Signature.ts:201-247`). A long-form
//! sequence length is refused (`Signature.ts:45-51`), including by Go's
//! BER parser (`signature.go:199-207`); it is not a preservation witness.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::primitives::{to_base64, PrivateKey, Signature};
use bsv_rs::wallet::types::Outpoint;
use bsv_rs::Error;
use num_bigint::BigUint;
use serde_json::{json, Value};

fn deterministic_test_key(scalar: u8) -> PrivateKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn inputs() -> Value {
    let certifier = deterministic_test_key(42);
    let mut cert = Certificate::new(
        [1; 32],
        [2; 32],
        deterministic_test_key(69).public_key(),
        certifier.public_key(),
    );
    cert.set_revocation_outpoint(Some(Outpoint::new([0; 32], 0)));
    cert.set_field("name", to_base64(b"certificate DER round-trip #375"));
    cert.sign(&certifier).unwrap();
    let canonical = cert.signature.clone().unwrap();
    let parsed = Signature::from_der(&canonical).unwrap();
    assert!(parsed.is_low_s());

    // Change only S to n-S. k256's DER encoder preserves that scalar;
    // this crate's general Signature::to_der deliberately normalizes it.
    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let high_s = (order - BigUint::from_bytes_be(parsed.s())).to_bytes_be();
    let mut scalar = [0; 32];
    scalar[32 - high_s.len()..].copy_from_slice(&high_s);
    let high = k256::ecdsa::Signature::from_scalars(*parsed.r(), scalar)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec();
    assert!(!Signature::from_der(&high).unwrap().is_low_s());

    // The same canonical signature, with its outer length in BER long form.
    // No hand-written certificate or signature fixture: mutate writer output.
    let mut ber = vec![canonical[0], 0x81];
    ber.extend_from_slice(&canonical[1..]);
    let unsigned = cert.to_binary(false).unwrap();
    let cases: Vec<_> = [
        ("canonical_low_s", canonical),
        ("high_s", high),
        ("ber_long_form_length", ber),
    ]
    .into_iter()
    .map(|(name, signature)| {
        cert.set_signature(Some(signature.clone()));
        let mut frame = unsigned.clone();
        frame.extend_from_slice(&signature);
        json!({
            "name": name,
            "certificate": cert,
            "unsignedBinaryHex": hex::encode(&unsigned),
            "binaryHex": hex::encode(frame),
        })
    })
    .collect();
    json!({
        "inputWriter": "bsv-rs Certificate::sign, serde_json and Certificate::to_binary; deterministic test scalars 42 and 69",
        "cases": cases,
    })
}

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "vectors/auth_certificate_der_roundtrip_375.json"
    ))
    .unwrap()
}

#[test]
fn recorded_inputs_are_built_by_this_crates_certificate_writer() {
    let recorded = vector();
    let generated = inputs();
    assert_eq!(recorded["inputWriter"], generated["inputWriter"]);
    assert_eq!(
        recorded["goSdk"],
        "v1.7.2 (2ca481c5931b987a0c8f48bb341c70b7477b6b07)"
    );
    assert_eq!(recorded["goVersion"], "go1.27.0");
    assert_eq!(recorded["reference"], "ts-stack@edf6e03 (Node v22.18.0)");
    assert_eq!(recorded["cases"].as_array().unwrap().len(), 3);
    for (actual, expected) in recorded["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(generated["cases"].as_array().unwrap())
    {
        for field in ["name", "certificate", "unsignedBinaryHex", "binaryHex"] {
            assert_eq!(
                actual[field], expected[field],
                "{}: {field}",
                actual["name"]
            );
        }
        assert_eq!(
            actual["inputSignatureHex"],
            actual["certificate"]["signature"]
        );
    }
}

#[test]
fn certificate_json_preserves_every_input_signature_byte() {
    for case in vector()["cases"].as_array().unwrap() {
        let cert: Certificate = serde_json::from_value(case["certificate"].clone()).unwrap();
        let written = serde_json::to_value(&cert).unwrap();
        assert_eq!(written, case["certificate"], "{}", case["name"]);
        assert_eq!(written["signature"], case["inputSignatureHex"]);
        assert_eq!(written["signature"], case["reference"]["jsonSignatureHex"]);
    }
}

#[test]
fn low_and_high_s_der_survive_wire_roundtrips_and_verify_as_in_the_reference() {
    for case in &vector()["cases"].as_array().unwrap()[..2] {
        let cert: Certificate = serde_json::from_value(case["certificate"].clone()).unwrap();
        let bytes = cert.to_binary(true).unwrap();
        assert_eq!(hex::encode(&bytes), case["binaryHex"]);
        assert_eq!(case["reference"]["outputBinaryHex"], case["binaryHex"]);
        let read = Certificate::from_binary(&bytes).unwrap();
        assert_eq!(read.signature, cert.signature, "{}", case["name"]);
        assert_eq!(read.to_binary(true).unwrap(), bytes);
        assert_eq!(serde_json::to_value(&read).unwrap(), case["certificate"]);
        assert_eq!(
            case["reference"]["outputSignatureHex"],
            case["inputSignatureHex"]
        );
        assert_eq!(case["reference"]["verify"], true);
        assert_eq!(case["reference"]["outputVerify"], true);
        assert_eq!(cert.verify(), Ok(true));
        assert_eq!(read.verify(), Ok(true));
    }
}

#[test]
fn ber_long_form_length_is_refused_where_the_reference_refuses_it() {
    let v = vector();
    let case = &v["cases"][2];
    let cert: Certificate = serde_json::from_value(case["certificate"].clone()).unwrap();
    let error = Error::CertificateValidationError("Invalid DER entity length".into());
    assert_eq!(cert.to_binary(true), Err(error.clone()));
    assert_eq!(
        Certificate::from_binary(&hex::decode(case["binaryHex"].as_str().unwrap()).unwrap()).err(),
        Some(error)
    );
    assert_eq!(case["reference"]["writeError"], "Invalid DER entity length");
    assert_eq!(case["reference"]["readError"], "Invalid DER entity length");
    assert_eq!(case["reference"]["verify"], false);
    assert_eq!(cert.verify(), Ok(false));
}

#[test]
fn go_sdk_adapter_normalizes_high_s_and_drops_the_rejected_ber_signature() {
    let v = vector();
    let cases = v["cases"].as_array().unwrap();
    let canonical = &cases[0]["inputSignatureHex"];
    for case in &cases[..2] {
        assert_eq!(case["go"]["parseAccepted"], true);
        assert_eq!(case["go"]["verify"], true);
        assert_eq!(case["go"]["outputVerify"], true);
        assert_eq!(case["go"]["outputSignatureHex"], *canonical);
        assert_eq!(case["go"]["outputBinaryHex"], cases[0]["binaryHex"]);
    }
    assert_ne!(cases[1]["inputSignatureHex"], *canonical);
    let ber = &cases[2];
    assert_eq!(ber["go"]["parseAccepted"], false);
    assert_eq!(ber["go"]["parseError"], "malformed signature: bad length");
    assert_eq!(ber["go"]["verify"], false);
    assert_eq!(
        ber["go"]["verifyError"],
        "failed to parse signature: malformed signature: bad length"
    );
    assert_eq!(ber["go"]["outputSignatureHex"], "");
    assert_eq!(ber["go"]["outputVerify"], false);
    assert_eq!(ber["go"]["outputVerifyError"], "certificate is not signed");
    assert_eq!(ber["go"]["outputBinaryHex"], ber["unsignedBinaryHex"]);
}

#[test]
#[ignore = "recorder input: run with --ignored --nocapture and capture the marked JSON line"]
fn print_certificate_der_roundtrip_inputs_375() {
    println!("CERTIFICATE_DER_ROUNDTRIP_375_INPUT={}", inputs());
}
