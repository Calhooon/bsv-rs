//! A certificate's field value is its base64 text (#261): held as that
//! string, its UTF-8 bytes written and signed as BRC-52 asks ("Field values in CertificateBinary are
//! the UTF-8 bytes of the Base64 string, not the Base64-decoded ciphertext
//! bytes", `brcs@5119a9b` `peer-to-peer/0052.md:41,97`), as the reference
//! writes them (`ts-stack@edf6e03` `Certificate.ts:294-296`) and stores them
//! (`MasterCertificate.ts:283`), and as Go writes them (`go-sdk@2ca481c`
//! `wallet/serializer/certificate.go:58-60`). The base64 text is decoded at
//! decrypt time and nowhere earlier, under the reference's field encryption:
//! a random symmetric key per field, that key encrypted by the wallet
//! (`MasterCertificate.ts:254-310`, `VerifiableCertificate.ts:152-219`).
//!
//! The witnesses are `tests/vectors/certificate_field_value_261.json`: a
//! certificate the reference issued with encrypted fields, and one issued
//! here, each with the reference's `verify()` verdict and the plaintexts the
//! reference decrypts, recorded by `tests/support/certificate_field_value_261.mjs`
//! under Node v22.18.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{from_base64, from_hex, sha256, to_base64, to_hex, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Vectors {
    reference_issued: ReferenceIssued,
    rust_issued: RustIssued,
}

/// The reference's JSON of a certificate: its `WalletCertificate` shape.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CertificateJson {
    #[serde(rename = "type")]
    cert_type: String,
    serial_number: String,
    subject: String,
    certifier: String,
    revocation_outpoint: String,
    fields: HashMap<String, String>,
    signature: String,
}

#[derive(Deserialize)]
struct ReferenceIssued {
    keys: Keys,
    plaintexts: HashMap<String, String>,
    certificate: CertificateJson,
    master_keyring: HashMap<String, String>,
    verifier_keyring: HashMap<String, String>,
    anyone_keyring: HashMap<String, String>,
    binary_hex: String,
    preimage_sha256: String,
    reference_verify: bool,
    reference_master_plaintexts: HashMap<String, String>,
    reference_verifier_plaintexts: HashMap<String, String>,
    reference_anyone_plaintexts: HashMap<String, String>,
}

#[derive(Deserialize)]
struct RustIssued {
    keys: Keys,
    plaintexts: HashMap<String, String>,
    certificate: CertificateJson,
    binary_hex: String,
    reference_to_binary_hex: String,
    reference_verify: bool,
    reference_master_plaintexts: HashMap<String, String>,
    reference_verifier_plaintexts: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Keys {
    certifier: u8,
    subject: u8,
    verifier: u8,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/certificate_field_value_261.json")).unwrap()
}

fn key(scalar: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn bytes32(b64: &str) -> [u8; 32] {
    from_base64(b64).unwrap().try_into().unwrap()
}

/// The reference's JSON of the certificate, carried verbatim: since #268
/// this crate's serde shape is the reference's (`type`, the signature hex).
fn reference_json(c: &CertificateJson) -> serde_json::Value {
    serde_json::json!({
        "type": c.cert_type,
        "serialNumber": c.serial_number,
        "subject": c.subject,
        "certifier": c.certifier,
        "revocationOutpoint": c.revocation_outpoint,
        "fields": c.fields,
        "signature": c.signature,
    })
}

#[test]
fn a_reference_issued_encrypted_field_certificate_read_from_json_signs_the_reference_preimage() {
    let r = vectors().reference_issued;
    assert!(r.reference_verify);

    let cert: Certificate = serde_json::from_value(reference_json(&r.certificate)).unwrap();
    for (name, text) in &r.certificate.fields {
        assert_eq!(&cert.fields[name], text, "field {name} held as its text");
    }
    assert_eq!(to_hex(&cert.signing_hash().unwrap()), r.preimage_sha256);
    assert_eq!(to_hex(&cert.to_binary(true).unwrap()), r.binary_hex);
    assert!(cert.verify().unwrap());

    let read = Certificate::from_binary(&from_hex(&r.binary_hex).unwrap()).unwrap();
    assert_eq!(read.fields, cert.fields);
    assert!(read.verify().unwrap());
}

#[tokio::test]
async fn a_reference_issued_certificate_decrypts_here_to_the_reference_plaintexts() {
    let r = vectors().reference_issued;
    assert_eq!(r.reference_master_plaintexts, r.plaintexts);
    assert_eq!(r.reference_verifier_plaintexts, r.plaintexts);
    assert_eq!(r.reference_anyone_plaintexts, r.plaintexts);

    let cert = Certificate::from_binary(&from_hex(&r.binary_hex).unwrap()).unwrap();
    let certifier = key(r.keys.certifier).public_key();

    let master = MasterCertificate::new(cert.clone(), r.master_keyring.clone());
    let subject_wallet = ProtoWallet::new(Some(key(r.keys.subject)));
    let decrypted = master
        .decrypt_fields(&subject_wallet, &certifier, None, None, "test")
        .await
        .unwrap();
    assert_eq!(decrypted, r.plaintexts);

    let mut verifiable = VerifiableCertificate::new(cert.clone(), r.verifier_keyring.clone());
    let verifier_wallet = ProtoWallet::new(Some(key(r.keys.verifier)));
    let decrypted = verifiable
        .decrypt_fields(&verifier_wallet, None, None, "test")
        .await
        .unwrap();
    assert_eq!(decrypted, r.plaintexts);

    let mut public = VerifiableCertificate::new(cert, r.anyone_keyring.clone());
    let decrypted = public
        .decrypt_fields(&ProtoWallet::anyone(), None, None, "test")
        .await
        .unwrap();
    assert_eq!(decrypted, r.plaintexts);
}

#[cfg(feature = "http")]
#[tokio::test]
async fn a_reference_issued_certificate_from_a_wallet_json_result_verifies_and_decrypts() {
    use bsv_rs::auth::types::RequestedCertificateSet;
    use bsv_rs::auth::utils::get_verifiable_certificates;
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let r = vectors().reference_issued;
    let c = &r.certificate;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/listCertificates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "totalCertificates": 1,
            "certificates": [{
                "type": c.cert_type,
                "serialNumber": c.serial_number,
                "subject": c.subject,
                "certifier": c.certifier,
                "revocationOutpoint": c.revocation_outpoint,
                "signature": c.signature,
                "fields": c.fields,
            }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proveCertificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "keyringForVerifier": r.verifier_keyring })),
        )
        .mount(&server)
        .await;

    let wallet = HttpWalletJson::new(Some("test".into()), Some(server.uri()));
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier(c.certifier.clone());
    requested.add_type(c.cert_type.clone(), r.plaintexts.keys().cloned().collect());
    let verifier = key(r.keys.verifier);

    let mut certs =
        get_verifiable_certificates(&wallet, &requested, &verifier.public_key(), "test")
            .await
            .unwrap();
    assert_eq!(certs.len(), 1);
    let cert = &mut certs[0];
    assert_eq!(to_hex(&cert.signing_hash().unwrap()), r.preimage_sha256);
    assert!(cert.verify().unwrap());

    let decrypted = cert
        .decrypt_fields(&ProtoWallet::new(Some(verifier)), None, None, "test")
        .await
        .unwrap();
    assert_eq!(decrypted, r.plaintexts);
}

#[tokio::test]
async fn a_certificate_issued_here_holds_base64_text_and_the_reference_verifies_and_decrypts_it() {
    let w = vectors().rust_issued;
    assert!(w.reference_verify);
    assert_eq!(w.reference_master_plaintexts, w.plaintexts);
    assert_eq!(w.reference_verifier_plaintexts, w.plaintexts);

    // The recorded certificate: its bytes are the reference's for its JSON.
    let cert: Certificate = serde_json::from_value(reference_json(&w.certificate)).unwrap();
    assert_eq!(to_hex(&cert.to_binary(true).unwrap()), w.binary_hex);
    assert_eq!(w.binary_hex, w.reference_to_binary_hex);
    assert!(cert.verify().unwrap());

    // A fresh issuance holds the ciphertext's base64 text, signs it, and
    // decrypts back to the plaintexts.
    let certifier = key(w.keys.certifier);
    let subject = key(w.keys.subject);
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier,
        subject.public_key(),
        w.plaintexts.clone(),
        bytes32(&w.certificate.cert_type),
        Some(bytes32(&w.certificate.serial_number)),
        "test",
    )
    .await
    .unwrap();
    assert_eq!(master.fields.len(), w.plaintexts.len());
    for (name, text) in &master.fields {
        let ciphertext = from_base64(text).unwrap();
        assert_eq!(
            &to_base64(&ciphertext),
            text,
            "field {name} is canonical base64 text"
        );
        // 32-byte IV, the plaintext, a 16-byte tag
        assert_eq!(ciphertext.len(), 32 + w.plaintexts[name].len() + 16);
    }
    let preimage = master.to_binary(false).unwrap();
    for value in master.fields.values() {
        let value = value.as_bytes();
        assert!(preimage.windows(value.len()).any(|win| win == value));
    }
    assert_eq!(sha256(&preimage), master.signing_hash().unwrap());
    assert!(master.verify().unwrap());
    let decrypted = master
        .decrypt_fields(
            &ProtoWallet::new(Some(subject)),
            &certifier.public_key(),
            None,
            None,
            "test",
        )
        .await
        .unwrap();
    assert_eq!(decrypted, w.plaintexts);
}

#[test]
fn from_binary_refuses_a_field_value_that_is_not_utf8_the_field_named() {
    // The reference's fromBinary reads each value with toUTF8Strict
    // (`Certificate.ts:384`); BRC-52: malformed UTF-8 MUST NOT be made
    // acceptable by retaining bytes (`0052.md:103`).
    let r = vectors().reference_issued;
    let mut cert = Certificate::from_binary(&from_hex(&r.binary_hex).unwrap()).unwrap();
    cert.set_field("email", "AAAA");
    let mut bytes = cert.to_binary(true).unwrap();
    let at = bytes
        .windows(11)
        .position(|w| w == b"\x05email\x04AAAA")
        .unwrap();
    bytes[at + 7..at + 10].copy_from_slice(&[0xff, 0xfe, 0x41]);
    match Certificate::from_binary(&bytes) {
        Err(Error::InvalidUtf8(m)) => assert!(
            m.contains("certificate field email is not UTF-8 base64 text"),
            "{m}"
        ),
        other => panic!("expected InvalidUtf8, got {other:?}"),
    }
}

#[test]
fn set_field_holds_any_string_and_writes_its_bytes_as_the_reference_does() {
    // The reference's `fields` record takes any string and writes its UTF-8
    // (`Certificate.ts:294-296`): no base64 check at the setter.
    let r = vectors().reference_issued;
    let mut cert = Certificate::from_binary(&from_hex(&r.binary_hex).unwrap()).unwrap();
    cert.set_field("email", "not base64 ✓");
    assert_eq!(cert.fields["email"], "not base64 ✓");
    let bytes = cert.to_binary(false).unwrap();
    let text = "not base64 ✓".as_bytes();
    assert!(bytes.windows(text.len()).any(|w| w == text));
    let read = Certificate::from_binary(&bytes).unwrap();
    assert_eq!(read.fields, cert.fields);
}

#[test]
fn the_json_reader_refuses_a_field_value_that_is_not_utf8() {
    let r = vectors().reference_issued;
    let json = serde_json::to_string(&reference_json(&r.certificate)).unwrap();
    let text = r.certificate.fields.values().next().unwrap();

    // Raw bytes that are not UTF-8 where a value's text stands.
    let mut raw = json.clone().into_bytes();
    let at = json.find(text.as_str()).unwrap();
    raw[at] = 0xff;
    assert!(serde_json::from_slice::<Certificate>(&raw).is_err());

    // A lone surrogate escape, which no UTF-8 string carries.
    let surrogate = json.replacen(text.as_str(), "\\ud800", 1);
    assert!(serde_json::from_str::<Certificate>(&surrogate).is_err());
}

#[test]
fn certificate_fields_serialize_as_the_base64_strings_they_hold() {
    let r = vectors().reference_issued;
    let cert = Certificate::from_binary(&from_hex(&r.binary_hex).unwrap()).unwrap();
    let json = serde_json::to_value(&cert).unwrap();
    for (name, text) in &r.certificate.fields {
        assert_eq!(
            json["fields"][name],
            serde_json::Value::String(text.clone())
        );
    }
    let back: Certificate = serde_json::from_value(json).unwrap();
    assert_eq!(back.fields, cert.fields);
    assert!(back.verify().unwrap());
    let wallet = cert.to_wallet_certificate();
    assert_eq!(wallet.fields, r.certificate.fields);
}

/// Prints a certificate issued here, as the JSON the reference script reads
/// (`tests/support/certificate_field_value_261.mjs`). Run by hand:
/// `cargo test --features auth --test auth_certificate_field_value_261 -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn print_a_certificate_issued_here_for_the_reference() {
    let (certifier, subject, verifier) = (key(43), key(47), key(41));
    let plaintexts: HashMap<String, String> = [
        ("name", "Bob Example"),
        ("email", "bob@example.com"),
        ("city", "Zoë's Café"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier,
        subject.public_key(),
        plaintexts.clone(),
        [8u8; 32],
        Some([9u8; 32]),
        "test",
    )
    .await
    .unwrap();
    let mut names: Vec<String> = plaintexts.keys().cloned().collect();
    names.sort();
    let verifier_keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(subject.clone())),
        &certifier.public_key(),
        &verifier.public_key(),
        &master.fields,
        &names,
        &master.master_keyring,
        &master.serial_number,
        None,
        None,
        "test",
    )
    .await
    .unwrap();
    let out = serde_json::json!({
        "origin": "issued by this crate's MasterCertificate::issue_for_subject (certifier key 43, subject key 47, type 32 x 0x08, serial 32 x 0x09, no revocation outpoint) with a keyring for verifier key 41 by create_keyring_for_verifier",
        "keys": { "certifier": 43, "subject": 47, "verifier": 41 },
        "plaintexts": plaintexts,
        "certificate": {
            "type": master.type_base64(),
            "serialNumber": master.serial_number_base64(),
            "subject": master.subject.to_hex(),
            "certifier": master.certifier.to_hex(),
            "revocationOutpoint": format!("{}.0", "00".repeat(32)),
            "fields": master.to_wallet_certificate().fields,
            "signature": to_hex(master.signature.as_ref().unwrap()),
        },
        "master_keyring": master.master_keyring,
        "verifier_keyring": verifier_keyring,
        "binary_hex": to_hex(&master.to_binary(true).unwrap()),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
