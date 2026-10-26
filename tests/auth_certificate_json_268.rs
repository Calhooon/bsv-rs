//! The three certificate types' JSON is the reference's (#268): `type` and
//! `serialNumber` base64, `subject` and `certifier` hex, `revocationOutpoint`
//! `<txid>.<index>`, `fields` the base64 strings, `signature` hex, and the
//! `masterKeyring` and `keyring` records of base64 strings (`ts-stack@edf6e03`
//! `Certificate.ts:150-212`, `MasterCertificate.ts:164-237`,
//! `VerifiableCertificate.ts:80-118`; go-sdk@2ca481c
//! `auth/certificates/certificate.go:32-52`, `master.go:28-35`,
//! `verifiable.go:16-29`).
//!
//! The witnesses are `tests/vectors/certificate_json_268.json`, recorded by
//! `tests/support/certificate_json_268.mjs` under Node v22.18.0: the
//! reference's `JSON.stringify` of a `Certificate`, a `MasterCertificate` and
//! a `VerifiableCertificate` it issued (three fields and one field), each
//! read here and written back, by value and, where every map has one key,
//! byte for byte; and this crate's JSON of the three types, read by the
//! reference, with the reference's `verify()` verdict, its `toBinary(true)`,
//! the plaintexts it decrypts and its own `JSON.stringify` of what it read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Vectors {
    reference_issued: Vec<ReferenceIssued>,
    rust_issued: Vec<RustIssued>,
}

/// The three types' JSON texts of one certificate.
#[derive(Deserialize, Serialize)]
struct Texts {
    certificate: String,
    master: String,
    verifiable: String,
}

#[derive(Deserialize)]
struct ReferenceIssued {
    keys: Keys,
    plaintexts: HashMap<String, String>,
    json: Texts,
    binary_hex: String,
    reference_verify: bool,
    reference_master_plaintexts: HashMap<String, String>,
    reference_verifier_plaintexts: HashMap<String, String>,
}

#[derive(Deserialize)]
struct RustIssued {
    keys: Keys,
    plaintexts: HashMap<String, String>,
    json: Texts,
    binary_hex: String,
    reference_json: Texts,
    reference_to_binary_hex: String,
    reference_verify: bool,
    reference_master_plaintexts: HashMap<String, String>,
    reference_verifier_plaintexts: HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone, Copy)]
struct Keys {
    certifier: u8,
    subject: u8,
    verifier: u8,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/certificate_json_268.json")).unwrap()
}

fn key(scalar: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

/// Reads `text` as `T` and writes it back: equal to the text by value, and
/// byte for byte when `exact` (every map of the certificate has one key, so
/// no map order can differ).
fn read_and_write_back<T: DeserializeOwned + Serialize>(text: &str, exact: bool, what: &str) -> T {
    let read: T = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("{what}: the reference's JSON is not read here: {e}"));
    let written = serde_json::to_string(&read).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&written).unwrap(),
        serde_json::from_str::<serde_json::Value>(text).unwrap(),
        "{what}: written back by value"
    );
    if exact {
        assert_eq!(written, text, "{what}: written back byte for byte");
    }
    read
}

/// Reads the three texts as this crate's types, checks each is written
/// back, then that the certificate verifies, writes `binary_hex` and
/// decrypts to `plaintexts` under both keyrings.
async fn read_the_three(
    json: &Texts,
    keys: Keys,
    plaintexts: &HashMap<String, String>,
    binary_hex: &str,
) {
    let exact = plaintexts.len() == 1;
    let cert: Certificate = read_and_write_back(&json.certificate, exact, "Certificate");
    let master: MasterCertificate = read_and_write_back(&json.master, exact, "MasterCertificate");
    let mut verifiable: VerifiableCertificate =
        read_and_write_back(&json.verifiable, exact, "VerifiableCertificate");

    assert!(cert.verify().unwrap());
    assert_eq!(to_hex(&cert.to_binary(true)), binary_hex);
    assert_eq!(to_hex(&master.to_binary(true)), binary_hex);
    assert_eq!(to_hex(&verifiable.to_binary(true)), binary_hex);
    assert_eq!(
        verifiable.to_json_value(),
        serde_json::from_str::<serde_json::Value>(&json.verifiable).unwrap()
    );

    let decrypted = master
        .decrypt_fields(
            &ProtoWallet::new(Some(key(keys.subject))),
            &key(keys.certifier).public_key(),
            None,
            None,
            "test",
        )
        .await
        .unwrap();
    assert_eq!(&decrypted, plaintexts);
    let decrypted = verifiable
        .decrypt_fields(
            &ProtoWallet::new(Some(key(keys.verifier))),
            None,
            None,
            "test",
        )
        .await
        .unwrap();
    assert_eq!(&decrypted, plaintexts);
}

#[tokio::test]
async fn the_reference_json_of_the_three_certificate_types_is_read_here_and_written_back() {
    let v = vectors();
    assert_eq!(v.reference_issued.len(), 2);
    for r in &v.reference_issued {
        assert!(r.reference_verify);
        assert_eq!(&r.reference_master_plaintexts, &r.plaintexts);
        assert_eq!(&r.reference_verifier_plaintexts, &r.plaintexts);
        read_the_three(&r.json, r.keys, &r.plaintexts, &r.binary_hex).await;
    }
}

#[tokio::test]
async fn the_json_this_crate_writes_for_the_three_types_is_read_by_the_reference() {
    let v = vectors();
    assert_eq!(v.rust_issued.len(), 2);
    for w in &v.rust_issued {
        // The reference read the recorded JSON: it verified, wrote the same
        // bytes and decrypted the plaintexts under both keyrings.
        assert!(w.reference_verify);
        assert_eq!(w.reference_to_binary_hex, w.binary_hex);
        assert_eq!(&w.reference_master_plaintexts, &w.plaintexts);
        assert_eq!(&w.reference_verifier_plaintexts, &w.plaintexts);
        // The reference's JSON.stringify of what it read is the JSON written here.
        for (here, there) in [
            (&w.json.certificate, &w.reference_json.certificate),
            (&w.json.master, &w.reference_json.master),
            (&w.json.verifiable, &w.reference_json.verifiable),
        ] {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(here).unwrap(),
                serde_json::from_str::<serde_json::Value>(there).unwrap()
            );
            if w.plaintexts.len() == 1 {
                assert_eq!(here, there);
            }
        }
        read_the_three(&w.json, w.keys, &w.plaintexts, &w.binary_hex).await;
    }
}

#[tokio::test]
async fn a_fresh_issuance_writes_the_reference_names_and_encodings() {
    let (certifier, subject, verifier) = (key(43), key(47), key(41));
    let (master, verifiable) =
        issue_here(&certifier, &subject, &verifier, &[("name", "Bob")]).await;

    let json = serde_json::to_value(&verifiable).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut want = vec![
        "type",
        "serialNumber",
        "subject",
        "certifier",
        "revocationOutpoint",
        "fields",
        "signature",
        "keyring",
    ];
    want.sort();
    assert_eq!(keys, want);
    assert_eq!(
        json["signature"],
        to_hex(master.signature.as_ref().unwrap())
    );
    assert_eq!(json["revocationOutpoint"], format!("{}.0", "00".repeat(32)));
    assert!(json["keyring"]["name"].is_string());
    let master_json = serde_json::to_value(&master).unwrap();
    assert!(master_json.get("certType").is_none());
    assert!(master_json["masterKeyring"]["name"].is_string());
}

#[test]
fn an_absent_revocation_outpoint_reads_from_null_from_no_key_and_from_the_sentinel() {
    let key = key(5).public_key();
    let cert = Certificate::new([1; 32], [2; 32], key.clone(), key);
    let json = serde_json::to_value(&cert).unwrap();
    assert_eq!(json["revocationOutpoint"], format!("{}.0", "00".repeat(32)));
    for outpoint in [serde_json::Value::Null, json["revocationOutpoint"].clone()] {
        let mut j = json.clone();
        j["revocationOutpoint"] = outpoint;
        let read: Certificate = serde_json::from_value(j).unwrap();
        assert_eq!(read.revocation_outpoint, None);
    }
    let mut j = json.clone();
    j.as_object_mut().unwrap().remove("revocationOutpoint");
    let read: Certificate = serde_json::from_value(j).unwrap();
    assert_eq!(read.revocation_outpoint, None);
    assert_eq!(read.to_binary(true), cert.to_binary(true));
}

/// Issues a certificate here with `fields`, and a keyring for `verifier`.
async fn issue_here(
    certifier: &PrivateKey,
    subject: &PrivateKey,
    verifier: &PrivateKey,
    fields: &[(&str, &str)],
) -> (MasterCertificate, VerifiableCertificate) {
    let plaintexts: HashMap<String, String> = fields
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        certifier,
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
    let keyring = MasterCertificate::create_keyring_for_verifier(
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
    let verifiable = VerifiableCertificate::new(master.certificate.clone(), keyring);
    (master, verifiable)
}

/// Prints the certificates issued here, as the JSON the reference script
/// reads (`tests/support/certificate_json_268.mjs`). Run by hand:
/// `cargo test --features auth --test auth_certificate_json_268 -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn print_the_certificates_issued_here_for_the_reference() {
    let keys = Keys {
        certifier: 43,
        subject: 47,
        verifier: 41,
    };
    let (certifier, subject, verifier) =
        (key(keys.certifier), key(keys.subject), key(keys.verifier));
    let mut out = Vec::new();
    for fields in [
        &[
            ("name", "Bob Example"),
            ("email", "bob@example.com"),
            ("city", "Zoë's Café"),
        ][..],
        &[("name", "Bob Example")][..],
    ] {
        let (master, verifiable) = issue_here(&certifier, &subject, &verifier, fields).await;
        let plaintexts: HashMap<&str, &str> = fields.iter().copied().collect();
        out.push(serde_json::json!({
            "origin": "issued by this crate's MasterCertificate::issue_for_subject (certifier key 43, subject key 47, type 32 x 0x08, serial 32 x 0x09, no revocation outpoint) with a keyring for verifier key 41 by create_keyring_for_verifier; each JSON text this crate's serde_json::to_string",
            "keys": keys,
            "plaintexts": plaintexts,
            "json": Texts {
                certificate: serde_json::to_string(&master.certificate).unwrap(),
                master: serde_json::to_string(&master).unwrap(),
                verifiable: serde_json::to_string(&verifiable).unwrap(),
            },
            "binary_hex": to_hex(&master.to_binary(true)),
        }));
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
