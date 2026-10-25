//! `WireWriter::write_identity_certificate` writes one discovery entry as the
//! reference writes it (bsv-rs#182).
//!
//! The reference's `#serializeDiscoveryResult` (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:2478-2520`, the
//! maps to `:2558`) and Go's `SerializeIdentityCertificate` (`go-sdk@2ca481c`
//! `wallet/serializer/identity_certificate.go:12-49`): the certificate's binary
//! behind a varint length (`:2500-2505`; Go `:16-20`), certifierInfo's name,
//! iconUrl and description as plain varint-length UTF-8 strings (`:2507-2518`;
//! Go `:23-25`), trust a byte (`:2520`; Go `:26`), the public keyring as a count
//! and varint-length key with varint-length raw-byte value pairs (`:2522-2539`;
//! Go `:29-43`), the decrypted fields the same with UTF-8 values (`:2541-2557`;
//! Go `:46`). No present-flag byte, no NIL sentinel. The writer's bytes are fed
//! to the transceiver's discovery reader and compared with the reference's
//! bytes, hand-assembled, and with the shared vector's.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::to_base64;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::collections::HashMap;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

/// Answers every call with the success byte and `body`.
struct CannedWire {
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl WalletWire for CannedWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        let mut answer = vec![0u8];
        answer.extend_from_slice(&self.body);
        Ok(answer)
    }
}

fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn certificate() -> WalletCertificate {
    WalletCertificate {
        certificate_type: to_base64(&[0x11; 32]),
        subject: G.to_string(),
        serial_number: to_base64(&[0x22; 32]),
        certifier: TWO_G.to_string(),
        revocation_outpoint: format!("{}.1", "33".repeat(32)),
        signature: "3006020101020101".to_string(),
        fields: map(&[("role", "reader"), ("name", "Fixture")]),
    }
}

fn identity_certificate() -> IdentityCertificate {
    IdentityCertificate {
        certificate: certificate(),
        certifier_info: Some(IdentityCertifier {
            name: "Fixture Certifier".into(),
            icon_url: Some("https://certifier.invalid/icon".into()),
            description: Some("fixture only".into()),
            trust: 5,
        }),
        publicly_revealed_keyring: Some(map(&[
            ("role", &to_base64(b"key-2")),
            ("name", &to_base64(b"key-1")),
        ])),
        decrypted_fields: Some(map(&[("role", "reader"), ("name", "Fixture")])),
    }
}

fn written(cert: &IdentityCertificate) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_identity_certificate(cert).unwrap();
    w.into_bytes()
}

/// A discovery result of one entry, the writer's.
fn discovery_frame(cert: &IdentityCertificate) -> Vec<u8> {
    let mut frame = vec![1];
    frame.extend_from_slice(&written(cert));
    frame
}

async fn discovered(frame: Vec<u8>) -> DiscoverCertificatesResult {
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    WalletWireTransceiver::new(CannedWire { body: frame })
        .discover_by_identity_key(args, "fixtures.invalid")
        .await
        .unwrap()
}

fn var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() < 0xfd, "one-byte varints only");
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

#[tokio::test]
async fn an_identity_certificate_the_writer_writes_reads_through_the_transceiver() {
    let cert = identity_certificate();
    let read = discovered(discovery_frame(&cert)).await;
    assert_eq!(read.total_certificates, 1);
    assert_eq!(json(&read.certificates[0]), json(&cert));
}

/// The entry as `#serializeDiscoveryResult` writes it (the lines in the file's
/// header), assembled byte by byte; the maps in Go's sorted order.
#[test]
fn an_identity_certificate_is_written_as_the_reference_writes_it() {
    let mut certificate_bytes = WireWriter::new();
    certificate_bytes
        .write_wallet_certificate(&certificate())
        .unwrap();
    let mut reference = Vec::new();
    var_bytes(&mut reference, certificate_bytes.as_bytes());
    var_bytes(&mut reference, b"Fixture Certifier");
    var_bytes(&mut reference, b"https://certifier.invalid/icon");
    var_bytes(&mut reference, b"fixture only");
    reference.push(5);
    reference.push(2);
    var_bytes(&mut reference, b"name");
    var_bytes(&mut reference, b"key-1");
    var_bytes(&mut reference, b"role");
    var_bytes(&mut reference, b"key-2");
    reference.push(2);
    var_bytes(&mut reference, b"name");
    var_bytes(&mut reference, b"Fixture");
    var_bytes(&mut reference, b"role");
    var_bytes(&mut reference, b"reader");
    assert_eq!(written(&identity_certificate()), reference);
}

/// The shared vector's entry (the bytes TS and Go exchange) is the writer's
/// for the vector's value.
#[test]
fn the_shared_discovery_vector_entry_is_the_writers_bytes() {
    let path = format!(
        "{}/tests/vectors/wallet_wire/discoverByIdentityKey-simple-result.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wire = hex::decode(v["wire"].as_str().unwrap()).unwrap();
    assert_eq!(&wire[..2], &[0, 1], "a success frame of one entry");
    let e = &v["json"]["certificates"][0];
    let s = |key: &str| e[key].as_str().unwrap().to_string();
    let strings = |value: &serde_json::Value| -> HashMap<String, String> {
        serde_json::from_value(value.clone()).unwrap()
    };
    let cert = IdentityCertificate {
        certificate: WalletCertificate {
            certificate_type: s("type"),
            subject: s("subject"),
            serial_number: s("serialNumber"),
            certifier: s("certifier"),
            revocation_outpoint: s("revocationOutpoint"),
            signature: s("signature"),
            fields: strings(&e["fields"]),
        },
        certifier_info: Some(serde_json::from_value(e["certifierInfo"].clone()).unwrap()),
        publicly_revealed_keyring: Some(strings(&e["publiclyRevealedKeyring"])),
        decrypted_fields: Some(strings(&e["decryptedFields"])),
    };
    assert_eq!(written(&cert), &wire[2..]);
}

/// An absent iconUrl or description is the empty string, an absent
/// certifierInfo or map Go's zero value (`identity_certificate.go:23-46` reads
/// the struct's fields; TS has no absent case): three empty strings, trust 0,
/// a count of 0. The transceiver reads them back as it reads the reference's.
#[tokio::test]
async fn an_identity_certificate_with_nothing_optional_writes_empty_strings_and_counts() {
    let cert = IdentityCertificate {
        certificate: certificate(),
        certifier_info: None,
        publicly_revealed_keyring: None,
        decrypted_fields: None,
    };
    let bytes = written(&cert);
    let mut certificate_bytes = WireWriter::new();
    certificate_bytes
        .write_wallet_certificate(&certificate())
        .unwrap();
    let mut reference = Vec::new();
    var_bytes(&mut reference, certificate_bytes.as_bytes());
    reference.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    assert_eq!(bytes, reference);

    let read = discovered(discovery_frame(&cert)).await;
    let entry = &read.certificates[0];
    let certifier = IdentityCertifier {
        name: String::new(),
        icon_url: Some(String::new()),
        description: Some(String::new()),
        trust: 0,
    };
    assert_eq!(json(&entry.certifier_info), json(&Some(certifier)));
    assert_eq!(entry.publicly_revealed_keyring, None);
    assert_eq!(entry.decrypted_fields, None);
}

/// A keyring value crosses as its raw bytes, so one that is not base64 is
/// refused (TS's `toArray(value, 'base64')`, Go's `:38-41`).
#[test]
fn a_keyring_value_that_is_not_base64_is_refused() {
    let mut cert = identity_certificate();
    cert.publicly_revealed_keyring = Some(map(&[("name", "not base64!")]));
    let mut w = WireWriter::new();
    assert!(matches!(
        w.write_identity_certificate(&cert),
        Err(Error::WalletError(_))
    ));
}
