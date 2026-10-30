//! The transceiver reads the certificate result frames as the reference writes
//! them (bsv-rs#177).
//!
//! Each call is fed two frames: the one this crate's writer emits
//! (`WireWriter::write_wallet_certificate`) and the reference's bytes,
//! hand-assembled to `ts-stack@edf6e03`
//! (`packages/sdk/src/auth/certificates/Certificate.ts`,
//! `packages/sdk/src/wallet/substrates/WalletWire{Processor,Transceiver}.ts`)
//! or taken from the shared vectors. The transceiver reads both to the same
//! value, and `Certificate::from_binary` reads the certificate bytes the same.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::Certificate;
use bsv_rs::primitives::{to_base64, to_hex};
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use indexmap::IndexMap;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SIGNATURE: &str = "3006020101020101";

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

fn client(body: Vec<u8>) -> WalletWireTransceiver<CannedWire> {
    WalletWireTransceiver::new(CannedWire { body })
}

fn map(entries: &[(&str, &str)]) -> IndexMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The public result types carry no `PartialEq`; their JSON is compared.
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
        signature: SIGNATURE.to_string(),
        fields: map(&[("role", "reader"), ("name", "Fixture")]),
    }
}

/// The writer's certificate bytes.
fn writer_certificate() -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_wallet_certificate(&certificate()).unwrap();
    w.into_bytes()
}

fn var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() < 0xfd, "one-byte varints only");
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

/// The reference's `Certificate.toBinary` (`Certificate.ts:229-321`): type 32
/// (`:233-234`), serialNumber 32 (`:236-238`), subject 33 (`:240-246`),
/// certifier 33 (`:248-254`), the revocation txid 32 and a varint index
/// (`:256-277`), the fields sorted by name with a varint count, each a
/// varint-length name and a varint-length value (`:279-296`), then the
/// signature with no length prefix (`:299-311`).
fn reference_certificate() -> Vec<u8> {
    let mut out = vec![0x11; 32];
    out.extend_from_slice(&[0x22; 32]);
    out.extend_from_slice(&hex::decode(G).unwrap());
    out.extend_from_slice(&hex::decode(TWO_G).unwrap());
    out.extend_from_slice(&[0x33; 32]);
    out.push(1);
    out.push(2);
    for (name, value) in [("name", "Fixture"), ("role", "reader")] {
        var_bytes(&mut out, name.as_bytes());
        var_bytes(&mut out, value.as_bytes());
    }
    out.extend_from_slice(&hex::decode(SIGNATURE).unwrap());
    out
}

/// `Certificate::from_binary`, this crate's own codec, reads `bytes` as the
/// certificate the transceiver gave.
fn assert_codec_reads(bytes: &[u8], cert: &WalletCertificate) {
    let parsed = Certificate::from_binary(bytes).unwrap();
    assert_eq!(parsed.type_base64(), cert.certificate_type);
    assert_eq!(parsed.serial_number_base64(), cert.serial_number);
    assert_eq!(parsed.subject.to_hex(), cert.subject);
    assert_eq!(parsed.certifier.to_hex(), cert.certifier);
    let outpoint = parsed.revocation_outpoint.unwrap();
    assert_eq!(
        format!("{}.{}", to_hex(&outpoint.txid), outpoint.vout),
        cert.revocation_outpoint
    );
    assert_eq!(parsed.fields, cert.fields);
    assert_eq!(to_hex(&parsed.signature.unwrap()), cert.signature);
}

fn acquire_args() -> AcquireCertificateArgs {
    AcquireCertificateArgs {
        certificate_type: to_base64(&[0x11; 32]),
        certifier: TWO_G.to_string(),
        acquisition_protocol: AcquisitionProtocol::Issuance,
        // #487 binds an issuance result to the requested field names.
        fields: certificate().fields,
        serial_number: None,
        revocation_outpoint: None,
        signature: None,
        certifier_url: Some("https://certifier.invalid".to_string()),
        keyring_revealer: None,
        keyring_for_subject: None,
        privileged: None,
        privileged_reason: None,
    }
}

/// acquireCertificate's result is the certificate's bytes
/// (`WalletWireTransceiver.ts:1437`, `Certificate.fromBinary(result)`).
#[tokio::test]
async fn an_acquired_certificate_reads_as_the_reference_and_the_writer_write_it() {
    assert_eq!(writer_certificate(), reference_certificate());
    for frame in [writer_certificate(), reference_certificate()] {
        let read = client(frame.clone())
            .acquire_certificate(acquire_args(), Some("fixtures.invalid"))
            .await
            .unwrap();
        assert_eq!(json(&read), json(&certificate()));
        assert_codec_reads(&frame, &read);
    }
}

/// listCertificates' entry (`WalletWireTransceiver.ts:1508-1548`): the
/// certificate behind a varint length, the keyring flag and entries (values
/// as raw bytes), then the verifier as a varint length, 0 or 33, and 33 raw
/// bytes (`:1533-1542`).
fn list_frame(certificate: &[u8], verifier: Option<&str>) -> Vec<u8> {
    let mut out = vec![1];
    var_bytes(&mut out, certificate);
    out.push(1);
    out.push(1);
    var_bytes(&mut out, b"name");
    var_bytes(&mut out, b"Fixture");
    match verifier {
        Some(v) => var_bytes(&mut out, &hex::decode(v).unwrap()),
        None => out.push(0),
    }
    out
}

fn list_args() -> ListCertificatesArgs {
    ListCertificatesArgs {
        certifiers: vec![],
        types: vec![],
        limit: None,
        offset: None,
        privileged: None,
        privileged_reason: None,
    }
}

#[tokio::test]
async fn a_listed_certificate_and_its_verifier_read_as_the_reference_writes_them() {
    for (cert, verifier) in [
        (writer_certificate(), Some(G)),
        (reference_certificate(), Some(G)),
        (reference_certificate(), None),
    ] {
        let read = client(list_frame(&cert, verifier))
            .list_certificates(list_args(), Some("fixtures.invalid"))
            .await
            .unwrap();
        assert_eq!(read.total_certificates, 1);
        let entry = &read.certificates[0];
        assert_eq!(json(&entry.certificate), json(&certificate()));
        assert_eq!(
            entry.keyring,
            Some(map(&[("name", &to_base64(b"Fixture"))]))
        );
        assert_eq!(entry.verifier.as_deref(), verifier);
        assert_codec_reads(&cert, &entry.certificate);
    }
}

/// The reference refuses a verifier of any length but 0 or 33
/// (`WalletWireTransceiver.ts:1536-1540`); the string the reader once took is
/// one of them.
#[tokio::test]
async fn a_listed_verifier_of_another_length_is_refused() {
    let mut frame = list_frame(&reference_certificate(), None);
    frame.pop();
    var_bytes(&mut frame, G.as_bytes());
    let err = client(frame)
        .list_certificates(list_args(), Some("fixtures.invalid"))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::WalletError(
            "invalid listCertificates verifier length: expected 33 bytes, received 66".into()
        )
    );
}

/// The shared vector's entry, the reference's bytes (`WalletWireProcessor.ts`
/// and Go's `list_certificates.go:121`, `WriteIntBytes(cert.Verifier)`).
#[tokio::test]
async fn the_shared_list_certificates_vector_reads_through_the_transceiver() {
    let (json, wire) = vector("listCertificates-full-result.json");
    let read = client(wire[1..].to_vec())
        .list_certificates(list_args(), Some("fixtures.invalid"))
        .await
        .unwrap();
    let expected = &json["certificates"][0];
    let entry = &read.certificates[0];
    assert_vector_certificate(&entry.certificate, expected);
    assert_eq!(entry.verifier.as_deref(), expected["verifier"].as_str());
    assert_eq!(
        serde_json::to_value(&entry.keyring).unwrap(),
        expected["keyring"]
    );
}

/// The discovery entry as `#serializeDiscoveryResult` writes it
/// (`WalletWireProcessor.ts:2478-2560`): the certificate behind a varint
/// length (`:2503-2505`), certifierInfo's name, iconUrl and description as
/// plain varint-length UTF-8 strings (`:2507-2518`), trust a byte (`:2520`),
/// the public keyring with raw-byte values (`:2522-2539`), the decrypted
/// fields as strings (`:2541-2557`).
fn discovery_frame(certificate: &[u8], icon_url: &str) -> Vec<u8> {
    let mut out = vec![1];
    var_bytes(&mut out, certificate);
    var_bytes(&mut out, b"Fixture Certifier");
    var_bytes(&mut out, icon_url.as_bytes());
    var_bytes(&mut out, b"fixture only");
    out.push(5);
    out.push(1);
    var_bytes(&mut out, b"name");
    var_bytes(&mut out, b"Fixture");
    out.push(1);
    var_bytes(&mut out, b"role");
    var_bytes(&mut out, b"reader");
    out
}

fn assert_discovered(read: &DiscoverCertificatesResult, icon_url: &str) {
    assert_eq!(read.total_certificates, 1);
    let entry = &read.certificates[0];
    assert_eq!(json(&entry.certificate), json(&certificate()));
    let certifier = IdentityCertifier {
        name: "Fixture Certifier".into(),
        icon_url: icon_url.into(),
        description: "fixture only".into(),
        trust: 5,
    };
    assert_eq!(json(&entry.certifier_info), json(&certifier));
    assert_eq!(
        entry.publicly_revealed_keyring,
        map(&[("name", &to_base64(b"Fixture"))])
    );
    assert_eq!(entry.decrypted_fields, map(&[("role", "reader")]));
}

#[tokio::test]
async fn a_certificate_discovered_by_identity_key_reads_as_the_reference_writes_it() {
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    for (cert, icon_url) in [
        (writer_certificate(), "https://certifier.invalid/icon"),
        (reference_certificate(), "https://certifier.invalid/icon"),
        (reference_certificate(), ""),
    ] {
        let read = client(discovery_frame(&cert, icon_url))
            .discover_by_identity_key(args.clone(), Some("fixtures.invalid"))
            .await
            .unwrap();
        assert_discovered(&read, icon_url);
        assert_codec_reads(&cert, &read.certificates[0].certificate);
    }
}

#[tokio::test]
async fn a_certificate_discovered_by_attributes_reads_as_the_reference_writes_it() {
    let args = DiscoverByAttributesArgs {
        attributes: map(&[("name", "Fixture")]),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    for (cert, icon_url) in [
        (writer_certificate(), "https://certifier.invalid/icon"),
        (reference_certificate(), "https://certifier.invalid/icon"),
        (reference_certificate(), ""),
    ] {
        let read = client(discovery_frame(&cert, icon_url))
            .discover_by_attributes(args.clone(), Some("fixtures.invalid"))
            .await
            .unwrap();
        assert_discovered(&read, icon_url);
        assert_codec_reads(&cert, &read.certificates[0].certificate);
    }
}

/// The shared vector's discovery entry, the reference's bytes (and Go's
/// `SerializeIdentityCertificate`, `identity_certificate.go:12-49`).
#[tokio::test]
async fn the_shared_discovery_vector_reads_through_the_transceiver() {
    let (json, wire) = vector("discoverByIdentityKey-simple-result.json");
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    let read = client(wire[1..].to_vec())
        .discover_by_identity_key(args, Some("fixtures.invalid"))
        .await
        .unwrap();
    let expected = &json["certificates"][0];
    let entry = &read.certificates[0];
    assert_vector_certificate(&entry.certificate, expected);
    assert_eq!(
        serde_json::to_value(&entry.certifier_info).unwrap(),
        expected["certifierInfo"]
    );
    assert_eq!(
        serde_json::to_value(&entry.publicly_revealed_keyring).unwrap(),
        expected["publiclyRevealedKeyring"]
    );
    assert_eq!(
        serde_json::to_value(&entry.decrypted_fields).unwrap(),
        expected["decryptedFields"]
    );
}

/// proveCertificate's result is the keyring alone (`WalletWireProcessor.ts`,
/// a varint count and each a varint-length name and raw-byte value): no
/// certificate crosses, and the reader is pinned unchanged.
#[tokio::test]
async fn a_proved_certificate_keyring_reads_as_the_reference_writes_it() {
    let mut frame = vec![1];
    var_bytes(&mut frame, b"name");
    var_bytes(&mut frame, b"Fixture");
    let args = ProveCertificateArgs {
        certificate: certificate(),
        fields_to_reveal: vec!["name".into()],
        verifier: TWO_G.to_string(),
        privileged: None,
        privileged_reason: None,
    };
    let read = client(frame)
        .prove_certificate(args, Some("fixtures.invalid"))
        .await
        .unwrap();
    assert_eq!(
        read.keyring_for_verifier,
        map(&[("name", &to_base64(b"Fixture"))])
    );
}

fn vector(name: &str) -> (serde_json::Value, Vec<u8>) {
    let path = format!(
        "{}/tests/vectors/wallet_wire/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wire = hex::decode(v["wire"].as_str().unwrap()).unwrap();
    assert_eq!(wire[0], 0, "a success frame");
    (v["json"].clone(), wire)
}

fn assert_vector_certificate(cert: &WalletCertificate, expected: &serde_json::Value) {
    assert_eq!(cert.certificate_type, expected["type"].as_str().unwrap());
    assert_eq!(
        cert.serial_number,
        expected["serialNumber"].as_str().unwrap()
    );
    assert_eq!(cert.subject, expected["subject"].as_str().unwrap());
    assert_eq!(cert.certifier, expected["certifier"].as_str().unwrap());
    assert_eq!(
        cert.revocation_outpoint,
        expected["revocationOutpoint"].as_str().unwrap()
    );
    assert_eq!(cert.signature, expected["signature"].as_str().unwrap());
    assert_eq!(
        serde_json::to_value(&cert.fields).unwrap(),
        expected["fields"]
    );
}
