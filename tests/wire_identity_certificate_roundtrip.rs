//! `WireReader::read_identity_certificate` and `read_optional_identity_certifier`
//! read one discovery entry as `WireWriter::write_identity_certificate` writes
//! it and the reference reads it (bsv-rs#184).
//!
//! The reference's discovery reader (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1700-1752`) and
//! Go's `DeserializeIdentityCertificate` (`go-sdk@2ca481c`
//! `wallet/serializer/identity_certificate.go:51-100`): the certificate behind a
//! varint length, name, iconUrl and description as plain strings, trust a byte,
//! the public keyring as a count of varint-length key and varint-length raw-byte
//! pairs (rendered base64), the decrypted fields as a count of string pairs.
//! The reader reads as the transceiver's `parse_discovery_result` reads: an
//! empty string is `Some("")`, an empty map `None`, trust 0 as written.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::to_base64;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader, WireWriter};
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

/// Reads one entry and asserts the reader consumed every byte of it.
fn read(bytes: &[u8]) -> IdentityCertificate {
    let mut reader = WireReader::new(bytes);
    let cert = reader.read_identity_certificate().unwrap();
    assert_eq!(reader.remaining(), 0, "the entry is read to its end");
    cert
}

async fn discovered(entry: &[u8]) -> IdentityCertificate {
    let mut frame = vec![1];
    frame.extend_from_slice(entry);
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    let mut result = WalletWireTransceiver::new(CannedWire { body: frame })
        .discover_by_identity_key(args, "fixtures.invalid")
        .await
        .unwrap();
    result.certificates.remove(0)
}

#[test]
fn an_identity_certificate_the_writer_writes_reads_back_through_the_reader() {
    let cert = identity_certificate();
    assert_eq!(json(&read(&written(&cert))), json(&cert));
}

/// Go's zero value, which the writer writes for an absent certifierInfo or map,
/// reads back as the transceiver reads it: `Some` with empty strings and trust
/// 0, the maps `None`; never `None` for the certifier.
#[tokio::test]
async fn the_zero_value_entry_reads_back_as_the_transceiver_reads_it() {
    let bytes = written(&IdentityCertificate {
        certificate: certificate(),
        certifier_info: None,
        publicly_revealed_keyring: None,
        decrypted_fields: None,
    });
    let entry = read(&bytes);
    let zero = IdentityCertifier {
        name: String::new(),
        icon_url: Some(String::new()),
        description: Some(String::new()),
        trust: 0,
    };
    assert_eq!(json(&entry.certifier_info), json(&Some(zero)));
    assert_eq!(entry.publicly_revealed_keyring, None);
    assert_eq!(entry.decrypted_fields, None);
    assert_eq!(json(&entry), json(&discovered(&bytes).await));
}

/// The shared vector's entry (the bytes TS and Go exchange) reads to the
/// vector's value: the proof against the reference, not only this crate's writer.
#[test]
fn the_shared_discovery_vector_entry_reads_through_the_reader_to_the_vectors_fields() {
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
    let expected = IdentityCertificate {
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
    assert_eq!(json(&read(&wire[2..])), json(&expected));
}

/// A keyring value crosses as raw bytes; bytes that are not UTF-8 read back as
/// their base64, as the struct carries them.
#[test]
fn a_keyring_value_whose_bytes_are_not_utf8_round_trips_as_base64() {
    let raw = [0xff, 0xfe, 0x80, 0x00, 0xc3];
    let mut cert = identity_certificate();
    cert.publicly_revealed_keyring = Some(map(&[("name", &to_base64(&raw))]));
    let bytes = written(&cert);
    assert!(bytes
        .windows(raw.len() + 1)
        .any(|w| w[0] == 5 && w[1..] == raw));
    assert_eq!(json(&read(&bytes)), json(&cert));
}

/// A count or a length past the bytes is `ReaderUnderflow`, no panic and no
/// allocation of the count (`bounded_capacity`, CLAUDE.md rule 5).
#[test]
fn a_count_that_overruns_the_bytes_is_refused_without_a_panic() {
    let zero = written(&IdentityCertificate {
        certificate: certificate(),
        certifier_info: None,
        publicly_revealed_keyring: None,
        decrypted_fields: None,
    });
    let huge = [0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    let at = |tail: usize| -> Vec<u8> {
        let mut bytes = zero[..zero.len() - tail].to_vec();
        bytes.extend_from_slice(&huge);
        bytes
    };
    // The keyring's count, then the decrypted fields' count.
    for bytes in [at(2), at(1)] {
        let mut reader = WireReader::new(&bytes);
        assert!(matches!(
            reader.read_identity_certificate(),
            Err(Error::ReaderUnderflow { .. })
        ));
    }
    // The certificate's length.
    let mut reader = WireReader::new(&huge);
    assert!(matches!(
        reader.read_identity_certificate(),
        Err(Error::ReaderUnderflow { .. })
    ));
}

/// The layout this crate wrote before #182 (a present-flag byte, NIL-sentinel
/// strings and maps, keyring values as base64 text) is refused, here as
/// `ReaderUnderflow`: the flag `1` is read as the name's length, the name's own
/// length byte as the name, its first character as iconUrl's length, and the
/// lengths run past the bytes; an absent certifier's `-1` flag opens a 9-byte
/// varint that the keyring's NIL sentinel completes as a length of `u64::MAX`.
/// Other contents can misread rather than refuse; none reads as written.
#[test]
#[allow(deprecated)]
fn the_layout_before_182_is_refused() {
    let cert = identity_certificate();
    let old = |certifier: Option<&IdentityCertifier>| -> Vec<u8> {
        let mut c = WireWriter::new();
        c.write_wallet_certificate(&cert.certificate).unwrap();
        let mut w = WireWriter::new();
        w.write_var_int(c.as_bytes().len() as u64);
        w.write_bytes(c.as_bytes());
        w.write_optional_identity_certifier(certifier);
        w.write_optional_string_map(cert.publicly_revealed_keyring.as_ref());
        w.write_optional_string_map(cert.decrypted_fields.as_ref());
        w.into_bytes()
    };
    for bytes in [old(cert.certifier_info.as_ref()), old(None)] {
        let mut reader = WireReader::new(&bytes);
        assert!(matches!(
            reader.read_identity_certificate(),
            Err(Error::ReaderUnderflow { .. })
        ));
    }
}

/// `read_identity_certifier` reads the three strings and the byte; the old
/// `write_identity_certifier` writes the same bytes when iconUrl and
/// description are present, and a NIL sentinel for an absent one, which is now
/// a length past the bytes, refused.
#[test]
#[allow(deprecated)]
fn the_certifier_reader_reads_three_plain_strings_and_the_trust_byte() {
    let info = identity_certificate().certifier_info.unwrap();
    let mut w = WireWriter::new();
    w.write_string(&info.name);
    w.write_string(info.icon_url.as_deref().unwrap());
    w.write_string(info.description.as_deref().unwrap());
    w.write_u8(info.trust);
    let mut old = WireWriter::new();
    old.write_identity_certifier(&info);
    assert_eq!(old.as_bytes(), w.as_bytes());
    let mut reader = WireReader::new(w.as_bytes());
    assert_eq!(
        json(&reader.read_identity_certifier().unwrap()),
        json(&info)
    );
    assert_eq!(reader.remaining(), 0);

    let mut nil = WireWriter::new();
    nil.write_identity_certifier(&IdentityCertifier {
        icon_url: None,
        ..info
    });
    assert!(matches!(
        WireReader::new(nil.as_bytes()).read_identity_certifier(),
        Err(Error::ReaderUnderflow { .. })
    ));
}
