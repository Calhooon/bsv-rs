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
//! empty string is `""`, an empty map empty, a trust outside 1 to 10 refused
//! (`WalletWireTransceiver.ts:1710`; bsv-rs#247).
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::to_base64;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use indexmap::IndexMap;

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

fn map(entries: &[(&str, &str)]) -> IndexMap<String, String> {
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
        certifier_info: IdentityCertifier {
            name: "Fixture Certifier".into(),
            icon_url: "https://certifier.invalid/icon".into(),
            description: "fixture only".into(),
            trust: 5,
        },
        publicly_revealed_keyring: map(&[
            ("role", &to_base64(b"key-2")),
            ("name", &to_base64(b"key-1")),
        ]),
        decrypted_fields: map(&[("role", "reader"), ("name", "Fixture")]),
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

async fn discovered(entry: &[u8]) -> Result<IdentityCertificate, Error> {
    let mut frame = vec![1];
    frame.extend_from_slice(entry);
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    let mut result = WalletWireTransceiver::new(CannedWire { body: frame })
        .discover_by_identity_key(args, Some("fixtures.invalid"))
        .await?;
    Ok(result.certificates.remove(0))
}

/// An entry with three empty strings, `trust` and two counts of 0. At trust 0
/// it is Go's zero value for an entry with no certifier info and no maps, as
/// `SerializeIdentityCertificate` writes it (`identity_certificate.go:23-46`).
/// Hand-assembled: this crate's writer refuses to write it since #183.
fn empty_entry(trust: u8) -> Vec<u8> {
    let mut c = WireWriter::new();
    c.write_wallet_certificate(&certificate()).unwrap();
    let mut w = WireWriter::new();
    w.write_var_int(c.as_bytes().len() as u64);
    w.write_bytes(c.as_bytes());
    w.write_bytes(&[0, 0, 0, trust, 0, 0]);
    w.into_bytes()
}

#[test]
fn an_identity_certificate_the_writer_writes_reads_back_through_the_reader() {
    let cert = identity_certificate();
    assert_eq!(json(&read(&written(&cert))), json(&cert));
}

/// Go's zero value for an absent certifierInfo (which Go's writer writes and
/// this crate's refuses to, #183) is refused by the reader as the transceiver
/// refuses it, in the same words: trust 0 is outside the reference's 1 to 10
/// (`WalletWireTransceiver.ts:1710`, `:2018-2025`; bsv-rs#247). The same
/// bytes at trust 1 read as the transceiver reads them: empty strings and
/// empty maps, the members being required (bsv-rs#105).
#[tokio::test]
async fn the_zero_value_entry_is_refused_as_the_transceiver_refuses_it() {
    let words = "Invalid discovery trust: expected an integer from 1 to 10, received 0";
    let bytes = empty_entry(0);
    assert_eq!(
        WireReader::new(&bytes)
            .read_identity_certificate()
            .map(drop),
        Err(Error::WalletError(words.into()))
    );
    assert_eq!(
        discovered(&bytes).await.map(drop),
        Err(Error::WalletError(words.into()))
    );

    let bytes = empty_entry(1);
    let entry = read(&bytes);
    let empty = IdentityCertifier {
        name: String::new(),
        icon_url: String::new(),
        description: String::new(),
        trust: 1,
    };
    assert_eq!(json(&entry.certifier_info), json(&empty));
    assert!(entry.publicly_revealed_keyring.is_empty());
    assert!(entry.decrypted_fields.is_empty());
    assert_eq!(json(&discovered(&bytes).await.unwrap()), json(&entry));
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
    let strings = |value: &serde_json::Value| -> IndexMap<String, String> {
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
        certifier_info: serde_json::from_value(e["certifierInfo"].clone()).unwrap(),
        publicly_revealed_keyring: strings(&e["publiclyRevealedKeyring"]),
        decrypted_fields: strings(&e["decryptedFields"]),
    };
    assert_eq!(json(&read(&wire[2..])), json(&expected));
}

/// A keyring value crosses as raw bytes; bytes that are not UTF-8 read back as
/// their base64, as the struct carries them.
#[test]
fn a_keyring_value_whose_bytes_are_not_utf8_round_trips_as_base64() {
    let raw = [0xff, 0xfe, 0x80, 0x00, 0xc3];
    let mut cert = identity_certificate();
    cert.publicly_revealed_keyring = map(&[("name", &to_base64(&raw))]);
    let bytes = written(&cert);
    assert!(bytes
        .windows(raw.len() + 1)
        .any(|w| w[0] == 5 && w[1..] == raw));
    assert_eq!(json(&read(&bytes)), json(&cert));
}

/// A count or a length past the bytes is refused, no panic and no allocation
/// of the count (CLAUDE.md rule 5): a map's count past `2^53 - 1` in the
/// strict reader's words, as the transceiver refuses it (bsv-rs#236; until
/// then `ReaderUnderflow` when the entries ran out), as is a certificate length
/// past the same precision bound (#458).
#[test]
fn a_count_that_overruns_the_bytes_is_refused_without_a_panic() {
    let zero = empty_entry(1);
    let huge = [0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    let at = |tail: usize| -> Vec<u8> {
        let mut bytes = zero[..zero.len() - tail].to_vec();
        bytes.extend_from_slice(&huge);
        bytes
    };
    // The keyring's count, then the decrypted fields' count.
    for bytes in [at(2), at(1)] {
        let mut reader = WireReader::new(&bytes);
        assert_eq!(
            reader.read_identity_certificate().map(drop),
            Err(Error::WalletError(
                "number too large to retain precision - use readVarIntBn".into()
            ))
        );
    }
    // The certificate's length.
    let mut reader = WireReader::new(&huge);
    assert_eq!(
        reader.read_identity_certificate().map(drop),
        Err(Error::WalletError(
            "number too large to retain precision - use readVarIntBn".into()
        ))
    );
}

/// The layout this crate wrote before #182 (a present-flag byte, NIL-sentinel
/// strings and maps, keyring values as base64 text) is refused, here as
/// a short read: with a certifier present, the flag `1` is read as the
/// name's length, the name's own length byte as the name, the name's opening
/// byte as iconUrl's length, and the lengths run past the bytes; with the
/// certifier absent, the `-1` flag (`0xff`) opens a 9-byte varint that the
/// keyring's count and the opening bytes of its key complete, a length far past
/// the precision bound. Other contents can misread rather than refuse; none reads as
/// written.
#[test]
fn the_layout_before_182_is_refused() {
    let cert = identity_certificate();
    // The old layout assembled by hand: the present flag, NIL-sentinel
    // strings, and maps behind a count or the NIL sentinel.
    let old_map = |w: &mut WireWriter, map: Option<&IndexMap<String, String>>| match map {
        None => {
            w.write_var_int(u64::MAX);
        }
        Some(map) => {
            w.write_string_map(map);
        }
    };
    let old = |certifier: Option<&IdentityCertifier>| -> Vec<u8> {
        let mut c = WireWriter::new();
        c.write_wallet_certificate(&cert.certificate).unwrap();
        let mut w = WireWriter::new();
        w.write_var_int(c.as_bytes().len() as u64);
        w.write_bytes(c.as_bytes());
        match certifier {
            None => {
                w.write_i8(-1);
            }
            Some(c) => {
                w.write_i8(1);
                w.write_string(&c.name);
                w.write_optional_string(Some(&c.icon_url));
                w.write_optional_string(Some(&c.description));
                w.write_u8(c.trust);
            }
        }
        old_map(&mut w, Some(&cert.publicly_revealed_keyring));
        old_map(&mut w, Some(&cert.decrypted_fields));
        w.into_bytes()
    };
    for (bytes, words) in [
        (
            old(Some(&cert.certifier_info)),
            "ReaderUint8Array read exceeds available data",
        ),
        (
            old(None),
            "number too large to retain precision - use readVarIntBn",
        ),
    ] {
        let mut reader = WireReader::new(&bytes);
        assert_eq!(
            reader.read_identity_certificate().map(drop),
            Err(Error::WalletError(words.into()))
        );
    }
}

/// `read_identity_certifier` reads the three strings and the byte, a trust
/// outside 1 to 10 refused in the transceiver's words (bsv-rs#247); the layout
/// before #182 is the same bytes when iconUrl and description are present, and
/// a NIL sentinel for an absent one, which is an unsigned length past 2^53 - 1,
/// refused.
#[test]
fn the_certifier_reader_reads_three_plain_strings_and_the_trust_byte() {
    let info = identity_certificate().certifier_info;
    let mut w = WireWriter::new();
    w.write_string(&info.name);
    w.write_string(&info.icon_url);
    w.write_string(&info.description);
    w.write_u8(info.trust);
    let mut reader = WireReader::new(w.as_bytes());
    assert_eq!(
        json(&reader.read_identity_certifier().unwrap()),
        json(&info)
    );
    assert_eq!(reader.remaining(), 0);

    let mut nil = WireWriter::new();
    nil.write_string(&info.name);
    nil.write_var_int(u64::MAX);
    nil.write_string(&info.description);
    nil.write_u8(info.trust);
    assert_eq!(
        WireReader::new(nil.as_bytes())
            .read_identity_certifier()
            .map(drop),
        Err(Error::WalletError(
            "number too large to retain precision - use readVarIntBn".into()
        ))
    );

    for trust in [0u8, 11] {
        let mut w = WireWriter::new();
        w.write_string(&info.name);
        w.write_string("");
        w.write_string("");
        w.write_u8(trust);
        let words =
            format!("Invalid discovery trust: expected an integer from 1 to 10, received {trust}");
        assert_eq!(
            WireReader::new(w.as_bytes())
                .read_identity_certifier()
                .map(drop),
            Err(Error::WalletError(words.clone()))
        );
        assert_eq!(
            WireReader::new(w.as_bytes())
                .read_optional_identity_certifier()
                .map(drop),
            Err(Error::WalletError(words))
        );
    }
}
