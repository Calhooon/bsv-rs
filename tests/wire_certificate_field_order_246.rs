//! The wire's certificate writer writes the fields in the order the
//! signature is made over (#246).
//!
//! The reference's processor writes a certificate with `Certificate.toBinary`
//! (`ts-stack@edf6e03` `WalletWireProcessor.ts:1975`, `:2067`, `:2501`),
//! which orders the field names by `localeCompare` (`Certificate.ts:282`),
//! the order its `sign` signs over and this crate's `Certificate::sign` signs
//! over since #249. A certificate signed here and written by
//! `WireWriter::write_wallet_certificate` is the reference's bytes
//! (`tests/vectors/auth_certificate_field_order_249.json`, written by
//! `tests/support/certificate_field_order_249.mjs` against the reference),
//! and verifies over the bytes received, which this crate's
//! `Certificate::from_binary` keeps (BRC-52 `0052.md:103`). Until #246 the
//! writer sorted the names by bytes: `Name, a0, a_b, age, f, éa` where the
//! signature covers `a_b, a0, age, éa, f, Name`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::Certificate;
use bsv_rs::primitives::{from_hex, to_base64, to_hex, PrivateKey};
use bsv_rs::wallet::types::Outpoint;
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::WalletCertificate;
use serde::Deserialize;

#[derive(Deserialize)]
struct Witnesses {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    reference_verify: Option<bool>,
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

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", scalar)).unwrap()
}

/// The six names of #249's witness, each valued the base64 text of
/// `v-<name>`, as `certificate_field_order_249.mjs` builds them.
const NAMES: [&str; 6] = ["Name", "a_b", "age", "a0", "éa", "f"];

/// A certificate over the six names signed here by `certifier`.
fn signed_here(
    cert_type: [u8; 32],
    serial: [u8; 32],
    subject: u8,
    certifier: u8,
    outpoint: Option<Outpoint>,
) -> Certificate {
    let fields = NAMES
        .iter()
        .map(|n| (n.to_string(), to_base64(format!("v-{n}").as_bytes())))
        .collect();
    let mut cert = Certificate::new(
        cert_type,
        serial,
        key(subject).public_key(),
        key(certifier).public_key(),
    )
    .with_revocation_outpoint(outpoint)
    .with_fields(fields);
    cert.sign(&key(certifier)).unwrap();
    cert
}

/// The wallet's certificate: the fields' values the base64 text the
/// certificate carries, the outpoint `txid.index` (the zero sentinel for
/// none).
fn wallet_certificate(cert: &Certificate) -> WalletCertificate {
    let (txid, index) = cert
        .revocation_outpoint
        .as_ref()
        .map_or(([0u8; 32], 0), |o| (o.txid, o.vout));
    WalletCertificate {
        certificate_type: to_base64(&cert.cert_type),
        subject: cert.subject.to_hex(),
        serial_number: to_base64(&cert.serial_number),
        certifier: cert.certifier.to_hex(),
        revocation_outpoint: format!("{}.{index}", to_hex(&txid)),
        signature: to_hex(cert.signature.as_ref().unwrap()),
        fields: cert.fields.clone(),
    }
}

fn write(cert: &WalletCertificate) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_wallet_certificate(cert).unwrap();
    w.into_bytes()
}

/// `cert` written to the wire is `witness`'s bytes, verifies over them when
/// read back, and the wire's reader reads it to the same certificate.
fn assert_wire_frame_is_the_signed_bytes(cert: &Certificate, witness: &Witness) {
    assert_eq!(witness.reference_verify, Some(true), "{}", witness.name);
    let wallet = wallet_certificate(cert);
    let frame = write(&wallet);
    assert_eq!(to_hex(&frame), witness.hex, "{}", witness.name);
    assert_eq!(frame, cert.to_binary(true).unwrap(), "{}", witness.name);

    let read = Certificate::from_binary(&frame).unwrap();
    assert_eq!(read.verify(), Ok(true), "{}", witness.name);

    let back = WireReader::new(&frame).read_wallet_certificate().unwrap();
    assert_eq!(
        serde_json::to_value(&back).unwrap(),
        serde_json::to_value(&wallet).unwrap(),
        "{}",
        witness.name
    );
    assert_eq!(write(&back), frame, "{}", witness.name);
}

#[test]
fn a_certificate_signed_here_is_written_to_the_wire_in_the_signed_order() {
    // The reference's certificate (certifier 21, subject 23, type 32 x 0x06,
    // serial 32 x 0x07, no revocation outpoint): signed here it is the
    // reference's signature, RFC 6979 on both sides.
    let cert = signed_here([6u8; 32], [7u8; 32], 23, 21, None);
    assert_wire_frame_is_the_signed_bytes(&cert, &witness("reference_signed_mixed_names"));

    // This crate's witness, which the reference verifies.
    let cert = signed_here(
        [8u8; 32],
        [9u8; 32],
        27,
        25,
        Some(Outpoint::new([10u8; 32], 1)),
    );
    assert_wire_frame_is_the_signed_bytes(&cert, &witness("rust_signed_mixed_names"));
}

#[test]
fn the_wire_writes_the_names_in_local_compare_order_not_byte_order() {
    let cert = signed_here([6u8; 32], [7u8; 32], 23, 21, None);
    let frame = write(&wallet_certificate(&cert));
    // The fields follow type, serial, subject, certifier, txid and a one-byte
    // index: a one-byte count, then each name and value.
    let mut at = 32 + 32 + 33 + 33 + 32 + 1;
    assert_eq!(frame[at], 6);
    at += 1;
    let mut names = Vec::new();
    for _ in 0..6 {
        let len = frame[at] as usize;
        names.push(String::from_utf8(frame[at + 1..at + 1 + len].to_vec()).unwrap());
        at += 1 + len;
        at += 1 + frame[at] as usize;
    }
    assert_eq!(names, ["a_b", "a0", "age", "éa", "f", "Name"]);
    assert_eq!(
        from_hex(&witness("reference_signed_mixed_names").hex).unwrap(),
        frame
    );
}
