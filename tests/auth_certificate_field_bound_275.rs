//! A certificate field value is bounded as the reference bounds it (#275).
//!
//! `Certificate.toBinary` refuses a value whose text is over 1 MiB of UTF-8
//! in its snapshot of the fields, and `fromBinary` a declared value length
//! over 1 MiB before it reads the bytes, both in one text, `Certificate field
//! <name> exceeds the maximum of 1048576 bytes` (`ts-stack@edf6e03`
//! `Certificate.ts:27`, `:76-79`, `:377-381`); `sign` and `verify` serialize
//! through `toBinary` (`:458`, `:427`). The wallet wire's writer and reader
//! carry the same text (#246, #189). Where a field is decrypted, the
//! reference reads its text as canonical base64 of 1 byte to 1 MiB
//! (`MasterCertificate.ts:63-74`, `:351-357`, `:587-591`;
//! `VerifiableCertificate.ts:41-52`, `:187-191`; `WalletByteEncoding.ts:39-64`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{to_base64, PrivateKey};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use std::collections::HashMap;

const MIB: usize = 1024 * 1024;
const OVER: &str = "Certificate field big exceeds the maximum of 1048576 bytes";

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

fn certificate() -> Certificate {
    Certificate::new(
        [1u8; 32],
        [2u8; 32],
        key(3).public_key(),
        key(4).public_key(),
    )
}

fn refused(words: &str) -> Error {
    Error::CertificateValidationError(words.into())
}

/// A varint as the reader reads it.
fn varint(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [&[0xfd][..], &(n as u16).to_le_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[0xfe][..], &(n as u32).to_le_bytes()].concat(),
        _ => [&[0xff][..], &n.to_le_bytes()].concat(),
    }
}

/// This crate's writer's frame with no field, its count byte replaced by one
/// field `name` of declared length `declared` and the bytes `value`: the
/// writer's bound bypassed.
fn frame_with_one_field(name: &str, declared: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = certificate().to_binary(false).unwrap();
    assert_eq!(bytes.pop(), Some(0), "the field count is the last byte");
    bytes.push(1);
    bytes.extend(varint(name.len() as u64));
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend(varint(declared));
    bytes.extend_from_slice(value);
    bytes
}

#[test]
fn a_field_value_of_exactly_one_mib_is_written_read_signed_and_verified_275() {
    let value = "A".repeat(MIB);
    let mut cert = certificate();
    cert.set_field("big", value.clone());
    let unsigned = cert.to_binary(false).unwrap();
    assert_eq!(
        Certificate::from_binary(&unsigned).unwrap().fields["big"],
        value
    );
    cert.sign(&key(4)).unwrap();
    let signed = cert.to_binary(true).unwrap();
    let read = Certificate::from_binary(&signed).unwrap();
    assert_eq!(read.fields["big"], value);
    assert_eq!(read.verify(), Ok(true));
    // The hand-built frame of exactly the bound reads too.
    let frame = frame_with_one_field("big", MIB as u64, value.as_bytes());
    assert_eq!(
        Certificate::from_binary(&frame).unwrap().fields["big"],
        value
    );
}

#[test]
fn a_field_value_one_byte_over_one_mib_is_refused_by_the_writer_in_the_reference_words_275() {
    let mut cert = certificate();
    cert.set_field("small", "QQ==");
    cert.set_field("big", "A".repeat(MIB + 1));
    assert_eq!(cert.to_binary(false), Err(refused(OVER)));
    assert_eq!(cert.to_binary(true), Err(refused(OVER)));
    assert_eq!(cert.signing_hash(), Err(refused(OVER)));
    assert_eq!(cert.sign(&key(4)), Err(refused(OVER)));
    assert_eq!(cert.signature, None, "nothing signed");
    // The text's UTF-8 bytes are measured, not its characters: half a
    // mebibyte of two-byte characters and one more byte is over.
    let mut wide = certificate();
    wide.set_field("big", format!("{}A", "é".repeat(MIB / 2)));
    assert_eq!(wide.to_binary(false), Err(refused(OVER)));
}

#[test]
fn a_signed_certificate_given_a_field_value_over_one_mib_is_false_at_verify_275() {
    let mut cert = certificate();
    cert.set_field("big", "QQ==");
    cert.sign(&key(4)).unwrap();
    cert.fields.insert("big".into(), "A".repeat(MIB + 1));
    // The reference's `verify` answers `false` to every failure under it
    // (`Certificate.ts:435-439`), the bound's refusal with them.
    assert_eq!(cert.verify(), Ok(false));
}

#[test]
fn a_frame_with_a_field_value_one_byte_over_one_mib_is_refused_by_the_reader_275() {
    let value = vec![b'A'; MIB + 1];
    let frame = frame_with_one_field("big", value.len() as u64, &value);
    assert_eq!(
        Certificate::from_binary(&frame).map(drop),
        Err(refused(OVER))
    );
}

#[test]
fn a_declared_field_value_length_over_one_mib_is_refused_before_its_bytes_are_read_275() {
    // A length the frame does not carry: the bound is the refusal, not the
    // bytes remaining.
    for declared in [MIB as u64 + 1, u32::MAX.into(), u64::MAX] {
        let frame = frame_with_one_field("big", declared, b"AAAA");
        assert_eq!(
            Certificate::from_binary(&frame).map(drop),
            Err(refused(OVER)),
            "{declared}"
        );
    }
}

#[test]
fn the_certificate_and_the_wallet_wire_refuse_an_over_bound_value_in_one_text_275() {
    let mut cert = certificate();
    cert.set_field("big", "QQ==");
    cert.sign(&key(4)).unwrap();
    let signed = cert.to_binary(true).unwrap();
    let mut on_the_wire = WireReader::new(&signed).read_wallet_certificate().unwrap();
    cert.fields.insert("big".into(), "A".repeat(MIB + 1));
    let Err(Error::CertificateValidationError(words)) = cert.to_binary(true) else {
        panic!("refused");
    };
    on_the_wire.fields.insert("big".into(), "A".repeat(MIB + 1));
    let mut w = WireWriter::new();
    assert_eq!(
        w.write_wallet_certificate(&on_the_wire).map(drop),
        Err(Error::WalletError(words.clone()))
    );
    let value = vec![b'A'; MIB + 1];
    let frame = frame_with_one_field("big", value.len() as u64, &value);
    assert_eq!(
        WireReader::new(&frame).read_wallet_certificate().map(drop),
        Err(Error::WalletError(words))
    );
}

/// A master certificate of one field, `name`, and a verifier's keyring for it.
async fn issued() -> (MasterCertificate, VerifiableCertificate) {
    let (certifier, subject, verifier) = (key(43), key(47), key(41));
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier,
        subject.public_key(),
        HashMap::from([("name".to_string(), "Alice".to_string())]),
        [8u8; 32],
        Some([9u8; 32]),
        "test",
    )
    .await
    .unwrap();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(subject)),
        &certifier.public_key(),
        &verifier.public_key(),
        &master.fields,
        &["name".to_string()],
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

/// Texts of the field's ciphertext that are not canonical base64, each with
/// the words the reference refuses it in; the first three decode to the
/// ciphertext under a lenient decoder.
fn non_canonical(text: &str) -> Vec<(String, &'static str)> {
    // "Alice": 32 + 5 + 16 = 53 bytes, one '=' of padding.
    assert!(text.ends_with('=') && !text.ends_with("=="), "{text}");
    let unused_bits_set = {
        let mut chars: Vec<char> = text.chars().collect();
        let at = chars.len() - 2;
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let index = alphabet.find(chars[at]).unwrap();
        chars[at] = alphabet.chars().nth(index | 1).unwrap();
        chars.into_iter().collect::<String>()
    };
    let encoding = "Certificate field name must use canonical base64 encoding";
    let size = "Certificate field name is empty, oversized, or non-canonical";
    vec![
        (text.trim_end_matches('=').to_string(), encoding),
        (format!(" {text}\n"), encoding),
        (format!("{}\n{}", &text[..4], &text[4..]), encoding),
        (unused_bits_set, encoding),
        (String::new(), size),
        (to_base64(&vec![0u8; MIB + 1]), size),
    ]
}

#[tokio::test]
async fn a_field_value_that_is_not_canonical_base64_is_refused_at_decrypt_275() {
    let (master, verifiable) = issued().await;
    let (certifier, subject, verifier) = (key(43), key(47), key(41));
    let subject_wallet = ProtoWallet::new(Some(subject));
    let verifier_wallet = ProtoWallet::new(Some(verifier));
    let text = master.fields["name"].clone();
    assert_eq!(
        master
            .decrypt_field(
                &subject_wallet,
                &certifier.public_key(),
                "name",
                None,
                None,
                "test"
            )
            .await,
        Ok("Alice".to_string())
    );
    assert_eq!(
        verifiable
            .decrypt_field(&verifier_wallet, "name", None, None, "test")
            .await,
        Ok("Alice".to_string())
    );
    for (bad, words) in non_canonical(&text) {
        let mut m = master.clone();
        m.certificate.fields.insert("name".into(), bad.clone());
        assert_eq!(
            m.decrypt_field(
                &subject_wallet,
                &certifier.public_key(),
                "name",
                None,
                None,
                "test"
            )
            .await,
            Err(refused(words)),
            "master {bad:.40}"
        );
        let mut v = verifiable.clone();
        v.certificate.fields.insert("name".into(), bad.clone());
        assert_eq!(
            v.decrypt_field(&verifier_wallet, "name", None, None, "test")
                .await,
            Err(refused(words)),
            "verifiable {bad:.40}"
        );
    }
}

#[tokio::test]
async fn a_keyring_for_a_verifier_refuses_a_non_canonical_field_it_does_not_reveal_275() {
    let (master, _) = issued().await;
    let mut fields = master.fields.clone();
    fields.insert("other".into(), "Zm8".into());
    let result = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(key(47))),
        &key(43).public_key(),
        &key(41).public_key(),
        &fields,
        &["name".to_string()],
        &master.master_keyring,
        &master.serial_number,
        None,
        None,
        "test",
    )
    .await;
    assert_eq!(
        result,
        Err(refused(
            "Certificate field other must use canonical base64 encoding"
        ))
    );
}
