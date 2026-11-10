//! #842: `Signature::from_der` reads a DER signature as the reference's
//! `Signature.fromDER` does (`ts-stack@edf6e03`
//! `packages/sdk/src/primitives/Signature.ts:44-97`), and so do the doors that
//! read a DER signature through it, against `vectors/signature_der_842.json`
//! (`support/signature_der_842.mjs`, Node v22.18.0, two runs byte-identical):
//! `TransactionSignature::from_checksig_format` (`TransactionSignature.ts:460-472`),
//! `messages::verify` (`SignedMessage.ts:65-105`), `compat::bsm::verify_message_der`
//! (`Signature.fromDER` then `BSM.verify`, `BSM.ts:71-74`; the reference's BSM
//! takes a parsed signature) and `ProtoWallet::verify_signature`
//! (`ProtoWallet.ts:358-394`, its argument validator ahead of the reader). Every signature the
//! cells are built from is this crate's signer's, equal to the recording's,
//! and every shape is rebuilt here from it and compared with the recorded
//! bytes. Until #842 bytes after a signature, a wrong sequence length and an
//! unneeded leading zero were accepted, so a signed message or a BSM
//! signature with bytes after its DER verified as the signature alone.
//!
//! One cell is stated, not followed (`STATED`): R past 32 bytes, a value at or
//! above 2^256, which the reference holds as a `BigNumber` and its verify
//! answers false, where this crate's `Signature` holds 32 bytes and refuses it
//! as `Integer component too large`.
#![cfg(all(feature = "messages", feature = "compat"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::compat::bsm;
use bsv_rs::messages;
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::ec::{PrivateKey, Signature};
use bsv_rs::primitives::{sha256, BigNumber};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use bsv_rs::Error;
use serde_json::Value;

const MESSAGE: &[u8] = b"hello";
/// The one cell the reference accepts and this crate's 32-byte type cannot hold.
const STATED: &str = "r_past_32_bytes";
const TOO_LARGE: &str = "ERR:Integer component too large";

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/signature_der_842.json")).unwrap()
}

fn key() -> PrivateKey {
    PrivateKey::from_bytes(&[0x2b; 32]).unwrap()
}

fn cases<'a>(vector: &'a Value, door: &str) -> &'a [Value] {
    vector[door]["cases"].as_array().unwrap()
}

fn der_of(case: &Value) -> Vec<u8> {
    hex::decode(case["der"].as_str().unwrap()).unwrap()
}

fn value(bytes: &[u8; 32]) -> String {
    let text = hex::encode(bytes);
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

fn words(error: Error) -> String {
    match error {
        Error::InvalidSignature(words) => format!("ERR:{words}"),
        Error::WalletRefusal { message, .. } => format!("ERR:{message}"),
        other => format!("OTHER:{other}"),
    }
}

fn from_der(der: &[u8]) -> String {
    match Signature::from_der(der) {
        Ok(sig) => format!("ok {} {}", value(sig.r()), value(sig.s())),
        Err(error) => words(error),
    }
}

fn from_checksig_format(checksig: &[u8]) -> String {
    match TransactionSignature::from_checksig_format(checksig) {
        Ok(sig) => format!("ok {} {} {}", value(sig.r()), value(sig.s()), sig.scope()),
        Err(error) => words(error),
    }
}

fn verdict(result: bsv_rs::Result<bool>) -> String {
    match result {
        Ok(valid) => valid.to_string(),
        Err(error) => words(error),
    }
}

/// The shapes of a signature's DER, built here as the recorder builds them.
fn shapes(der: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let r_len = usize::from(der[3]);
    let (r, s) = (&der[4..4 + r_len], &der[6 + r_len..]);
    let strip = |v: &[u8]| {
        v.iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect::<Vec<u8>>()
    };
    let seq = |r: &[u8], s: &[u8]| {
        let mut body = vec![0x02, r.len() as u8];
        body.extend_from_slice(r);
        body.extend_from_slice(&[0x02, s.len() as u8]);
        body.extend_from_slice(s);
        [vec![0x30, body.len() as u8], body].concat()
    };
    let long = |r_long: bool| {
        let mut body = vec![0x02];
        body.extend(if r_long {
            vec![0x81, r.len() as u8]
        } else {
            vec![r.len() as u8]
        });
        body.extend_from_slice(r);
        body.push(0x02);
        body.extend(if r_long {
            vec![s.len() as u8]
        } else {
            vec![0x81, s.len() as u8]
        });
        body.extend_from_slice(s);
        [vec![0x30, body.len() as u8], body].concat()
    };
    let mut big = vec![1u8];
    big.extend(vec![0u8; 32 - strip(r).len()]);
    big.extend(strip(r));
    vec![
        ("canonical", der.to_vec()),
        ("suffix_1", [der, &[0]].concat()),
        ("suffix_2", [der, &[0, 1]].concat()),
        ("suffix_33", [der, &(0..33).collect::<Vec<u8>>()].concat()),
        (
            "sequence_length_short",
            [&[0x30, der[1] - 1], &der[2..]].concat(),
        ),
        (
            "sequence_length_long_over_a_byte",
            [&[0x30, der[1] + 1], &der[2..], &[0]].concat(),
        ),
        ("long_form_sequence", [&[0x30, 0x81], &der[1..]].concat()),
        ("long_form_r", long(true)),
        ("long_form_s", long(false)),
        ("r_padded", seq(&[&[0, 0], &strip(r)[..]].concat(), s)),
        ("s_padded", seq(r, &[&[0], s].concat())),
        ("r_past_32_bytes", seq(&big, s)),
    ]
}

/// The recorded cases are the shapes of the recorded DER, by this crate's
/// builder above, in order.
fn assert_shapes(door: &Value) {
    let der = hex::decode(door["der"].as_str().unwrap()).unwrap();
    let built = shapes(&der);
    let recorded = door["cases"].as_array().unwrap();
    assert_eq!(built.len(), recorded.len());
    for ((name, bytes), case) in built.iter().zip(recorded) {
        assert_eq!(case["name"], *name);
        assert_eq!(hex::encode(bytes), case["der"].as_str().unwrap(), "{name}");
    }
}

fn wallet_args() -> (Protocol, String, Counterparty) {
    (
        Protocol::new(SecurityLevel::Counterparty, "tests"),
        "1".into(),
        Counterparty::Self_,
    )
}

#[test]
fn the_three_signatures_are_this_crates_signers_and_the_shapes_its_builders_842() {
    let vector = vector();
    let signed = messages::sign_with(MESSAGE, &key(), None, [1; 32]).unwrap();
    let recorded = [
        vector["signed_message"]["prefix"].as_str().unwrap(),
        vector["signed_message"]["der"].as_str().unwrap(),
    ]
    .concat();
    assert_eq!(hex::encode(&signed), recorded);
    let bsm_der = key().sign(&bsm::magic_hash(MESSAGE)).unwrap().to_der();
    assert_eq!(hex::encode(bsm_der), vector["bsm"]["der"].as_str().unwrap());
    let (protocol_id, key_id, counterparty) = wallet_args();
    let wallet_der = ProtoWallet::new(Some(key()))
        .create_signature(CreateSignatureArgs {
            data: Some(vec![1, 2, 3]),
            protocol_id,
            key_id,
            counterparty: Some(counterparty),
            ..Default::default()
        })
        .unwrap()
        .signature;
    assert_eq!(
        hex::encode(wallet_der),
        vector["proto_wallet"]["der"].as_str().unwrap()
    );
    for door in ["signed_message", "bsm", "proto_wallet"] {
        assert_shapes(&vector[door]);
    }
}

#[test]
fn a_der_signature_followed_by_bytes_is_refused_842() {
    let vector = vector();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        if !name.starts_with("suffix") {
            continue;
        }
        assert_eq!(
            from_der(&der_of(case)),
            case["from_der"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_sequence_length_other_than_its_contents_is_refused_842() {
    let vector = vector();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        if !name.starts_with("sequence_length") {
            continue;
        }
        assert_eq!(
            from_der(&der_of(case)),
            case["from_der"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_long_form_length_is_refused_in_the_reference_words_842() {
    let vector = vector();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        if !name.starts_with("long_form") {
            continue;
        }
        assert_eq!(
            from_der(&der_of(case)),
            "ERR:Invalid DER entity length",
            "{name}"
        );
        assert_eq!(
            from_der(&der_of(case)),
            case["from_der"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn an_unneeded_leading_zero_is_refused_842() {
    let vector = vector();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        if !name.ends_with("_padded") {
            continue;
        }
        assert_eq!(
            from_der(&der_of(case)),
            case["from_der"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn every_reader_cell_is_the_reference_save_the_stated_one_842() {
    let vector = vector();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        let der = der_of(case);
        let checksig = [&der[..], &[0x41]].concat();
        if name == STATED {
            assert!(case["from_der"].as_str().unwrap().starts_with("ok 1"));
            assert_eq!(from_der(&der), TOO_LARGE);
            assert_eq!(from_checksig_format(&checksig), TOO_LARGE);
            continue;
        }
        assert_eq!(from_der(&der), case["from_der"].as_str().unwrap(), "{name}");
        assert_eq!(
            from_checksig_format(&checksig),
            case["from_checksig_format"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn an_input_under_eight_bytes_and_a_lone_byte_are_read_as_the_reference_reads_them_842() {
    let vector = vector();
    for case in vector["reader"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let der = der_of(case);
        if name == "checksig_empty" {
            assert_eq!(
                from_checksig_format(&[]),
                case["from_checksig_format"].as_str().unwrap()
            );
            continue;
        }
        assert_eq!(from_der(&der), case["from_der"].as_str().unwrap(), "{name}");
        assert_eq!(
            from_checksig_format(&[&der[..], &[0x41]].concat()),
            case["from_checksig_format"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_signed_message_with_bytes_after_its_signature_does_not_verify_842() {
    let vector = vector();
    let prefix = hex::decode(vector["signed_message"]["prefix"].as_str().unwrap()).unwrap();
    for case in cases(&vector, "signed_message") {
        let name = case["name"].as_str().unwrap();
        let signed = [&prefix[..], &der_of(case)].concat();
        let got = verdict(messages::verify(MESSAGE, &signed, None));
        if name == STATED {
            assert_eq!(case["verify"], "false");
            assert_eq!(got, TOO_LARGE);
            continue;
        }
        assert_eq!(got, case["verify"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn a_bsm_signature_with_bytes_after_it_does_not_verify_842() {
    let vector = vector();
    let public_key = key().public_key();
    for case in cases(&vector, "bsm") {
        let name = case["name"].as_str().unwrap();
        let got = verdict(bsm::verify_message_der(&der_of(case), &public_key, MESSAGE));
        if name == STATED {
            assert_eq!(case["verify"], "false");
            assert_eq!(got, TOO_LARGE);
            continue;
        }
        assert_eq!(got, case["verify"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn a_proto_wallet_refuses_every_shape_at_its_argument_check_as_the_reference_does_842() {
    let vector = vector();
    let wallet = ProtoWallet::new(Some(key()));
    for case in cases(&vector, "proto_wallet") {
        let name = case["name"].as_str().unwrap();
        let (protocol_id, key_id, counterparty) = wallet_args();
        let got = match wallet.verify_signature(VerifySignatureArgs {
            data: Some(vec![1, 2, 3]),
            signature: der_of(case),
            protocol_id,
            key_id,
            counterparty: Some(counterparty),
            ..Default::default()
        }) {
            Ok(result) => result.valid.to_string(),
            Err(error) => words(error),
        };
        assert_eq!(got, case["verify"].as_str().unwrap(), "{name}");
    }
}

/// Every signature this crate writes reads back: 1,000 signatures of this
/// crate's signer over 1,000 digests (low S; R with and without its sign
/// byte) and each with S negated (high S), which `to_der` writes as its
/// low-S twin; the bytes read write back to themselves.
#[test]
fn every_signature_this_crate_writes_reads_back_equal_842() {
    let n = BigNumber::secp256k1_order();
    let (mut with_sign_byte, mut without) = (0, 0);
    for i in 0u32..1000 {
        let key = PrivateKey::from_bytes(&sha256(&i.to_be_bytes())).unwrap();
        let low = key
            .sign(&sha256(&[i.to_le_bytes(), [7; 4]].concat()))
            .unwrap();
        let s = BigNumber::from_bytes_be(low.s());
        let mut high_s = [0u8; 32];
        high_s.copy_from_slice(&n.sub(&s).to_bytes_be(32));
        let high = Signature::new(*low.r(), high_s);
        assert!(!high.is_low_s());
        for sig in [&low, &high] {
            let der = sig.to_der();
            if der[3] == 33 {
                with_sign_byte += 1;
            } else {
                without += 1;
            }
            let read = Signature::from_der(&der).unwrap();
            assert_eq!(read, sig.to_low_s(), "{i}");
            assert_eq!(read.to_der(), der, "{i}");
            let checksig = TransactionSignature::new(sig.clone(), 0x41).to_checksig_format();
            let read = TransactionSignature::from_checksig_format(&checksig).unwrap();
            assert_eq!(read.signature(), &sig.to_low_s(), "{i}");
            assert_eq!(read.to_checksig_format(), checksig, "{i}");
        }
    }
    assert!(with_sign_byte > 0 && without > 0);
}

fn fold_vector() -> Value {
    serde_json::from_str(include_str!("vectors/script_signature_der_842.json")).unwrap()
}

/// `Signature::to_der` writes a zero S as the reference's `toDER` does, `02 00`
/// (`Signature.ts:201-250`: the S loop strips a zero no high bit follows), and a
/// zero R as `02 01 00` (`rmPadding` keeps a lone zero); `from_der` reads each
/// back as the reference's `fromDER` does, a zero S as zero and a lone-zero R
/// refused (`Invalid R-value in signature DER`), against the fold's recording
/// (`vectors/script_signature_der_842.json`, `to_der`). Until the fold a zero
/// S was written `02 01 00`, which the strict reader refuses: the round trip
/// broke.
#[test]
fn a_zero_s_is_written_as_the_reference_writes_it_and_reads_back_842() {
    let vector = fold_vector();
    let mut five = [0u8; 32];
    five[31] = 5;
    let cells = vector["to_der"].as_array().unwrap();
    assert_eq!(cells.len(), 3);
    for case in cells {
        let sig = match case["name"].as_str().unwrap() {
            "r_zero" => Signature::new([0; 32], five),
            "s_zero" => Signature::new(five, [0; 32]),
            "both_zero" => Signature::new([0; 32], [0; 32]),
            other => panic!("{other}"),
        };
        let der = sig.to_der();
        assert_eq!(hex::encode(&der), case["der"].as_str().unwrap(), "{case}");
        assert_eq!(from_der(&der), case["from_der"].as_str().unwrap(), "{case}");
    }
    // The zero S round trip, whole.
    let read = Signature::from_der(&Signature::new(five, [0; 32]).to_der()).unwrap();
    assert_eq!(read, Signature::new(five, [0; 32]));
}

/// A length byte of exactly `0x7f` (the last short form) and `0x80` (the first
/// long form) at the sequence, at R and at S, read as the reference's
/// `getLength` reads it (`Signature.ts:45-52`), against the fold's recording
/// (`der_lengths`): `0x80` refused in `Invalid DER entity length` at each, `0x7f`
/// read as a length (refused by the check after it in that check's words). The
/// 129-byte DER whose sequence length is `0x7f` is read by the reference with R
/// of 61 bytes and S of 62, the stated cell here (`Integer component too
/// large`); the reader's own acceptance of it is the unit test
/// `signature_der_tests.rs`' `the_length_edges_are_read_as_the_reference_reads_them_842`.
#[test]
fn a_length_byte_at_0x7f_and_0x80_is_read_as_the_reference_reads_it_842() {
    let vector = fold_vector();
    let cells = vector["der_lengths"].as_array().unwrap();
    assert_eq!(cells.len(), 7);
    for case in cells {
        let der = hex::decode(case["der"].as_str().unwrap()).unwrap();
        let recorded = case["from_der"].as_str().unwrap();
        if case["name"] == "sequence_7f_129_bytes" {
            assert!(recorded.starts_with("ok "), "{case}");
            assert_eq!(from_der(&der), TOO_LARGE, "{case}");
        } else {
            assert_eq!(from_der(&der), recorded, "{case}");
        }
    }
}
