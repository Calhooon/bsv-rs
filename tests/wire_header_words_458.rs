//! #458: Node 22's fatal UTF-8 and ReaderUint8Array's short-read words.
//! Recorded with the #338 processor helper against ts-stack@edf6e03.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::primitives::Reader;
use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireReader, WireWriter};
use bsv_rs::Error;
use fixtures::wallet::Stub;
use serde_json::{json, Value};

const UTF8_WORDS: &str = "The encoded data was not valid for encoding utf-8";
const READ_WORDS: &str = "ReaderUint8Array read exceeds available data";

fn short_read() -> Error {
    Error::WalletError(READ_WORDS.into())
}

fn recorded(name: &str) -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/originator_338.json")).unwrap();
    let cases = vector["processor"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    cases
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
        .clone()
}

async fn assert_refusal(request: &[u8], words: &str) -> Vec<u8> {
    let wallet = Stub::new(json!({"version": "v-1.0.0"}));
    let observed = wallet.observed.clone();
    let response = WalletWireProcessor::new(wallet)
        .process_message(request)
        .await
        .unwrap();
    let mut reader = WireReader::new(&response);
    assert_eq!(reader.read_u8().unwrap(), 1, "{request:02x?}");
    assert_eq!(reader.read_string().unwrap(), words, "{request:02x?}");
    assert_eq!(reader.read_var_int().unwrap(), 0, "empty stack");
    assert!(reader.is_empty());
    assert!(
        observed.lock().unwrap().is_none(),
        "wallet must not be called"
    );
    response
}

async fn assert_recorded(name: &str, length: u8, bytes: &[u8], words: &str) {
    let case = recorded(name);
    let mut request = WireWriter::new();
    request
        .write_u8(WalletCall::GetVersion.as_u8())
        .write_u8(length)
        .write_bytes(bytes);
    assert_eq!(hex::encode(request.as_bytes()), case["request_hex"]);
    assert_eq!(case["code"], 1);
    assert_eq!(case["message"], words);
    assert_eq!(case["observed"], json!([]));
    let response = assert_refusal(request.as_bytes(), words).await;
    assert_eq!(hex::encode(response), case["response_hex"]);
}

#[tokio::test]
async fn processor_bad_utf8_originator_uses_reference_words() {
    assert_recorded("invalid-utf8", 1, &[0xff], UTF8_WORDS).await;
}

#[tokio::test]
async fn processor_truncated_originator_uses_reference_words() {
    assert_recorded("length-250-truncated", 250, b"a", READ_WORDS).await;
    for length in 1..=250u8 {
        let mut request = WireWriter::new();
        request
            .write_u8(WalletCall::GetVersion.as_u8())
            .write_u8(length)
            .write_bytes(&vec![b'a'; usize::from(length) - 1]);
        assert_refusal(request.as_bytes(), READ_WORDS).await;
    }
}

#[tokio::test]
async fn processor_short_headers_and_parameters_use_reference_reader_words() {
    // The call byte, originator length byte, and all CompactSize payload widths
    // in getHeaderForHeight's height, after a complete empty-originator header.
    for request in [
        vec![],
        vec![WalletCall::GetVersion.as_u8()],
        vec![WalletCall::GetHeaderForHeight.as_u8(), 0],
        vec![WalletCall::GetHeaderForHeight.as_u8(), 0, 0xfd, 1],
        vec![WalletCall::GetHeaderForHeight.as_u8(), 0, 0xfe, 1, 0, 0],
        vec![
            WalletCall::GetHeaderForHeight.as_u8(),
            0,
            0xff,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ] {
        assert_refusal(&request, READ_WORDS).await;
    }
}

#[test]
fn wire_reader_short_reads_use_reference_words() {
    for available in 0..8 {
        let bytes = vec![0; available];
        let mut reader = WireReader::new(&bytes);
        assert_eq!(reader.read_u64_le(), Err(short_read()));
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.read_bytes(8), Err(short_read()));
        if available < 4 {
            assert_eq!(reader.read_u32_le(), Err(short_read()));
        }
        if available < 2 {
            assert_eq!(reader.read_u16_le(), Err(short_read()));
        }
        if available == 0 {
            assert_eq!(reader.read_u8(), Err(short_read()));
            assert_eq!(reader.read_i8(), Err(short_read()));
        }
    }
    // Empty input and truncated payloads for each CompactSize prefix, through
    // the unsigned, signed, optional and length-prefixed wire readers.
    for (prefix, width) in [(0xfd, 2), (0xfe, 4), (0xff, 8)] {
        for available in 0..=width {
            let mut bytes = vec![prefix];
            bytes.resize(available, 0);
            assert_eq!(WireReader::new(&bytes).read_var_int(), Err(short_read()));
            assert_eq!(
                WireReader::new(&bytes).read_signed_var_int(),
                Err(short_read())
            );
            assert_eq!(
                WireReader::new(&bytes).read_optional_var_int(),
                Err(short_read())
            );
            assert_eq!(
                WireReader::new(&bytes)
                    .read_identity_certificate()
                    .map(drop),
                Err(short_read())
            );
        }
    }
}

#[test]
fn wire_length_checks_use_reference_reader_words() {
    for length in [4, (1u64 << 32) + 3, u64::MAX - 1] {
        let mut bytes = WireWriter::new();
        bytes.write_var_int(length).write_bytes(b"abc");
        assert_eq!(
            WireReader::new(bytes.as_bytes()).read_string(),
            Err(short_read())
        );
        assert_eq!(
            WireReader::new(bytes.as_bytes()).read_optional_string(),
            Err(short_read())
        );
        assert_eq!(
            WireReader::new(bytes.as_bytes()).read_optional_bytes(),
            Err(short_read())
        );
    }
}

#[test]
fn primitive_reader_keeps_underflow_details() {
    assert_eq!(
        Reader::new(b"a").read_bytes(250),
        Err(Error::ReaderUnderflow {
            needed: 250,
            available: 1
        })
    );
}

#[test]
fn wire_reader_keeps_errors_other_than_underflow() {
    let bytes = [0xfd, 1, 0];
    assert_eq!(
        WireReader::new(&bytes).read_var_int(),
        Reader::new(&bytes).read_var_int()
    );
    assert!(WireReader::new(&bytes).read_var_int().is_err());
}
