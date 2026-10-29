//! #458: Node 22's fatal UTF-8 and ReaderUint8Array's short-read words.
//! Recorded with the #338 processor helper against ts-stack@edf6e03.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::primitives::Reader;
use bsv_rs::wallet::wire::{
    WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver, WireReader, WireWriter,
};
use bsv_rs::wallet::{ListCertificatesArgs, WalletCertificate};
use bsv_rs::Error;
use fixtures::wallet::Stub;
use serde_json::{json, Value};

const UTF8_WORDS: &str = "The encoded data was not valid for encoding utf-8";
const READ_WORDS: &str = "ReaderUint8Array read exceeds available data";
const PRECISION_WORDS: &str = "number too large to retain precision - use readVarIntBn";

fn short_read() -> Error {
    Error::WalletError(READ_WORDS.into())
}

fn recorded(name: &str) -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/originator_338.json")).unwrap();
    let cases = vector["processor"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
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
    for length in [4, (1u64 << 32) + 3, (1u64 << 53) - 1] {
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

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/wallet_wire/originator_338.json")).unwrap()
}

type LengthRead = for<'a> fn(&mut WireReader<'a>) -> Result<(), Error>;

async fn assert_length_case(name: &str, length: u64, words: &str) {
    let mut bytes = WireWriter::new();
    bytes.write_var_int(length).write_bytes(b"abc");
    let readers: [LengthRead; 3] = [
        |reader| reader.read_string().map(drop),
        |reader| reader.read_sign_action_spend().map(drop),
        |reader| reader.read_identity_certifier().map(drop),
    ];
    for read in readers {
        let mut reader = WireReader::new(bytes.as_bytes());
        assert_eq!(read(&mut reader), Err(Error::WalletError(words.into())));
        assert_eq!(reader.position(), 9, "payload must not be consumed");
    }
    if length != u64::MAX {
        for read in [
            (|reader: &mut WireReader<'_>| reader.read_optional_string().map(drop)) as LengthRead,
            |reader: &mut WireReader<'_>| reader.read_optional_bytes().map(drop),
        ] {
            let mut reader = WireReader::new(bytes.as_bytes());
            assert_eq!(read(&mut reader), Err(Error::WalletError(words.into())));
            assert_eq!(reader.position(), 9);
        }
    }
    if length >= 1 << 53 {
        let counts: [LengthRead; 5] = [
            |reader| reader.read_sign_action_spends().map(drop),
            |reader| reader.read_string_array().map(drop),
            |reader| reader.read_string_map().map(drop),
            |reader| reader.read_optional_string_map().map(drop),
            |reader| reader.read_send_with_result_array().map(drop),
        ];
        for (index, read) in counts.into_iter().enumerate() {
            if length == u64::MAX && index != 0 {
                continue;
            }
            let mut reader = WireReader::new(bytes.as_bytes());
            assert_eq!(read(&mut reader), Err(Error::WalletError(words.into())));
            assert_eq!(reader.position(), 9);
        }
    }
    let mut request = WireWriter::new();
    request
        .write_u8(WalletCall::CreateHmac.as_u8())
        .write_u8(0)
        .write_u8(0)
        .write_bytes(bytes.as_bytes());
    let case = recorded(&format!("protocol-length-{name}"));
    assert_eq!(hex::encode(request.as_bytes()), case["request_hex"]);
    assert_eq!(case["code"], 1);
    assert_eq!(case["message"], words);
    assert_eq!(case["observed"], json!([]));
    let response = assert_refusal(request.as_bytes(), words).await;
    assert_eq!(hex::encode(response), case["response_hex"]);

    let vector = vector();
    assert_eq!(vector["length_reads"].as_array().unwrap().len(), 12);
    for signed in [false, true] {
        if signed && length == u64::MAX {
            continue;
        }
        let direct = vector["length_reads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name && case["signed"] == signed)
            .unwrap();
        assert_eq!(direct["input_hex"], hex::encode(bytes.as_bytes()));
        assert_eq!(direct["message"], words);
        assert_eq!(direct["position"], 9);
        assert_eq!(
            direct["stage"],
            if length >= 1 << 53 { "varint" } else { "bytes" }
        );
    }
}

#[tokio::test]
async fn wire_length_2pow53_refuses_precision_before_read() {
    assert_length_case("2pow53", 1 << 53, PRECISION_WORDS).await;
}

#[tokio::test]
async fn wire_length_2pow53_plus_one_refuses_precision_before_read() {
    assert_length_case("2pow53-plus-1", (1 << 53) + 1, PRECISION_WORDS).await;
}

#[tokio::test]
async fn wire_length_u64_max_minus_one_refuses_precision_before_read() {
    assert_length_case("u64-max-minus-1", u64::MAX - 1, PRECISION_WORDS).await;
}

#[tokio::test]
async fn wire_length_u64_max_unsigned_refuses_precision_before_read() {
    assert_length_case("u64-max", u64::MAX, PRECISION_WORDS).await;
}

#[tokio::test]
async fn wire_length_max_safe_integer_still_uses_reader_words() {
    assert_length_case("2pow53-minus-1", (1 << 53) - 1, READ_WORDS).await;
}

#[tokio::test]
async fn wire_length_above_u32_still_uses_reader_words() {
    assert_length_case("2pow32-plus-3", (1 << 32) + 3, READ_WORDS).await;
}

#[test]
fn wire_length_signed_minus_one_keeps_reader_words_and_optional_absence() {
    let mut bytes = WireWriter::new();
    bytes.write_var_int(u64::MAX).write_bytes(b"abc");
    let mut reader = WireReader::new(bytes.as_bytes());
    let signed = reader.read_signed_var_int().unwrap();
    assert_eq!(signed, -1);
    // Rust's byte reader takes usize. A negative signed length cannot be
    // represented; the non-fitting length is refused by its bounds check.
    let length = usize::try_from(signed).unwrap_or(usize::MAX);
    assert_eq!(reader.read_bytes(length), Err(short_read()));
    assert_eq!(reader.position(), 9);
    let vector = vector();
    let case = vector["length_reads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "u64-max" && case["signed"] == true)
        .unwrap();
    assert_eq!(case["value"], -1);
    assert_eq!(case["stage"], "bytes");
    assert_eq!(case["message"], READ_WORDS);
    assert_eq!(case["position"], reader.position());
    let mut reader = WireReader::new(bytes.as_bytes());
    assert_eq!(reader.read_optional_bytes().unwrap(), None);
    assert_eq!(reader.position(), 9);
    assert_eq!(
        WireReader::new(bytes.as_bytes())
            .read_optional_string()
            .unwrap(),
        None
    );
}

#[test]
fn wire_string_array_item_lengths_are_unsigned() {
    let mut bytes = WireWriter::new();
    bytes.write_var_int(1).write_var_int(u64::MAX);
    let mut reader = WireReader::new(bytes.as_bytes());
    assert_eq!(
        reader.read_string_array(),
        Err(Error::WalletError(PRECISION_WORDS.into()))
    );
    assert_eq!(reader.position(), 10);
}

#[test]
fn wire_action_output_basket_length_keeps_signed_absence() {
    // WalletWireTransceiver.ts:533-534 reads this length signed and skips
    // the bytes at -1. WalletActionOutput represents the absent basket as "".
    let mut bytes = WireWriter::new();
    bytes
        .write_var_int(0)
        .write_var_int(0)
        .write_optional_bytes(None)
        .write_optional_bool(Some(true))
        .write_string("")
        .write_optional_string(None)
        .write_var_int(u64::MAX)
        .write_optional_string(None);
    let mut reader = WireReader::new(bytes.as_bytes());
    assert_eq!(reader.read_wallet_action_output().unwrap().basket, "");
    assert!(reader.is_empty());
}

struct Reply(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Reply {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

async fn assert_response_length_site(site: &str) {
    let vector = vector();
    for case in vector["response_lengths"].as_array().unwrap() {
        if case["site"] != site {
            continue;
        }
        let length = vector["length_reads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|read| read["name"] == case["name"])
            .unwrap()["length"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        if site == "certificate-verifier" && length < 1 << 53 {
            continue;
        }
        let mut response = WireWriter::new();
        if site == "certificate-verifier" {
            response.write_u8(0).write_var_int(1);
            let certificate = WalletCertificate {
                certificate_type: bsv_rs::primitives::to_base64(&[0; 32]),
                serial_number: bsv_rs::primitives::to_base64(&[0; 32]),
                subject: bsv_rs::primitives::PrivateKey::from_hex(&format!("{:064x}", 1))
                    .unwrap()
                    .public_key()
                    .to_hex(),
                certifier: bsv_rs::primitives::PrivateKey::from_hex(&format!("{:064x}", 2))
                    .unwrap()
                    .public_key()
                    .to_hex(),
                revocation_outpoint: format!("{}.0", "00".repeat(32)),
                fields: Default::default(),
                signature: String::new(),
            };
            let mut encoded = WireWriter::new();
            encoded.write_wallet_certificate(&certificate).unwrap();
            response
                .write_var_int(encoded.as_bytes().len() as u64)
                .write_bytes(encoded.as_bytes())
                .write_u8(0);
        } else {
            response.write_u8(1);
            if site == "error-stack" {
                response.write_string("");
            }
        }
        response.write_var_int(length).write_bytes(b"abc");
        assert_eq!(hex::encode(response.as_bytes()), case["response_hex"]);
        let client = WalletWireTransceiver::new(Reply(response.into_bytes()));
        let result = if site == "certificate-verifier" {
            client
                .list_certificates(
                    ListCertificatesArgs {
                        certifiers: vec![],
                        types: vec![],
                        limit: None,
                        offset: None,
                        privileged: None,
                        privileged_reason: None,
                    },
                    Some("fixtures.invalid"),
                )
                .await
                .map(drop)
        } else {
            client.get_version(None).await.map(drop)
        };
        assert_eq!(
            result,
            Err(Error::WalletError(case["message"].as_str().unwrap().into())),
            "{} {site}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn wire_error_message_lengths_use_reference_precision_words() {
    assert_response_length_site("error-message").await;
}

#[tokio::test]
async fn wire_error_stack_lengths_use_reference_precision_words() {
    assert_response_length_site("error-stack").await;
}

#[tokio::test]
async fn wire_certificate_verifier_lengths_use_reference_precision_words() {
    assert_response_length_site("certificate-verifier").await;
}

async fn assert_page_total_site(site: &str) {
    let vector = vector();
    let cases: Vec<_> = vector["page_totals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["site"] == site)
        .collect();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let total = case["total"].as_str().unwrap().parse::<u64>().unwrap();
        let words = case["message"].as_str().unwrap();
        if total >= 1 << 53 {
            assert_eq!(words, PRECISION_WORDS);
        }
        let mut response = WireWriter::new();
        response.write_u8(0).write_var_int(total);
        assert_eq!(hex::encode(response.as_bytes()), case["response_hex"]);
        let client = WalletWireTransceiver::new(Reply(response.into_bytes()));
        let result = if site == "listActions" {
            client
                .list_actions(serde_json::from_value(json!({"labels": []})).unwrap(), None)
                .await
                .map(drop)
        } else {
            client
                .list_outputs(
                    serde_json::from_value(json!({"basket": "fixtures"})).unwrap(),
                    None,
                )
                .await
                .map(drop)
        };
        assert_eq!(
            result,
            Err(Error::WalletError(words.into())),
            "{site} {}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn list_actions_totals_use_reference_precision_words() {
    assert_page_total_site("listActions").await;
}

#[tokio::test]
async fn list_outputs_totals_use_reference_precision_words() {
    assert_page_total_site("listOutputs").await;
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
