//! The wallet wire's optional and signed varints in the reference's form (#149).
//!
//! BRC-100 writes each of these fields as a `VarInt` with `-1` for absence
//! (`5119a9b` `wallet/0100.md:1655-1656` lockTime and version, `:1670` and
//! `:1750` the two sequence numbers, `:1808-1809`, `:2281-2282`, `:2364-2365`,
//! `:2405-2406` the limits and offsets, `:1940` listOutputs' offset a "Signed
//! integer") and says nothing of a negative's bytes: its `VarInt`
//! (`:1629-1637`) is unsigned. The TypeScript writer gives the bytes
//! (`ts-sdk@9e3ede6` `utils.ts:546-549`,
//! `writeVarIntNum`: `10` is `0x0A`, `-1` goes through `varIntBn` at `:586`,
//! `-1 + 2^64`, nine `0xFF`), and Go writes the same (`go-sdk@2ca481c`
//! `util/writer.go:66-71`, `WriteNegativeOne`). This crate wrote ZigZag:
//! `Some(10)` as `0x14`, absence as `0x01`, and read TS's `10` as `5`.
//!
//! Each field below: absence is nine `0xFF`, `10` is `0x0A`, the bound
//! (`u32::MAX`, the field's type and Go's `*uint32`) is `FE FF FF FF FF`.
//! The readers this crate has (signAction's spend) take TS's bytes and refuse
//! one above the bound with the field named, as `ReadOptionalUint32` does
//! (`util/reader.go:210-222`). The processor reads no argument of createAction
//! or of the list calls (its handlers refuse before reading), so those fields
//! have a writer here and no reader.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::collections::HashMap;
use std::sync::Mutex;

const ABSENT: [u8; 9] = [0xFF; 9];
const TEN: [u8; 1] = [0x0A];
const U32_MAX: [u8; 5] = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF];

/// Keeps the frame the transceiver sends and answers nothing.
#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

#[async_trait::async_trait]
impl WalletWire for Capture {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        *self.0.lock().unwrap() = message.to_vec();
        Err(Error::WalletError("captured".to_string()))
    }
}

#[derive(Clone, Copy, Debug)]
enum Field {
    CreateActionSequenceNumber,
    CreateActionLockTime,
    CreateActionVersion,
    SignActionSequenceNumber,
    ListActionsLimit,
    ListActionsOffset,
    ListOutputsLimit,
    ListOutputsOffset,
    ListCertificatesLimit,
    ListCertificatesOffset,
    DiscoverByIdentityKeyLimit,
    DiscoverByIdentityKeyOffset,
    DiscoverByAttributesLimit,
    DiscoverByAttributesOffset,
}

use Field::*;

const U32_FIELDS: [Field; 13] = [
    CreateActionSequenceNumber,
    CreateActionLockTime,
    CreateActionVersion,
    SignActionSequenceNumber,
    ListActionsLimit,
    ListActionsOffset,
    ListOutputsLimit,
    ListCertificatesLimit,
    ListCertificatesOffset,
    DiscoverByIdentityKeyLimit,
    DiscoverByIdentityKeyOffset,
    DiscoverByAttributesLimit,
    DiscoverByAttributesOffset,
];

/// The frame the transceiver writes with `value` in `field`, every other
/// optional field absent; the transceiver's refusal if it refuses.
async fn frame(field: Field, value: Option<i64>) -> Result<Vec<u8>, Error> {
    let u = || value.map(|v| u32::try_from(v).unwrap());
    let only = |f: Field| if f as u8 == field as u8 { u() } else { None };
    let t = WalletWireTransceiver::new(Capture::default());
    let o = "app.example";
    let err = match field {
        CreateActionSequenceNumber | CreateActionLockTime | CreateActionVersion => {
            let input = CreateActionInput {
                outpoint: Outpoint::new([7u8; 32], 1),
                input_description: "in".to_string(),
                unlocking_script: Some(vec![0x51]),
                unlocking_script_length: None,
                sequence_number: only(CreateActionSequenceNumber),
            };
            let args = CreateActionArgs {
                description: "a payment".to_string(),
                input_beef: None,
                inputs: Some(vec![input]),
                outputs: None,
                lock_time: only(CreateActionLockTime),
                version: only(CreateActionVersion),
                labels: None,
                options: None,
            };
            t.create_action(args, o).await.unwrap_err()
        }
        SignActionSequenceNumber => {
            let spend = SignActionSpend {
                unlocking_script: vec![0x51],
                sequence_number: u(),
            };
            let args = SignActionArgs {
                spends: HashMap::from([(0, spend)]),
                reference: "cmVm".to_string(),
                options: None,
            };
            t.sign_action(args, o).await.unwrap_err()
        }
        ListActionsLimit | ListActionsOffset => {
            let args = ListActionsArgs {
                labels: vec![],
                label_query_mode: None,
                include_labels: None,
                include_inputs: None,
                include_input_source_locking_scripts: None,
                include_input_unlocking_scripts: None,
                include_outputs: None,
                include_output_locking_scripts: None,
                limit: only(ListActionsLimit),
                offset: only(ListActionsOffset),
                seek_permission: None,
            };
            t.list_actions(args, o).await.unwrap_err()
        }
        ListOutputsLimit | ListOutputsOffset => {
            let args = ListOutputsArgs {
                basket: "default".to_string(),
                tags: None,
                tag_query_mode: None,
                include: None,
                include_custom_instructions: None,
                include_tags: None,
                include_labels: None,
                limit: only(ListOutputsLimit),
                offset: match field {
                    ListOutputsOffset => value.map(|v| i32::try_from(v).unwrap()),
                    _ => None,
                },
                seek_permission: None,
            };
            t.list_outputs(args, o).await.unwrap_err()
        }
        ListCertificatesLimit | ListCertificatesOffset => {
            let args = ListCertificatesArgs {
                certifiers: vec![],
                types: vec![],
                limit: only(ListCertificatesLimit),
                offset: only(ListCertificatesOffset),
                privileged: None,
                privileged_reason: None,
            };
            t.list_certificates(args, o).await.unwrap_err()
        }
        DiscoverByIdentityKeyLimit | DiscoverByIdentityKeyOffset => {
            let key = PrivateKey::from_bytes(&[1u8; 32]).unwrap().public_key();
            let args = DiscoverByIdentityKeyArgs {
                identity_key: key.to_hex(),
                limit: only(DiscoverByIdentityKeyLimit),
                offset: only(DiscoverByIdentityKeyOffset),
                seek_permission: None,
            };
            t.discover_by_identity_key(args, o).await.unwrap_err()
        }
        DiscoverByAttributesLimit | DiscoverByAttributesOffset => {
            let args = DiscoverByAttributesArgs {
                attributes: HashMap::from([("name".to_string(), "Alice".to_string())]),
                limit: only(DiscoverByAttributesLimit),
                offset: only(DiscoverByAttributesOffset),
                seek_permission: None,
            };
            t.discover_by_attributes(args, o).await.unwrap_err()
        }
    };
    let sent = t.wire().0.lock().unwrap().clone();
    if err != Error::WalletError("captured".to_string()) {
        assert!(sent.is_empty(), "{field:?}: a refusal sends nothing");
        return Err(err);
    }
    Ok(sent)
}

/// The bytes `field` takes for `value`: the field sits where the absent frame
/// and the `Some(0)` frame part, and everything around it is the absent
/// frame's, nine `0xFF` replaced.
async fn bytes_of(field: Field, value: Option<i64>) -> Vec<u8> {
    let absent = frame(field, None).await.unwrap();
    let zero = frame(field, Some(0)).await.unwrap();
    let at = absent.iter().zip(&zero).position(|(a, z)| a != z).unwrap();
    assert_eq!(
        absent[at..at + 9],
        ABSENT,
        "{field:?}: absence is nine 0xFF"
    );
    let sent = frame(field, value).await.unwrap();
    let tail = &absent[at + 9..];
    assert_eq!(sent[..at], absent[..at], "{field:?}: the bytes before");
    assert!(sent.ends_with(tail), "{field:?}: the bytes after");
    sent[at..sent.len() - tail.len()].to_vec()
}

// ============================================================================
// The writers: transceiver.rs and encoding.rs
// ============================================================================

#[tokio::test]
async fn an_absent_optional_varint_leaves_as_nine_ff_at_every_field() {
    for field in U32_FIELDS.into_iter().chain([ListOutputsOffset]) {
        assert_eq!(bytes_of(field, None).await, ABSENT, "{field:?}");
    }
}

/// TS writes `10` as `0x0A` at each of these sites (`WalletWireTransceiver.ts`
/// `:150-155` createAction's sequenceNumber, `:218-229` lockTime and version,
/// `:419-423` signAction's, `:574-583` listActions' limit and offset, `:961-969`
/// listOutputs', `:1656-1664` listCertificates', and the two discovers').
#[tokio::test]
async fn a_present_ten_leaves_as_the_reference_byte_0x0a_at_every_field() {
    for field in U32_FIELDS.into_iter().chain([ListOutputsOffset]) {
        assert_eq!(bytes_of(field, Some(10)).await, TEN, "{field:?}");
    }
}

#[tokio::test]
async fn a_u32_field_at_its_bound_leaves_as_the_plain_five_byte_varint() {
    for field in U32_FIELDS {
        let bound = Some(i64::from(u32::MAX));
        assert_eq!(bytes_of(field, bound).await, U32_MAX, "{field:?}");
    }
}

/// listOutputs' offset is an `i32` here (BRC-100 `:911`, `:1940`: negative
/// counts from the newest); `-1`, the newest, has absence's bytes, as TS's
/// writer gives it, and TS's processor reads it as absent (`WalletWireProcessor.ts`
/// `:966-979`, any negative). Below `-1` there is no form any reader keeps.
#[tokio::test]
async fn a_list_outputs_offset_below_minus_one_is_refused_naming_the_field() {
    let max = bytes_of(ListOutputsOffset, Some(i64::from(i32::MAX))).await;
    assert_eq!(max, [0xFE, 0xFF, 0xFF, 0xFF, 0x7F]);
    assert_eq!(bytes_of(ListOutputsOffset, Some(-1)).await, ABSENT);
    for below in [-2, i64::from(i32::MIN)] {
        let err = frame(ListOutputsOffset, Some(below)).await.unwrap_err();
        let text = format!("invalid offset: expected at least -1, got {below}");
        assert_eq!(err, Error::WalletError(text));
    }
}

#[test]
fn write_signed_var_int_writes_the_plain_varint_and_refuses_below_minus_one() {
    let mut writer = WireWriter::new();
    writer.write_signed_var_int("f", 10).unwrap();
    writer.write_signed_var_int("f", -1).unwrap();
    writer.write_signed_var_int("f", 253).unwrap();
    let expected = [&TEN[..], &ABSENT, &[0xFD, 0xFD, 0x00]].concat();
    assert_eq!(writer.as_bytes(), &expected[..]);
    let err = WireWriter::new()
        .write_signed_var_int("f", -2)
        .err()
        .unwrap();
    let text = "invalid f: expected at least -1, got -2".to_string();
    assert_eq!(err, Error::WalletError(text));
}

// ============================================================================
// The readers: encoding.rs (signAction's spend) and the optional reader
// ============================================================================

/// `[unlockingScript: VarInt length + bytes][sequenceNumber: VarInt]`, the
/// spend as TS writes it (`WalletWireTransceiver.ts:414-423`; BRC-100 `:1749-1750`).
fn ts_spend(sequence_number: &[u8]) -> Vec<u8> {
    [&[0x01, 0x51][..], sequence_number].concat()
}

fn read_spend(bytes: &[u8]) -> Result<Option<u32>, Error> {
    let mut reader = WireReader::new(bytes);
    let spend = reader.read_sign_action_spend()?;
    assert!(reader.is_empty());
    Ok(spend.sequence_number)
}

#[test]
fn a_sign_action_spend_reads_the_reference_bytes_of_ten_as_ten() {
    assert_eq!(read_spend(&ts_spend(&TEN)).unwrap(), Some(10));
    assert_eq!(read_spend(&ts_spend(&[0x05])).unwrap(), Some(5));
}

#[test]
fn a_sign_action_spend_reads_nine_ff_as_absent_and_the_bound_exactly() {
    assert_eq!(read_spend(&ts_spend(&ABSENT)).unwrap(), None);
    assert_eq!(read_spend(&ts_spend(&U32_MAX)).unwrap(), Some(u32::MAX));
}

#[test]
fn a_sign_action_spend_sequence_number_above_the_bound_is_refused_naming_it() {
    let over = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let err = read_spend(&ts_spend(&over)).unwrap_err();
    let text = "invalid sequenceNumber: expected at most 4294967295, got 4294967296";
    assert_eq!(err, Error::WalletError(text.to_string()));
}

#[test]
fn a_sign_action_spend_of_ten_is_written_as_the_reference_bytes() {
    let spend = SignActionSpend {
        unlocking_script: vec![0x51],
        sequence_number: Some(10),
    };
    let mut writer = WireWriter::new();
    writer.write_sign_action_spend(&spend);
    assert_eq!(writer.as_bytes(), &ts_spend(&TEN)[..]);
}

#[test]
fn a_sign_action_spend_written_here_reads_back_at_absence_ten_and_the_bound() {
    for sequence_number in [None, Some(0), Some(10), Some(u32::MAX)] {
        let spend = SignActionSpend {
            unlocking_script: vec![0x51],
            sequence_number,
        };
        let mut writer = WireWriter::new();
        writer.write_sign_action_spend(&spend);
        assert_eq!(read_spend(writer.as_bytes()).unwrap(), sequence_number);
    }
}

#[test]
fn the_optional_and_signed_readers_take_the_plain_varint() {
    let bytes = [&TEN[..], &ABSENT, &[0x05], &ABSENT].concat();
    let mut reader = WireReader::new(&bytes);
    assert_eq!(reader.read_optional_var_int().unwrap(), Some(10));
    assert_eq!(reader.read_optional_var_int().unwrap(), None);
    assert_eq!(reader.read_signed_var_int().unwrap(), 5);
    assert_eq!(reader.read_signed_var_int().unwrap(), -1);

    // Above i64::MAX and not nine 0xFF: TS's two's complement, no form here.
    let neg_two = [0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let err = WireReader::new(&neg_two).read_signed_var_int().unwrap_err();
    let text = "invalid signed varint: expected at most 9223372036854775807 or -1, \
                got 18446744073709551614";
    assert_eq!(err, Error::WalletError(text.to_string()));
}

// ============================================================================
// The shared vectors (go-sdk's testdata, read in place): the present case
// ============================================================================

/// The last `n` bytes of a request vector's `wire` hex.
fn vector_tail(name: &str, n: usize) -> Vec<u8> {
    let path = format!(
        "{}/tests/vectors/wallet_wire/{name}-simple-args.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wire = hex::decode(vector["wire"].as_str().unwrap()).unwrap();
    wire[wire.len() - n..].to_vec()
}

/// Go writes `limit` and `offset` last but for the flags after them
/// (`wallet/serializer/list_actions.go:47-48` and the other four): its `10`
/// is `0x0A`, its `0` is `0x00`, its absent offset nine `0xFF`, read so here.
#[test]
fn the_shared_vectors_present_limits_and_offsets_read_as_written() {
    for (name, n, limit, offset) in [
        ("listActions", 11, 10, None),
        ("listOutputs", 11, 10, None),
        ("discoverByIdentityKey", 3, 10, Some(0)),
        ("discoverByAttributes", 3, 5, Some(0)),
        ("listCertificates", 20, 5, Some(0)),
    ] {
        let tail = vector_tail(name, n);
        let mut reader = WireReader::new(&tail);
        assert_eq!(
            reader.read_optional_var_int().unwrap(),
            Some(limit),
            "{name}"
        );
        assert_eq!(reader.read_optional_var_int().unwrap(), offset, "{name}");
    }
}
