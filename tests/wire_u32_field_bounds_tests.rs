//! The wallet wire's `u32` fields read at their bound (#122).
//!
//! Each field below is a `u32` by the transaction format (the sequence
//! numbers, the version, the lock time) or by BRC-100's
//! `PositiveIntegerOrZero`, at most `2^32 - 1` (`5119a9b` `wallet/0100.md:394-402`;
//! the height is `PositiveInteger`, `:410-418`). The frame's tables write each
//! as a VarInt. `u32::MAX` reads back; `u32::MAX + 1` is refused with the field
//! named, where the reader once cast it to 0; the words are the reference's
//! `#requireInteger`'s, the name its own per site (#255).

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::sync::Mutex;

const OVER: u64 = u32::MAX as u64 + 1;

/// The reference's `#requireInteger` words (`ts-stack@edf6e03`
/// `WalletWireTransceiver.ts:2018-2025`) with its name for the field (#255).
fn refusal(field: &str) -> Error {
    Error::WalletError(format!(
        "Invalid {}: expected an integer from 0 to 4294967295, received 4294967296",
        field
    ))
}

fn var_int(value: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_var_int(value);
    writer.into_bytes()
}

/// Replaces the writer's 5-byte varint for `u32::MAX`, found once in `frame`,
/// with the writer's 9-byte varint for `u32::MAX + 1`.
fn widen_past_u32(frame: &[u8]) -> Vec<u8> {
    let max = var_int(u32::MAX as u64);
    let at: Vec<_> = (0..=frame.len() - max.len())
        .filter(|&i| frame[i..i + max.len()] == max[..])
        .collect();
    assert_eq!(at.len(), 1, "the u32::MAX varint appears once");
    let mut out = frame[..at[0]].to_vec();
    out.extend_from_slice(&var_int(OVER));
    out.extend_from_slice(&frame[at[0] + max.len()..]);
    out
}

// ============================================================================
// encoding.rs: sequenceNumber (two), version, lockTime
// ============================================================================

/// signAction's spend: `sequenceNumber`, VarInt, `-1` for absent
/// (`wallet/0100.md:1750`).
#[test]
fn a_sign_action_spend_sequence_number_above_u32_max_is_refused_not_truncated() {
    let spend = SignActionSpend {
        unlocking_script: vec![0x51],
        sequence_number: Some(u32::MAX),
    };
    let mut writer = WireWriter::new();
    writer.write_sign_action_spend(&spend);
    let frame = writer.into_bytes();
    let read = WireReader::new(&frame).read_sign_action_spend().unwrap();
    assert_eq!(read.sequence_number, Some(u32::MAX));

    // [script: varint len + bytes][sequenceNumber: optional (signed) varint]
    let mut writer = WireWriter::new();
    writer.write_var_int(1);
    writer.write_bytes(&[0x51]);
    writer.write_optional_var_int(Some(OVER));
    let over = writer.into_bytes();
    let err = WireReader::new(&over).read_sign_action_spend().unwrap_err();
    assert_eq!(err, refusal("signAction spend sequenceNumber"));
}

fn action_input(sequence_number: u32) -> WalletActionInput {
    WalletActionInput {
        source_outpoint: Outpoint::new([7u8; 32], 1),
        source_satoshis: 1000,
        source_locking_script: None,
        unlocking_script: None,
        input_description: "in".to_string(),
        sequence_number,
    }
}

/// listActions' input object: `sequenceNumber`, VarInt
/// (`wallet/0100.md:1861`).
#[test]
fn an_action_input_sequence_number_above_u32_max_is_refused_not_truncated() {
    let mut writer = WireWriter::new();
    writer.write_wallet_action_input(&action_input(u32::MAX));
    let frame = writer.into_bytes();
    let read = WireReader::new(&frame).read_wallet_action_input().unwrap();
    assert_eq!(read.sequence_number, u32::MAX);

    let over = widen_past_u32(&frame);
    let err = WireReader::new(&over)
        .read_wallet_action_input()
        .unwrap_err();
    assert_eq!(err, refusal("listActions input sequenceNumber"));
}

fn action(version: u32, lock_time: u32) -> WalletAction {
    WalletAction {
        txid: [9u8; 32],
        satoshis: 1000,
        status: ActionStatus::Completed,
        is_outgoing: true,
        description: "action".to_string(),
        labels: None,
        version,
        lock_time,
        inputs: None,
        outputs: None,
    }
}

fn action_frame(action: &WalletAction) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_wallet_action(action);
    writer.into_bytes()
}

/// listActions' action object: `version`, VarInt
/// (`wallet/0100.md:1834`).
#[test]
fn an_action_version_above_u32_max_is_refused_not_truncated() {
    let frame = action_frame(&action(u32::MAX, 0));
    let read = WireReader::new(&frame).read_wallet_action().unwrap();
    assert_eq!((read.version, read.lock_time), (u32::MAX, 0));

    let over = widen_past_u32(&frame);
    let err = WireReader::new(&over).read_wallet_action().unwrap_err();
    assert_eq!(err, refusal("listActions version"));
}

/// listActions' action object: `lockTime`, VarInt
/// (`wallet/0100.md:1835`).
#[test]
fn an_action_lock_time_above_u32_max_is_refused_not_truncated() {
    let frame = action_frame(&action(1, u32::MAX));
    let read = WireReader::new(&frame).read_wallet_action().unwrap();
    assert_eq!((read.version, read.lock_time), (1, u32::MAX));

    let over = widen_past_u32(&frame);
    let err = WireReader::new(&over).read_wallet_action().unwrap_err();
    assert_eq!(err, refusal("listActions lockTime"));
}

// ============================================================================
// processor.rs: getHeaderForHeight's height
// ============================================================================

/// Answers `get_header_for_height` and records the height it was asked for;
/// every other method is unreachable from these tests.
#[derive(Default)]
struct HeightWallet {
    asked: Mutex<Option<u32>>,
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! height_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for HeightWallet {
            $(async fn $method(&self, _: $args, _: Option<&str>) -> bsv_rs::Result<$result> {
                unreachable!()
            })*

            async fn is_authenticated(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn wait_for_authentication(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn get_height(&self, _: Option<&str>) -> bsv_rs::Result<GetHeightResult> {
                unreachable!()
            }
            async fn get_header_for_height(
                &self,
                args: GetHeaderArgs,
                _: Option<&str>,
            ) -> bsv_rs::Result<GetHeaderResult> {
                *self.asked.lock().unwrap() = Some(args.height);
                Ok(GetHeaderResult {
                    header: "00".repeat(80),
                })
            }
            async fn get_network(&self, _: Option<&str>) -> bsv_rs::Result<GetNetworkResult> {
                unreachable!()
            }
            async fn get_version(&self, _: Option<&str>) -> bsv_rs::Result<GetVersionResult> {
                unreachable!()
            }
        }
    };
}

height_wallet! {
        (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
        (encrypt, EncryptArgs, EncryptResult),
        (decrypt, DecryptArgs, DecryptResult),
        (create_hmac, CreateHmacArgs, CreateHmacResult),
        (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
        (create_signature, CreateSignatureArgs, CreateSignatureResult),
        (verify_signature, VerifySignatureArgs, VerifySignatureResult),
        (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
        (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
        (create_action, CreateActionArgs, CreateActionResult),
        (sign_action, SignActionArgs, SignActionResult),
        (abort_action, AbortActionArgs, AbortActionResult),
        (list_actions, ListActionsArgs, ListActionsResult),
        (internalize_action, InternalizeActionArgs, InternalizeActionResult),
        (list_outputs, ListOutputsArgs, ListOutputsResult),
        (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
        (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
        (list_certificates, ListCertificatesArgs, ListCertificatesResult),
        (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
        (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
        (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
        (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
}

/// [call: u8][originator: u8 len + bytes][height: varint]
fn get_header_frame(height: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(WalletCall::GetHeaderForHeight.as_u8());
    writer.write_u8(0);
    writer.write_var_int(height);
    writer.into_bytes()
}

/// getHeaderForHeight's argument: `height`, VarInt
/// (`wallet/0100.md:2471`, `PositiveInteger` at `:1498`).
#[tokio::test]
async fn a_header_height_above_u32_max_is_refused_not_truncated() {
    let processor = WalletWireProcessor::new(HeightWallet::default());

    let answer = processor
        .process_message(&get_header_frame(u32::MAX as u64))
        .await
        .unwrap();
    assert_eq!(answer[0], 0, "success byte");
    assert_eq!(*processor.wallet().asked.lock().unwrap(), Some(u32::MAX));

    let answer = processor
        .process_message(&get_header_frame(OVER))
        .await
        .unwrap();
    let mut reader = WireReader::new(&answer);
    assert_eq!(reader.read_u8().unwrap(), 1, "unknownError");
    // The reference's words (`#requireInteger`, `WalletWireProcessor.ts:1670-1675`,
    // bsv-rs#216), bare as every frame's are (#202).
    assert_eq!(
        reader.read_string().unwrap(),
        format!("Invalid getHeaderForHeight height: expected an integer from 1 to 4294967295, received {OVER}")
    );
    assert_eq!(*processor.wallet().asked.lock().unwrap(), Some(u32::MAX));
}

// ============================================================================
// transceiver.rs: totalActions, totalOutputs, totalCertificates (two)
// ============================================================================

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

fn canned(total: u64, rest: &[u8]) -> WalletWireTransceiver<CannedWire> {
    let mut body = var_int(total);
    body.extend_from_slice(rest);
    WalletWireTransceiver::new(CannedWire { body })
}

/// A reader that reads as many entries as the total names: `u32::MAX` with no
/// entry after it passes the bound and stops at the read of the entry after it.
fn assert_read_past_total(err: Error) {
    assert_eq!(
        err,
        Error::WalletError("ReaderUint8Array read exceeds available data".into()),
        "the total accepted, the entry after it short: {err:?}"
    );
}

async fn list_actions(total: u64) -> bsv_rs::Result<ListActionsResult> {
    let args = ListActionsArgs {
        labels: vec![],
        label_query_mode: None,
        include_labels: None,
        include_inputs: None,
        include_input_source_locking_scripts: None,
        include_input_unlocking_scripts: None,
        include_outputs: None,
        include_output_locking_scripts: None,
        limit: None,
        offset: None,
        seek_permission: None,
    };
    canned(total, &[]).list_actions(args, None).await
}

/// listActions' result: `totalActions`, VarInt
/// (`wallet/0100.md:1819`, `PositiveIntegerOrZero` at `:814`).
#[tokio::test]
async fn a_list_actions_total_above_u32_max_is_refused_not_truncated() {
    let read = list_actions(0).await.unwrap();
    assert_eq!(read.total_actions, 0);
    assert_read_past_total(list_actions(u32::MAX as u64).await.unwrap_err());
    assert_eq!(
        list_actions(OVER).await.unwrap_err(),
        refusal("listActions totalActions")
    );
}

async fn list_outputs(total: u64) -> bsv_rs::Result<ListOutputsResult> {
    let args = ListOutputsArgs {
        basket: "b".to_string(),
        tags: None,
        tag_query_mode: None,
        include: None,
        include_custom_instructions: None,
        include_tags: None,
        include_labels: None,
        limit: None,
        offset: None,
        seek_permission: None,
    };
    // [totalOutputs][BEEF: VarInt(MaxUint64) for absent]
    canned(total, &var_int(u64::MAX))
        .list_outputs(args, None)
        .await
}

/// listOutputs' result: `totalOutputs`, VarInt (`wallet/0100.md:1950`,
/// `PositiveIntegerOrZero | ExactModuleBalance` at `:932`; the decimal string
/// is a BRC-112 balance query's, #105, and this test reads the count).
#[tokio::test]
async fn a_list_outputs_total_above_u32_max_is_refused_not_truncated() {
    let read = list_outputs(0).await.unwrap();
    assert_eq!((read.total_outputs, read.beef), (0, None));
    assert_read_past_total(list_outputs(u32::MAX as u64).await.unwrap_err());
    assert_eq!(
        list_outputs(OVER).await.unwrap_err(),
        refusal("listOutputs totalOutputs")
    );
}

async fn list_certificates(total: u64) -> bsv_rs::Result<ListCertificatesResult> {
    let args = ListCertificatesArgs {
        certifiers: vec![],
        types: vec![],
        limit: None,
        offset: None,
        privileged: None,
        privileged_reason: None,
    };
    canned(total, &[]).list_certificates(args, None).await
}

/// listCertificates' result: `totalCertificates`, VarInt
/// (`wallet/0100.md:2294`, `PositiveIntegerOrZero` at `:1298`).
#[tokio::test]
async fn a_list_certificates_total_above_u32_max_is_refused_not_truncated() {
    let read = list_certificates(0).await.unwrap();
    assert_eq!(read.total_certificates, 0);
    // The page is read to the end of the frame, not to the total (#190;
    // `ts-stack@edf6e03` `WalletWireTransceiver.ts:1501-1506,1508,1550`):
    // `u32::MAX` with no entry after it reads back as an empty page.
    let read = list_certificates(u32::MAX as u64).await.unwrap();
    assert_eq!(
        (read.total_certificates, read.certificates.len()),
        (u32::MAX, 0)
    );
    assert_eq!(
        list_certificates(OVER).await.unwrap_err(),
        refusal("listCertificates totalCertificates")
    );
}

async fn discover_by_identity_key(total: u64) -> bsv_rs::Result<DiscoverCertificatesResult> {
    let args = DiscoverByIdentityKeyArgs {
        identity_key: PrivateKey::random().public_key().to_hex(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    canned(total, &[])
        .discover_by_identity_key(args, None)
        .await
}

/// discoverByIdentityKey's result: `totalCertificates`, VarInt
/// (`wallet/0100.md:2378`, `PositiveIntegerOrZero` at `:1392`).
#[tokio::test]
async fn a_discovered_certificates_total_above_u32_max_is_refused_not_truncated() {
    let read = discover_by_identity_key(0).await.unwrap();
    assert_eq!(read.total_certificates, 0);
    // The page is read to the end of the frame, not to the total (#190;
    // `WalletWireTransceiver.ts:1676-1681,1699,1759`).
    let read = discover_by_identity_key(u32::MAX as u64).await.unwrap();
    assert_eq!(
        (read.total_certificates, read.certificates.len()),
        (u32::MAX, 0)
    );
    assert_eq!(
        discover_by_identity_key(OVER).await.unwrap_err(),
        refusal("discovery totalCertificates")
    );
}
