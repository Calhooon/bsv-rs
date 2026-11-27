//! The wallet wire's `u32` fields read at their bound (ported from the 0.9
//! line's bsv-rs#120, #122, #255).
//!
//! Each field below is a `u32` by the transaction format (the indices, the
//! sequence numbers, the version, the lock time) or by BRC-100's
//! `PositiveIntegerOrZero` (at most `2^32 - 1`). The frame's tables write each
//! as a VarInt. `u32::MAX` reads back; `u32::MAX + 1` is refused with the field
//! named, where the reader once cast it (`as u32`) to another value; the words
//! are the reference's `#requireInteger`'s (`ts-stack@edf6e03`
//! `WalletWireTransceiver.ts:2018-2025`), the name its own per site (#255).

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::collections::HashMap;
use std::sync::Mutex;

const OVER: u64 = u32::MAX as u64 + 1;

/// The reference's `#requireInteger` words (`WalletWireTransceiver.ts:2018-2025`)
/// with the crate's name for the field (#255).
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

/// Replaces the writer's 5-byte varint for `u32::MAX`, found exactly once in
/// `frame`, with the writer's 9-byte varint for `u32::MAX + 1`, leaving every
/// other byte. The forged frame is one this crate's writer cannot produce (the
/// field is a `u32` in memory): it is built here, past the writer.
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
// encoding.rs: the readers' u32 indices, sequence numbers, version, lock time
// ============================================================================

#[test]
fn an_outpoint_index_above_u32_max_is_refused_not_truncated() {
    let mut writer = WireWriter::new();
    writer.write_outpoint(&Outpoint::new([7u8; 32], u32::MAX));
    let frame = writer.into_bytes();
    assert_eq!(
        WireReader::new(&frame).read_outpoint().unwrap(),
        Outpoint::new([7u8; 32], u32::MAX)
    );

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over).read_outpoint().unwrap_err(),
        refusal("outpoint index")
    );
}

#[test]
fn a_sign_action_spend_sequence_number_above_u32_max_is_refused_not_truncated() {
    let spend = SignActionSpend {
        unlocking_script: vec![0x51],
        sequence_number: Some(u32::MAX),
    };
    let mut writer = WireWriter::new();
    writer.write_sign_action_spend(&spend);
    let frame = writer.into_bytes();
    assert_eq!(
        WireReader::new(&frame)
            .read_sign_action_spend()
            .unwrap()
            .sequence_number,
        Some(u32::MAX)
    );

    // [script: varint len + bytes][sequenceNumber: optional (signed) varint]
    let mut writer = WireWriter::new();
    writer.write_var_int(1);
    writer.write_bytes(&[0x51]);
    writer.write_optional_var_int(Some(OVER));
    let over = writer.into_bytes();
    assert_eq!(
        WireReader::new(&over).read_sign_action_spend().unwrap_err(),
        refusal("signAction spend sequenceNumber")
    );
}

#[test]
fn a_sign_action_spend_index_above_u32_max_is_refused_not_truncated() {
    let mut spends = HashMap::new();
    spends.insert(
        u32::MAX,
        SignActionSpend {
            unlocking_script: vec![0x51],
            sequence_number: None,
        },
    );
    let mut writer = WireWriter::new();
    writer.write_sign_action_spends(&spends);
    let frame = writer.into_bytes();
    let read = WireReader::new(&frame).read_sign_action_spends().unwrap();
    assert_eq!(read.keys().copied().collect::<Vec<_>>(), vec![u32::MAX]);

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over)
            .read_sign_action_spends()
            .unwrap_err(),
        refusal("sign action spend input index")
    );
}

#[test]
fn an_internalize_output_index_above_u32_max_is_refused_not_truncated() {
    let output = InternalizeOutput {
        output_index: u32::MAX,
        protocol: "basket insertion".to_string(),
        payment_remittance: None,
        insertion_remittance: None,
    };
    let mut writer = WireWriter::new();
    writer.write_internalize_output(&output);
    let frame = writer.into_bytes();
    assert_eq!(
        WireReader::new(&frame)
            .read_internalize_output()
            .unwrap()
            .output_index,
        u32::MAX
    );

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over)
            .read_internalize_output()
            .unwrap_err(),
        refusal("internalize output index")
    );
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

#[test]
fn an_action_input_sequence_number_above_u32_max_is_refused_not_truncated() {
    let mut writer = WireWriter::new();
    writer.write_wallet_action_input(&action_input(u32::MAX));
    let frame = writer.into_bytes();
    assert_eq!(
        WireReader::new(&frame)
            .read_wallet_action_input()
            .unwrap()
            .sequence_number,
        u32::MAX
    );

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over)
            .read_wallet_action_input()
            .unwrap_err(),
        refusal("listActions input sequenceNumber")
    );
}

fn action_output(output_index: u32) -> WalletActionOutput {
    WalletActionOutput {
        satoshis: 1000,
        locking_script: Some(vec![0x51]),
        spendable: true,
        custom_instructions: None,
        tags: vec![],
        output_index,
        output_description: "out".to_string(),
        basket: "default".to_string(),
    }
}

#[test]
fn a_wallet_action_output_index_above_u32_max_is_refused_not_truncated() {
    let mut writer = WireWriter::new();
    writer.write_wallet_action_output(&action_output(u32::MAX));
    let frame = writer.into_bytes();
    assert_eq!(
        WireReader::new(&frame)
            .read_wallet_action_output()
            .unwrap()
            .output_index,
        u32::MAX
    );

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over)
            .read_wallet_action_output()
            .unwrap_err(),
        refusal("listActions output outputIndex")
    );
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

#[test]
fn an_action_version_above_u32_max_is_refused_not_truncated() {
    let frame = action_frame(&action(u32::MAX, 0));
    let read = WireReader::new(&frame).read_wallet_action().unwrap();
    assert_eq!((read.version, read.lock_time), (u32::MAX, 0));

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over).read_wallet_action().unwrap_err(),
        refusal("listActions version")
    );
}

#[test]
fn an_action_lock_time_above_u32_max_is_refused_not_truncated() {
    let frame = action_frame(&action(1, u32::MAX));
    let read = WireReader::new(&frame).read_wallet_action().unwrap();
    assert_eq!((read.version, read.lock_time), (1, u32::MAX));

    let over = widen_past_u32(&frame);
    assert_eq!(
        WireReader::new(&over).read_wallet_action().unwrap_err(),
        refusal("listActions lockTime")
    );
}

// ============================================================================
// processor.rs: getHeaderForHeight's height
// ============================================================================

/// Records the height `get_header_for_height` was asked for; every other
/// method is unreachable from these tests.
#[derive(Default)]
struct HeightWallet {
    asked: Mutex<Option<u32>>,
}

#[async_trait::async_trait]
impl WalletInterface for HeightWallet {
    async fn get_public_key(
        &self,
        _a: GetPublicKeyArgs,
        _o: &str,
    ) -> bsv_rs::Result<GetPublicKeyResult> {
        unreachable!("get_public_key")
    }
    async fn encrypt(&self, _a: EncryptArgs, _o: &str) -> bsv_rs::Result<EncryptResult> {
        unreachable!("encrypt")
    }
    async fn decrypt(&self, _a: DecryptArgs, _o: &str) -> bsv_rs::Result<DecryptResult> {
        unreachable!("decrypt")
    }
    async fn create_hmac(&self, _a: CreateHmacArgs, _o: &str) -> bsv_rs::Result<CreateHmacResult> {
        unreachable!("create_hmac")
    }
    async fn verify_hmac(&self, _a: VerifyHmacArgs, _o: &str) -> bsv_rs::Result<VerifyHmacResult> {
        unreachable!("verify_hmac")
    }
    async fn create_signature(
        &self,
        _a: CreateSignatureArgs,
        _o: &str,
    ) -> bsv_rs::Result<CreateSignatureResult> {
        unreachable!("create_signature")
    }
    async fn verify_signature(
        &self,
        _a: VerifySignatureArgs,
        _o: &str,
    ) -> bsv_rs::Result<VerifySignatureResult> {
        unreachable!("verify_signature")
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        _a: WalletRevealCounterpartyArgs,
        _o: &str,
    ) -> bsv_rs::Result<RevealCounterpartyKeyLinkageResult> {
        unreachable!("reveal_counterparty_key_linkage")
    }
    async fn reveal_specific_key_linkage(
        &self,
        _a: WalletRevealSpecificArgs,
        _o: &str,
    ) -> bsv_rs::Result<RevealSpecificKeyLinkageResult> {
        unreachable!("reveal_specific_key_linkage")
    }
    async fn create_action(
        &self,
        _a: CreateActionArgs,
        _o: &str,
    ) -> bsv_rs::Result<CreateActionResult> {
        unreachable!("create_action")
    }
    async fn sign_action(&self, _a: SignActionArgs, _o: &str) -> bsv_rs::Result<SignActionResult> {
        unreachable!("sign_action")
    }
    async fn abort_action(
        &self,
        _a: AbortActionArgs,
        _o: &str,
    ) -> bsv_rs::Result<AbortActionResult> {
        unreachable!("abort_action")
    }
    async fn list_actions(
        &self,
        _a: ListActionsArgs,
        _o: &str,
    ) -> bsv_rs::Result<ListActionsResult> {
        unreachable!("list_actions")
    }
    async fn internalize_action(
        &self,
        _a: InternalizeActionArgs,
        _o: &str,
    ) -> bsv_rs::Result<InternalizeActionResult> {
        unreachable!("internalize_action")
    }
    async fn list_outputs(
        &self,
        _a: ListOutputsArgs,
        _o: &str,
    ) -> bsv_rs::Result<ListOutputsResult> {
        unreachable!("list_outputs")
    }
    async fn relinquish_output(
        &self,
        _a: RelinquishOutputArgs,
        _o: &str,
    ) -> bsv_rs::Result<RelinquishOutputResult> {
        unreachable!("relinquish_output")
    }
    async fn acquire_certificate(
        &self,
        _a: AcquireCertificateArgs,
        _o: &str,
    ) -> bsv_rs::Result<WalletCertificate> {
        unreachable!("acquire_certificate")
    }
    async fn list_certificates(
        &self,
        _a: ListCertificatesArgs,
        _o: &str,
    ) -> bsv_rs::Result<ListCertificatesResult> {
        unreachable!("list_certificates")
    }
    async fn prove_certificate(
        &self,
        _a: ProveCertificateArgs,
        _o: &str,
    ) -> bsv_rs::Result<ProveCertificateResult> {
        unreachable!("prove_certificate")
    }
    async fn relinquish_certificate(
        &self,
        _a: RelinquishCertificateArgs,
        _o: &str,
    ) -> bsv_rs::Result<RelinquishCertificateResult> {
        unreachable!("relinquish_certificate")
    }
    async fn discover_by_identity_key(
        &self,
        _a: DiscoverByIdentityKeyArgs,
        _o: &str,
    ) -> bsv_rs::Result<DiscoverCertificatesResult> {
        unreachable!("discover_by_identity_key")
    }
    async fn discover_by_attributes(
        &self,
        _a: DiscoverByAttributesArgs,
        _o: &str,
    ) -> bsv_rs::Result<DiscoverCertificatesResult> {
        unreachable!("discover_by_attributes")
    }

    async fn is_authenticated(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
        unreachable!("is_authenticated")
    }
    async fn wait_for_authentication(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
        unreachable!("wait_for_authentication")
    }
    async fn get_height(&self, _: &str) -> bsv_rs::Result<GetHeightResult> {
        unreachable!("get_height")
    }
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        _: &str,
    ) -> bsv_rs::Result<GetHeaderResult> {
        *self.asked.lock().unwrap() = Some(args.height);
        Ok(GetHeaderResult {
            header: "00".repeat(80),
        })
    }
    async fn get_network(&self, _: &str) -> bsv_rs::Result<GetNetworkResult> {
        unreachable!("get_network")
    }
    async fn get_version(&self, _: &str) -> bsv_rs::Result<GetVersionResult> {
        unreachable!("get_version")
    }
}

/// [call: u8][originator: u8 len + bytes][height: varint]
fn get_header_frame(height: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(WalletCall::GetHeaderForHeight.as_u8());
    writer.write_u8(0);
    writer.write_var_int(height);
    writer.into_bytes()
}

#[tokio::test]
async fn a_header_height_above_u32_max_is_refused_not_truncated() {
    let processor = WalletWireProcessor::new(HeightWallet::default());

    // u32::MAX is parsed and handed to the wallet, not cast.
    let answer = processor
        .process_message(&get_header_frame(u32::MAX as u64))
        .await
        .unwrap();
    assert_eq!(answer[0], 0, "success byte");
    assert_eq!(*processor.wallet().asked.lock().unwrap(), Some(u32::MAX));

    // u32::MAX + 1 is refused at the read, before the wallet is reached; the
    // pre-fix cast read 0 and asked the wallet for header 0.
    let answer = processor
        .process_message(&get_header_frame(OVER))
        .await
        .unwrap();
    let mut reader = WireReader::new(&answer);
    assert_eq!(reader.read_u8().unwrap(), 1, "error code");
    assert_eq!(
        reader.read_string().unwrap(),
        format!(
            "wallet error: Invalid height: expected an integer from 0 to 4294967295, received {OVER}"
        )
    );
    assert_eq!(*processor.wallet().asked.lock().unwrap(), Some(u32::MAX));
}

/// The 0.9 line's later lower bound (`height >= 1`, bsv-rs#216) did NOT travel
/// with this port: height 0 is still accepted here, as it is on `0.8.13`.
#[tokio::test]
async fn a_header_height_of_zero_is_still_accepted() {
    let processor = WalletWireProcessor::new(HeightWallet::default());
    let answer = processor
        .process_message(&get_header_frame(0))
        .await
        .unwrap();
    assert_eq!(answer[0], 0, "success byte");
    assert_eq!(*processor.wallet().asked.lock().unwrap(), Some(0));
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

fn list_actions_args() -> ListActionsArgs {
    ListActionsArgs {
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
    }
}

// The total is the FIRST field of each response; `u32::MAX + 1` is refused
// there, before any page entry is read (the pre-fix cast read 0). The stable
// line reads `total` entries, so a `u32::MAX` page is not a frame a test can
// build; the refusal before the first entry is the regression.
#[tokio::test]
async fn a_list_actions_total_above_u32_max_is_refused_not_truncated() {
    assert_eq!(
        canned(OVER, &[])
            .list_actions(list_actions_args(), "")
            .await
            .unwrap_err(),
        refusal("listActions totalActions")
    );
}

fn list_outputs_args() -> ListOutputsArgs {
    ListOutputsArgs {
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
    }
}

#[tokio::test]
async fn a_list_outputs_total_above_u32_max_is_refused_not_truncated() {
    assert_eq!(
        canned(OVER, &var_int(u64::MAX))
            .list_outputs(list_outputs_args(), "")
            .await
            .unwrap_err(),
        refusal("listOutputs totalOutputs")
    );
}

fn list_certificates_args() -> ListCertificatesArgs {
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
async fn a_list_certificates_total_above_u32_max_is_refused_not_truncated() {
    assert_eq!(
        canned(OVER, &[])
            .list_certificates(list_certificates_args(), "")
            .await
            .unwrap_err(),
        refusal("listCertificates totalCertificates")
    );
}

fn discover_args() -> DiscoverByIdentityKeyArgs {
    DiscoverByIdentityKeyArgs {
        identity_key: bsv_rs::primitives::PrivateKey::random()
            .public_key()
            .to_hex(),
        limit: None,
        offset: None,
        seek_permission: None,
    }
}

#[tokio::test]
async fn a_discovered_certificates_total_above_u32_max_is_refused_not_truncated() {
    assert_eq!(
        canned(OVER, &[])
            .discover_by_identity_key(discover_args(), "")
            .await
            .unwrap_err(),
        refusal("discovery totalCertificates")
    );
}
