//! `ProtoWallet` serves nine key calls and five status calls; the fourteen
//! other calls of `WalletInterface` it refuses, each as a typed refusal:
//! `Error::WalletRefusal { class: WalletRefusalClass::NotImplemented, .. }`,
//! its words the ones it always answered (#843, the captain's ruling of
//! 2026-11-17). Until then each was `Error::WalletError(String)`, so a host
//! told "this wallet does not serve the call" from a fault only by comparing
//! the text.
//!
//! The class is the reference's for a call a wallet does not serve
//! (`WERR_NOT_IMPLEMENTED`, `packages/wallet/wallet-toolbox/src/sdk/
//! WERR_errors.ts:8` at `ts-stack@11faa7d1`, raised by
//! `storage/StorageProvider.ts:445-534`), and it has no SDK code, so the wire
//! processor frames it as it framed the `WalletError`: code 1, `Wallet
//! operation failed`. The frames of all fourteen calls over a `ProtoWallet`
//! were recorded before the change, with this crate's own processor
//! (`tests/vectors/proto_wallet_stub_frames_843.json`, written by the
//! `#[ignore]`d recorder below), and are compared byte for byte here.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireWriter};
use bsv_rs::wallet::{ProtoWallet, WalletInterface};
use bsv_rs::{Error, WalletRefusalClass};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TYPE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const TXID: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

fn wallet() -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_bytes(&[7u8; 32]).unwrap()))
}

/// Arguments built from their JSON, so a shape that gains a field or a
/// constructor needs no change here.
fn args<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

fn certificate() -> Value {
    json!({
        "type": TYPE,
        "subject": KEY,
        "serialNumber": TYPE,
        "certifier": KEY,
        "revocationOutpoint": format!("{TXID}.0"),
        "signature": "",
        "fields": {}
    })
}

/// The typed refusal, the words and the display (the words alone: a
/// `WalletRefusal` has no `wallet error: ` prefix).
fn assert_not_implemented<T: std::fmt::Debug>(result: bsv_rs::Result<T>, words: &str) {
    let error = result.expect_err("a ProtoWallet does not serve the call");
    assert_eq!(
        error,
        Error::WalletRefusal {
            class: WalletRefusalClass::NotImplemented,
            message: words.to_string(),
        }
    );
    assert_eq!(error.to_string(), words);
}

#[tokio::test]
async fn create_action_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .create_action(args(json!({ "description": "a stub call" })), None)
        .await;
    assert_not_implemented(
        result,
        "createAction requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn sign_action_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .sign_action(args(json!({ "spends": {}, "reference": "cmVm" })), None)
        .await;
    assert_not_implemented(
        result,
        "signAction requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn abort_action_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .abort_action(args(json!({ "reference": "cmVm" })), None)
        .await;
    assert_not_implemented(
        result,
        "abortAction requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn list_actions_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .list_actions(args(json!({ "labels": [] })), None)
        .await;
    assert_not_implemented(
        result,
        "listActions requires a full wallet implementation with transaction history",
    );
}

/// The arguments are judged ahead of the refusal, as before: valid ones
/// reach it.
#[tokio::test]
async fn internalize_action_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .internalize_action(
            args(json!({ "tx": [], "outputs": [], "description": "a stub call" })),
            None,
        )
        .await;
    assert_not_implemented(
        result,
        "internalizeAction requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn list_outputs_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .list_outputs(args(json!({ "basket": "a basket" })), None)
        .await;
    assert_not_implemented(
        result,
        "listOutputs requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn relinquish_output_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .relinquish_output(
            args(json!({ "basket": "a basket", "output": format!("{TXID}.0") })),
            None,
        )
        .await;
    assert_not_implemented(
        result,
        "relinquishOutput requires a full wallet implementation with UTXO management",
    );
}

#[tokio::test]
async fn acquire_certificate_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .acquire_certificate(
            args(json!({
                "type": TYPE,
                "certifier": KEY,
                "acquisitionProtocol": "direct",
                "fields": {}
            })),
            None,
        )
        .await;
    assert_not_implemented(
        result,
        "acquireCertificate requires a full wallet implementation with certificate storage",
    );
}

#[tokio::test]
async fn list_certificates_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .list_certificates(args(json!({ "certifiers": [], "types": [] })), None)
        .await;
    assert_not_implemented(
        result,
        "listCertificates requires a full wallet implementation with certificate storage",
    );
}

#[tokio::test]
async fn prove_certificate_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .prove_certificate(
            args(json!({
                "certificate": certificate(),
                "fieldsToReveal": [],
                "verifier": KEY
            })),
            None,
        )
        .await;
    assert_not_implemented(
        result,
        "proveCertificate requires a full wallet implementation with certificate storage",
    );
}

#[tokio::test]
async fn relinquish_certificate_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .relinquish_certificate(
            args(json!({ "type": TYPE, "serialNumber": TYPE, "certifier": KEY })),
            None,
        )
        .await;
    assert_not_implemented(
        result,
        "relinquishCertificate requires a full wallet implementation with certificate storage",
    );
}

#[tokio::test]
async fn discover_by_identity_key_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .discover_by_identity_key(args(json!({ "identityKey": KEY })), None)
        .await;
    assert_not_implemented(
        result,
        "discoverByIdentityKey requires a full wallet implementation with certificate discovery",
    );
}

#[tokio::test]
async fn discover_by_attributes_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .discover_by_attributes(args(json!({ "attributes": { "name": "a" } })), None)
        .await;
    assert_not_implemented(
        result,
        "discoverByAttributes requires a full wallet implementation with certificate discovery",
    );
}

#[tokio::test]
async fn get_header_for_height_on_a_proto_wallet_is_a_not_implemented_refusal_843() {
    let result = wallet()
        .get_header_for_height(args(json!({ "height": 1 })), None)
        .await;
    assert_not_implemented(
        result,
        "getHeaderForHeight requires a full wallet implementation with block header storage",
    );
}

// ============================================================================
// The wire: the frames of a processor over a ProtoWallet are unchanged
// ============================================================================

const FRAMES: &str = include_str!("vectors/proto_wallet_stub_frames_843.json");

const STUB_CALLS: [WalletCall; 14] = [
    WalletCall::CreateAction,
    WalletCall::SignAction,
    WalletCall::AbortAction,
    WalletCall::ListActions,
    WalletCall::InternalizeAction,
    WalletCall::ListOutputs,
    WalletCall::RelinquishOutput,
    WalletCall::AcquireCertificate,
    WalletCall::ListCertificates,
    WalletCall::ProveCertificate,
    WalletCall::RelinquishCertificate,
    WalletCall::DiscoverByIdentityKey,
    WalletCall::DiscoverByAttributes,
    WalletCall::GetHeaderForHeight,
];

/// A request frame: the call, the originator `test`, then the parameters the
/// two calls that reach the wallet need (abortAction's reference bytes,
/// getHeaderForHeight's height); the twelve others are refused by the
/// processor before it reads one.
fn request(call: WalletCall) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(call.as_u8());
    writer.write_u8(4);
    writer.write_bytes(b"test");
    match call {
        WalletCall::AbortAction => {
            writer.write_bytes(b"ref");
        }
        WalletCall::GetHeaderForHeight => {
            writer.write_var_int(1);
        }
        _ => {}
    }
    writer.into_bytes()
}

async fn frames_now() -> Value {
    let processor = WalletWireProcessor::new(wallet());
    let mut cells = Vec::new();
    for call in STUB_CALLS {
        let request = request(call);
        let response = processor.process_message(&request).await.unwrap();
        cells.push(json!({
            "call": call.method_name(),
            "request_hex": hex::encode(&request),
            "response_hex": hex::encode(&response),
        }));
    }
    Value::Array(cells)
}

/// The fourteen frames are the bytes recorded before the stubs were typed:
/// `NotImplemented` has no SDK code, so abortAction and getHeaderForHeight
/// (the two the processor hands to the wallet) stay code 1, `Wallet
/// operation failed`, and the twelve the processor refuses itself never
/// reach the wallet.
#[tokio::test]
async fn a_processor_over_a_proto_wallet_frames_the_fourteen_stubs_as_before_843() {
    let recorded: Value = serde_json::from_str(FRAMES).unwrap();
    assert_eq!(recorded["frames"].as_array().unwrap().len(), 14);
    assert_eq!(frames_now().await, recorded["frames"]);
}

/// The two frames that come from the wallet's refusal, by hand: code 1, the
/// replacement's words, the empty stack.
#[tokio::test]
async fn the_two_stubs_the_processor_reaches_are_framed_code_1_without_their_words_843() {
    let mut frame = vec![1u8, 23];
    frame.extend(b"Wallet operation failed");
    frame.push(0);
    let processor = WalletWireProcessor::new(wallet());
    for call in [WalletCall::AbortAction, WalletCall::GetHeaderForHeight] {
        let response = processor.process_message(&request(call)).await.unwrap();
        assert_eq!(response, frame, "{call}");
    }
}

/// Writes the vector. Run by hand, on the tree whose frames are to be kept
/// (it was run on the pre-fix tree, `4c5454be`):
/// `BSV_RECORD_843=<path> cargo test --features wallet --test proto_wallet_stub_refusals_843 -- --ignored`
#[tokio::test]
#[ignore = "recorder: writes the vector to the path in BSV_RECORD_843"]
async fn record_the_frames_of_a_processor_over_a_proto_wallet() {
    let path = std::env::var("BSV_RECORD_843").expect("BSV_RECORD_843 names the file to write");
    let document = json!({
        "description": "The response frames of WalletWireProcessor over a ProtoWallet for the fourteen calls a ProtoWallet does not serve, recorded by this crate's own processor at 4c5454be, before the stubs became WalletRefusal { class: NotImplemented } (#843).",
        "frames": frames_now().await,
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap();
    text.push('\n');
    std::fs::write(path, text).unwrap();
}
