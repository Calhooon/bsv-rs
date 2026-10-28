//! `WalletClient` takes a `WalletInterface` instance as its substrate (#335),
//! the reference's constructor's own alternative: `substrate: 'auto' |
//! 'Cicada' | 'XDM' | 'window.CWI' | 'json-api' | 'react-native' |
//! 'secure-json-api' | WalletInterface = 'auto'` (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/WalletClient.ts:83-107`), each call then
//! `this.substrate.<call>(args, this.originator)`.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`)
//! behind `WalletClient::with_substrate` records each of the 28 calls and
//! the originator it received; nothing is probed and no port is reached.
//! The `Auto` path (the reference's `'auto'` tries the named substrates on
//! their defaults, `:95-101`) and the named substrates on their default URLs
//! stay unpinned here: a test of them would reach whatever listens on
//! 2121, 3321 and 3301.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use std::sync::Arc;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::*;
use identity_reveal_wallet::Counting;
use serde_json::json;

/// The 28 calls: the client's method, the `WalletInterface` method the
/// instance receives (the client's `get_header` is `getHeaderForHeight`).
const CALLS: [(&str, &str); 28] = [
    ("get_public_key", "get_public_key"),
    ("encrypt", "encrypt"),
    ("decrypt", "decrypt"),
    ("create_hmac", "create_hmac"),
    ("verify_hmac", "verify_hmac"),
    ("create_signature", "create_signature"),
    ("verify_signature", "verify_signature"),
    (
        "reveal_counterparty_key_linkage",
        "reveal_counterparty_key_linkage",
    ),
    ("reveal_specific_key_linkage", "reveal_specific_key_linkage"),
    ("create_action", "create_action"),
    ("sign_action", "sign_action"),
    ("abort_action", "abort_action"),
    ("list_actions", "list_actions"),
    ("internalize_action", "internalize_action"),
    ("list_outputs", "list_outputs"),
    ("relinquish_output", "relinquish_output"),
    ("acquire_certificate", "acquire_certificate"),
    ("list_certificates", "list_certificates"),
    ("prove_certificate", "prove_certificate"),
    ("relinquish_certificate", "relinquish_certificate"),
    ("discover_by_identity_key", "discover_by_identity_key"),
    ("discover_by_attributes", "discover_by_attributes"),
    ("is_authenticated", "is_authenticated"),
    ("wait_for_authentication", "wait_for_authentication"),
    ("get_height", "get_height"),
    ("get_header", "get_header_for_height"),
    ("get_network", "get_network"),
    ("get_version", "get_version"),
];

fn from<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

fn key(n: u8) -> bsv_rs::primitives::PublicKey {
    PrivateKey::from_bytes(&[n; 32]).unwrap().public_key()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::App, "client instance")
}

/// Makes the 28 calls through `client` in `CALLS`' order; each answer is
/// the instance's, success or refusal, and is not judged here.
async fn call_every_method(client: &mut WalletClient) {
    let identity = key(7).to_hex();
    let txid = "00".repeat(32);
    let _ = client
        .get_public_key(GetPublicKeyArgs {
            identity_key: true,
            ..Default::default()
        })
        .await;
    let _ = client
        .encrypt(EncryptArgs {
            plaintext: vec![1],
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .decrypt(DecryptArgs {
            ciphertext: vec![1],
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .create_hmac(CreateHmacArgs {
            data: vec![1],
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .verify_hmac(VerifyHmacArgs {
            data: vec![1],
            hmac: [0; 32],
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .create_signature(CreateSignatureArgs {
            data: Some(vec![1]),
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .verify_signature(VerifySignatureArgs {
            data: Some(vec![1]),
            signature: vec![0x30, 0x00],
            protocol_id: protocol(),
            key_id: "1".into(),
            ..Default::default()
        })
        .await;
    let _ = client
        .reveal_counterparty_key_linkage(WalletRevealCounterpartyArgs {
            counterparty: key(8),
            verifier: key(9),
            privileged: None,
            privileged_reason: None,
        })
        .await;
    let _ = client
        .reveal_specific_key_linkage(WalletRevealSpecificArgs {
            counterparty: Counterparty::Other(key(8)),
            verifier: key(9),
            protocol_id: protocol(),
            key_id: "1".into(),
            privileged: None,
            privileged_reason: None,
        })
        .await;
    let _ = client
        .create_action(from(json!({ "description": "a client action" })))
        .await;
    let _ = client
        .sign_action(from(json!({ "spends": {}, "reference": "UlJSUlJSUlI=" })))
        .await;
    let _ = client
        .abort_action(from(json!({ "reference": "UlJSUlJSUlI=" })))
        .await;
    let _ = client.list_actions(from(json!({ "labels": [] }))).await;
    let _ = client
        .internalize_action(from(json!({
            "tx": [1], "outputs": [], "description": "a client action"
        })))
        .await;
    let _ = client.list_outputs(from(json!({ "basket": "b" }))).await;
    let _ = client
        .relinquish_output(from(
            json!({ "basket": "b", "output": format!("{txid}.0") }),
        ))
        .await;
    let _ = client
        .acquire_certificate(from(json!({
            "type": "AAAA", "certifier": identity, "acquisitionProtocol": "direct",
            "fields": {}
        })))
        .await;
    let _ = client
        .list_certificates(from(json!({ "certifiers": [], "types": [] })))
        .await;
    let _ = client
        .prove_certificate(from(json!({
            "certificate": {
                "type": "AAAA", "subject": identity, "serialNumber": "AAAA",
                "certifier": identity, "revocationOutpoint": format!("{txid}.0"),
                "signature": "00", "fields": {}
            },
            "fieldsToReveal": [], "verifier": identity
        })))
        .await;
    let _ = client
        .relinquish_certificate(from(json!({
            "type": "AAAA", "serialNumber": "AAAA", "certifier": identity
        })))
        .await;
    let _ = client
        .discover_by_identity_key(from(json!({ "identityKey": identity })))
        .await;
    let _ = client
        .discover_by_attributes(from(json!({ "attributes": {} })))
        .await;
    let _ = client.is_authenticated().await;
    let _ = client.wait_for_authentication().await;
    let _ = client.get_height().await;
    let _ = client.get_header(from(json!({ "height": 1 }))).await;
    let _ = client.get_network().await;
    let _ = client.get_version().await;
}

fn received() -> Vec<&'static str> {
    CALLS.iter().map(|(_, method)| *method).collect()
}

#[tokio::test]
async fn every_call_reaches_the_instance_with_the_clients_originator() {
    let wallet = Counting::new();
    let mut client =
        WalletClient::with_substrate(Arc::new(wallet.clone()), Some("myapp.example".into()));

    call_every_method(&mut client).await;

    assert_eq!(wallet.calls(), received());
    assert_eq!(
        wallet.originators(),
        vec![Some("myapp.example".to_string()); 28]
    );
}

#[tokio::test]
async fn every_call_reaches_the_instance_with_no_originator_when_none_is_set() {
    let wallet = Counting::new();
    let mut client = WalletClient::with_substrate(Arc::new(wallet.clone()), None);

    call_every_method(&mut client).await;

    assert_eq!(wallet.calls(), received());
    assert_eq!(wallet.originators(), vec![None; 28]);
}

#[tokio::test]
async fn the_instances_answers_come_back_through_the_client() {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_bytes(&[5; 32]).unwrap()));
    let identity = wallet.identity_key_hex();
    let mut client = WalletClient::with_substrate(Arc::new(wallet), None);

    let key = client
        .get_public_key(GetPublicKeyArgs {
            identity_key: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(key.public_key, identity);
    assert_eq!(
        client.get_version().await.unwrap(),
        format!("bsv-rs-{}", env!("CARGO_PKG_VERSION"))
    );
    assert!(client.is_authenticated().await.unwrap());
    assert_eq!(client.get_height().await.unwrap(), 0);
    assert_eq!(client.get_network().await.unwrap(), Network::Mainnet);
    // A refusal is the instance's, as given.
    let refused = client
        .create_action(from(json!({ "description": "a client action" })))
        .await
        .unwrap_err();
    let direct = ProtoWallet::new(None)
        .create_action(from(json!({ "description": "a client action" })), None)
        .await
        .unwrap_err();
    assert_eq!(refused, direct);
    assert_eq!(client.substrate_type(), SubstrateType::Auto);
    assert_eq!(client.originator(), None);
}
