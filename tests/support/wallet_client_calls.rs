//! The complete client call set shared by the instance and trait regressions.
#![allow(dead_code)]

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::*;
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

pub fn from<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

pub fn key(n: u8) -> bsv_rs::primitives::PublicKey {
    PrivateKey::from_bytes(&[n; 32]).unwrap().public_key()
}

pub fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::App, "client instance")
}

/// Calls all 28 methods through the public inherent surface.
pub async fn call_every_method(client: &mut WalletClient) {
    keys(client).await;
    signatures(client).await;
    linkage(client).await;
    actions(client).await;
    outputs_and_certificates(client).await;
    discovery_and_status(client).await;
}

pub fn received() -> Vec<&'static str> {
    CALLS.iter().map(|(_, method)| *method).collect()
}
async fn keys(client: &mut WalletClient) {
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
}

async fn signatures(client: &mut WalletClient) {
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
}

async fn linkage(client: &mut WalletClient) {
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
}

async fn actions(client: &mut WalletClient) {
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
}

async fn outputs_and_certificates(client: &mut WalletClient) {
    let identity = key(7).to_hex();
    let txid = "00".repeat(32);
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
}

async fn discovery_and_status(client: &mut WalletClient) {
    let identity = key(7).to_hex();
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
