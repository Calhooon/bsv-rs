//! #478: the reference's request bytes, descriptions and unique-token search.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_tokens_343.rs"]
mod tokens;

use bsv_rs::kvstore::{KVStoreConfig, KVStoreSetOptions, LocalKVStore};
use bsv_rs::primitives::from_hex;
use bsv_rs::wallet::{Counterparty, ListOutputsResult, SignableTransaction};
use identity_reveal_wallet::Counting;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap()
}

fn local_run(operation: &str) -> Value {
    vector()["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["kind"] == "local" && run["operation"] == operation)
        .unwrap()
        .clone()
}

async fn create_request() -> Counting {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 0,
        outputs: vec![],
        beef: None,
    });
    let store =
        LocalKVStore::new(wallet.clone(), KVStoreConfig::default().with_encrypt(false)).unwrap();
    // This recording wallet stops at the boundary, after recording the request.
    assert!(store.set("alpha", "two", None).await.is_err());
    wallet
}

#[tokio::test]
async fn local_lock_requests_for_self_false_478() {
    let wallet = create_request().await;
    let run = local_run("set");
    let expected: Value = serde_json::from_str(
        run["get_public_key_json"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let requests = wallet.public_key_args.lock().unwrap();
    let request = &requests[0];
    let protocol = request.protocol_id.as_ref().unwrap();
    let actual = serde_json::json!({
        "protocolID": [protocol.security_level as u8, protocol.protocol_name],
        "keyID": request.key_id,
        "counterparty": match request.counterparty.as_ref().unwrap() {
            Counterparty::Self_ => "self".to_owned(),
            Counterparty::Anyone => "anyone".to_owned(),
            Counterparty::Other(key) => key.to_hex(),
        },
        "forSelf": request.for_self,
    });
    assert!(!request.identity_key);
    assert!(request.privileged.is_none());
    assert!(request.privileged_reason.is_none());
    assert!(request.seek_permission.is_none());
    // Canonical JSON compares every request member and byte, independent of key order.
    assert_eq!(
        serde_json::to_string(&actual).unwrap(),
        serde_json::to_string(&expected).unwrap(),
        "the recorded PushDrop.lock getPublicKey request"
    );
}

#[tokio::test]
async fn local_remove_description_uses_in_478() {
    let harness = tokens::setup(false, 1).await;
    harness.store.remove().await;
    let creates = harness.wallet.creates.lock().unwrap();
    assert_eq!(
        creates.last().unwrap().description.as_bytes(),
        local_run("remove")["create_action_description"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
}

#[tokio::test]
async fn local_output_description_is_key_value_token_478() {
    let wallet = create_request().await;
    let created = wallet.created.lock().unwrap();
    assert_eq!(
        created.as_ref().unwrap().outputs.as_ref().unwrap()[0]
            .output_description
            .as_bytes(),
        local_run("set")["create_action_output_descriptions"][0]
            .as_str()
            .unwrap()
            .as_bytes()
    );
}

#[tokio::test]
async fn local_outpoint_requires_one_matching_token_at_its_actual_index_478() {
    let cases = vector()["token_search"]["cases"]
        .as_array()
        .unwrap()
        .clone();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for case in cases {
        let mut wallet = Counting::of_scalar(9);
        *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
            total_outputs: 0,
            outputs: vec![],
            beef: None,
        });
        wallet.signable = Some(SignableTransaction {
            tx: from_hex(case["transaction"].as_str().unwrap()).unwrap(),
            reference: vec![0x52; 8],
        });
        *wallet.sign_mode.lock().unwrap() = "valid";
        let store =
            LocalKVStore::new(wallet, KVStoreConfig::default().with_encrypt(false)).unwrap();
        // The bound action preserves the requested two-satoshi output at zero.
        // Only one-satoshi copies of its script qualify for the reference search.
        let result = store
            .set(
                "alpha",
                "two",
                Some(KVStoreSetOptions {
                    token_amount: Some(2),
                    ..Default::default()
                }),
            )
            .await;
        actual.push((
            case["name"].clone(),
            result.map_err(|error| error.to_string()),
        ));
        let outcome = if let Some(outpoint) = case["outpoint"].as_str() {
            Ok(outpoint.to_owned())
        } else {
            Err(case["error"].as_str().unwrap().to_owned())
        };
        expected.push((case["name"].clone(), outcome));
    }
    // Accumulate all three outcomes so the base run records every wrong answer.
    assert_eq!(
        actual, expected,
        "nonzero, absent and duplicate token outcomes"
    );
}
