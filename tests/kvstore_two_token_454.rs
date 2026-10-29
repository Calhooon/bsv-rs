//! #454: byte comparisons against SDK-written two-token actions and requests.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod reference;
#[path = "support/kvstore_tokens_343.rs"]
mod tokens;
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::transaction::{Beef, Transaction};
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use serde_json::Value;

fn cases() -> Value {
    serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap()
}

async fn compare(global: bool, remove: bool) {
    let all = cases();
    let kind = if global { "global" } else { "local" };
    let op = if remove { "remove" } else { "set" };
    let case = all["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == kind && c["operation"] == op)
        .unwrap();
    let mut h = tokens::setup(global, 0).await;
    if !global {
        h.store = tokens::Store::Local(
            bsv_rs::kvstore::LocalKVStore::new(
                h.wallet.clone(),
                bsv_rs::kvstore::KVStoreConfig::default().with_encrypt(false),
            )
            .unwrap(),
        );
    }
    let sources: Vec<_> = case["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                Transaction::from_beef(&from_hex(s.as_str().unwrap()).unwrap(), None).unwrap(),
                0,
            )
        })
        .collect();
    *h.wallet.spending_many.lock().unwrap() = sources.clone();
    // The recording wallet reverses its sources; match the reference's input order.
    h.wallet.spending_many.lock().unwrap().reverse();
    let mut beef = Beef::new();
    for (tx, _) in &sources {
        beef.merge_transaction(tx.clone());
    }
    *h.wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 2,
        beef: Some(beef.to_binary()),
        outputs: sources
            .iter()
            .map(|(tx, _)| WalletOutput {
                outpoint: Outpoint::from_string(&format!("{}.0", tx.id())).unwrap(),
                satoshis: tx.outputs[0].satoshis.unwrap(),
                locking_script: Some(tx.outputs[0].locking_script.to_binary()),
                spendable: true,
                tags: Some(vec!["alpha".into()]),
                custom_instructions: None,
                labels: None,
            })
            .collect(),
    });
    *h.lookup.lock().unwrap() = sources
        .iter()
        .map(|(tx, _)| bsv_rs::overlay::OutputListItem {
            beef: tx.to_beef(true).unwrap(),
            output_index: 0,
            context: None,
        })
        .collect();
    if remove {
        h.store.remove().await
    } else {
        h.store.set("two").await
    }
    let args = h.wallet.created.lock().unwrap().clone().unwrap();
    assert_eq!(
        serde_json::to_value(args.inputs.as_ref().unwrap()).unwrap(),
        case["create_action_inputs"]
    );
    assert_eq!(
        to_hex(args.input_beef.as_ref().unwrap()),
        case["input_beef"]
    );
    let requests = h.wallet.signature_args.lock().unwrap().clone();
    let expected: Vec<Value> = case["create_signature_json"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_str(v.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(
        reference::signature_requests(&requests),
        Value::Array(expected),
        "PushDrop request text"
    );
    let signed = h.wallet.signed.lock().unwrap().clone().unwrap();
    reference::assert_reference_sign("two tokens", case, &signed, args.options.as_ref());
    assert_eq!(
        serde_json::to_value(&signed.spends).unwrap(),
        case["sign_action"]["spends"],
        "every unlocking script byte"
    );
}

#[tokio::test]
async fn local_set_two_token_bytes_and_signature_requests_454() {
    compare(false, false).await
}
#[tokio::test]
async fn local_remove_two_token_bytes_and_signature_requests_454() {
    compare(false, true).await
}
#[tokio::test]
async fn global_set_two_token_bytes_and_signature_requests_454() {
    compare(true, false).await
}
#[tokio::test]
async fn global_remove_two_token_bytes_and_signature_requests_454() {
    compare(true, true).await
}
