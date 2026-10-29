//! #470: local bound action failures use the reference's complete wrapper.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_retry_340.rs"]
mod support;

#[tokio::test]
async fn local_set_and_remove_wrap_the_recorded_bound_action_failure_470() {
    for name in [
        "local_set_once",
        "local_set_always",
        "local_remove_once",
        "local_remove_always",
    ] {
        let h = support::setup(name);
        let error = h.run().await.unwrap_err();
        assert_eq!(
            error.to_string(),
            h.case["error"]["message"].as_str().unwrap(),
            "{name}"
        );
        support::assert_attempts(&h, 1, 1);
    }
}

#[tokio::test]
async fn local_wrapper_uses_authenticated_count_for_set_and_reported_total_for_remove_470() {
    use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
    use bsv_rs::wallet::{ListOutputsResult, WalletOutput};
    use bsv_rs::{primitives::from_hex, Error};
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("vectors/kvstore_retry_340.json")).unwrap();
    for case in fixture["local_error_counts"].as_array().unwrap() {
        let mut wallet = identity_reveal_wallet::Counting::of_scalar(9);
        wallet.create_from_request = case["count"] != 0;
        if case["count"] == 0 {
            let source = bsv_rs::transaction::Transaction::from_beef(
                &from_hex(
                    support::fixture("local_set_once")["initial_tokens"][0]["beef"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                None,
            )
            .unwrap();
            *wallet.spending.lock().unwrap() = Some(source);
        }
        let listed = &case["listed"];
        *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
            total_outputs: listed["totalOutputs"].as_u64().unwrap() as u32,
            beef: Some(from_hex(listed["BEEF"].as_str().unwrap()).unwrap()),
            outputs: serde_json::from_value::<Vec<WalletOutput>>(listed["outputs"].clone())
                .unwrap(),
        });
        wallet
            .sign_answers
            .lock()
            .unwrap()
            .push_back(Err(Error::WalletError("wallet said no".into())));
        let store =
            LocalKVStore::new(wallet, KVStoreConfig::default().with_encrypt(false)).unwrap();
        let key = case["key"].as_str().unwrap();
        let result = if case["operation"] == "set" {
            store.set(key, "two", None).await.map(|_| ())
        } else {
            store.remove(key, None).await.map(|_| ())
        };
        assert_eq!(
            result.unwrap_err().to_string(),
            case["error"].as_str().unwrap()
        );
    }
}
