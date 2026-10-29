//! #341/#342: the reference's checks before signing and options on both calls.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_bound_341_342.rs"]
mod support;
use bsv_rs::kvstore::KVStoreConfig;
use support::{assert_options, setup, vector};

#[tokio::test]
async fn the_wallet_answer_is_bound_before_either_store_signs_341() {
    let fixture = vector();
    for global in [false, true] {
        for mode in [
            "version",
            "lock_time",
            "version_before_input",
            "missing_input",
            "duplicate_input",
            "sequence",
            "empty_reference",
        ] {
            let (store, wallet) = setup(global, KVStoreConfig::default()).await;
            *wallet.create_mode.lock().unwrap() = mode;
            // Both removals request the token and bind it before signing.
            let error = store.remove().await.unwrap_err();
            assert_eq!(
                error,
                bsv_rs::Error::KvStoreError(
                    fixture["refusals"][mode]["error"].as_str().unwrap().into()
                ),
                "{global}/{mode}"
            );
            assert!(
                wallet.signs.lock().unwrap().is_empty(),
                "{global}/{mode}: signed"
            );
            assert_eq!(
                wallet.aborts.lock().unwrap().len(),
                fixture["refusals"][mode]["abort_calls"].as_u64().unwrap() as usize
            );
        }
    }
}

#[tokio::test]
async fn the_local_output_is_bound_before_signing_341() {
    let (store, wallet) = setup(false, KVStoreConfig::default()).await;
    *wallet.create_mode.lock().unwrap() = "output";
    let error = store.set("two").await.unwrap_err();
    assert_eq!(
        error,
        bsv_rs::Error::KvStoreError(
            vector()["refusals"]["output"]["error"]
                .as_str()
                .unwrap()
                .into()
        )
    );
    assert!(wallet.signs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn both_stores_send_the_recorded_default_options_on_both_calls_342() {
    for global in [false, true] {
        let (store, wallet) = setup(global, KVStoreConfig::default()).await;
        assert_options(&wallet, global, "set_new", "defaults");
        store.set("two").await.unwrap_err();
        assert_options(&wallet, global, "set_update", "defaults");
        store.remove().await.unwrap_err();
        assert_options(&wallet, global, "remove", "defaults");
    }
}

#[tokio::test]
async fn a_wallet_added_input_has_no_requested_token_signer_341() {
    let (_, wallet) = setup(true, KVStoreConfig::default()).await;
    assert!(wallet
        .signed
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .spends
        .is_empty());
}

#[tokio::test]
async fn the_signed_result_is_checked_against_the_owned_template_341() {
    for mode in ["signed_version", "signed_output", "signed_script"] {
        let (store, wallet) = setup(false, KVStoreConfig::default()).await;
        *wallet.sign_mode.lock().unwrap() = mode;
        let error = store.set("two").await.unwrap_err();
        assert_eq!(
            error,
            bsv_rs::Error::KvStoreError(
                vector()["refusals"][mode]["error"].as_str().unwrap().into()
            )
        );
        assert_eq!(wallet.signs.lock().unwrap().len(), 1);
        assert_eq!(wallet.aborts.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_signed_result_naming_another_txid_is_refused_in_the_recorded_words_341() {
    let (store, wallet) = setup(false, KVStoreConfig::default()).await;
    *wallet.sign_mode.lock().unwrap() = "txid_mismatch";
    let error = store.set("two").await.unwrap_err();
    // completeBoundAction.ts:1140-1145 at the recording's ts-stack@edf6e03 pin.
    assert_eq!(
        error,
        bsv_rs::Error::KvStoreError(
            "Wallet signed transaction ID does not match its transaction data".into()
        )
    );
    assert_eq!(wallet.signs.lock().unwrap().len(), 1);
    assert_eq!(wallet.aborts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_missing_signed_transaction_is_refused_in_the_recorded_words_341() {
    let fixture = vector();
    let expected = &fixture["refusals"]["missing_signed_tx"];
    for global in [false, true] {
        let (store, wallet) = setup(global, KVStoreConfig::default()).await;
        let error = store.set("two").await.unwrap_err();
        assert_eq!(
            error,
            bsv_rs::Error::KvStoreError(expected["error"].as_str().unwrap().into()),
            "{global}: missing signed transaction words"
        );
        assert_eq!(
            wallet.signs.lock().unwrap().len(),
            expected["sign_calls"].as_u64().unwrap() as usize,
            "{global}: sign calls"
        );
        assert_eq!(
            wallet.aborts.lock().unwrap().len(),
            expected["abort_calls"].as_u64().unwrap() as usize,
            "{global}: abort calls"
        );
    }
}

#[tokio::test]
async fn a_valid_signed_result_supplies_the_completed_transaction_id_341() {
    let (store, wallet) = setup(false, KVStoreConfig::default()).await;
    *wallet.sign_mode.lock().unwrap() = "valid";
    let outpoint = store.set("two").await.unwrap();
    assert!(outpoint.ends_with(".0"));
    assert!(wallet.aborts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_wallet_cannot_inflate_or_redirect_the_requested_input_value_341() {
    for global in [false, true] {
        for mode in ["inflation", "unrequested_output"] {
            let (store, wallet) = setup(global, KVStoreConfig::default()).await;
            *wallet.create_mode.lock().unwrap() = mode;
            let error = store.remove().await.unwrap_err();
            assert_eq!(
                error,
                bsv_rs::Error::KvStoreError(
                    vector()["refusals"][mode]["error"].as_str().unwrap().into()
                )
            );
            assert!(wallet.signs.lock().unwrap().is_empty());
        }
    }
}
