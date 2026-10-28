//! #342: additive store builders preserve config literals and the recorded options.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_bound_341_342.rs"]
mod support;
use bsv_rs::kvstore::KVStoreConfig;

#[tokio::test]
async fn enabled_store_options_reach_both_calls_as_recorded_342() {
    for global in [false, true] {
        let (store, wallet) =
            support::setup_with_options(global, KVStoreConfig::default(), Some((true, true))).await;
        support::assert_options(&wallet, global, "set_new", "enabled");
        store.set("two").await.unwrap_err();
        support::assert_options(&wallet, global, "set_update", "enabled");
        store.remove().await.unwrap_err();
        support::assert_options(&wallet, global, "remove", "enabled");
    }
}

#[tokio::test]
async fn exhaustive_config_literals_keep_the_recorded_defaults_342() {
    for global in [false, true] {
        let config = KVStoreConfig {
            protocol_id: "kvstore".into(),
            service_name: "ls_kvstore".into(),
            token_amount: 1,
            topics: vec!["tm_kvstore".into()],
            originator: None,
            encrypt: true,
        };
        let (_, wallet) = support::setup(global, config).await;
        support::assert_options(&wallet, global, "set_new", "defaults");
    }
}
