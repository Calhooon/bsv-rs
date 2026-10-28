//! #342: enabled config values match the reference on both wallet calls.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_bound_341_342.rs"]
mod support;
use bsv_rs::kvstore::KVStoreConfig;

#[tokio::test]
async fn enabled_config_options_reach_both_calls_as_recorded_342() {
    for global in [false, true] {
        let config = KVStoreConfig::default()
            .with_accept_delayed_broadcast(true)
            .with_overlay_broadcast(true);
        let (store, wallet) = support::setup(global, config).await;
        support::assert_options(&wallet, global, "set_new", "enabled");
        store.set("two").await.unwrap_err();
        support::assert_options(&wallet, global, "set_update", "enabled");
        store.remove().await.unwrap_err();
        support::assert_options(&wallet, global, "remove", "enabled");
    }
}
