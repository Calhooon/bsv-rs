//! Shared client receivers match WalletInterface and the reference (#404).
//! On #335 both calls are compile errors; the replies and originators below
//! also pin forwarding without discovery or an HTTP request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions
#![cfg(feature = "wallet")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use std::sync::Arc;

use bsv_rs::wallet::WalletClient;
use identity_reveal_wallet::Counting;

#[tokio::test]
async fn shared_and_arc_clients_forward_with_the_configured_originator() {
    let wallet = Counting::new();
    let client =
        WalletClient::with_substrate(Arc::new(wallet.clone()), Some("shared.example".into()));
    let expected = format!("bsv-rs-{}", env!("CARGO_PKG_VERSION"));

    let shared: &WalletClient = &client;
    assert_eq!(shared.get_version().await.unwrap(), expected);

    let shared = Arc::new(client);
    assert_eq!(shared.get_version().await.unwrap(), expected);
    assert_eq!(wallet.calls(), ["get_version", "get_version"]);
    assert_eq!(wallet.originators(), vec![Some("shared.example".into()); 2]);
}
