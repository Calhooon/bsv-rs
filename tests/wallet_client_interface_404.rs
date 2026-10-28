//! The client core needs only `wallet`, and a client is itself a wallet (#404).
//! Every call through a client wrapping another client reaches the recording
//! wallet with its configured originator, without discovering a transport.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions
#![cfg(feature = "wallet")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/wallet_client_calls.rs"]
mod wallet_client_calls;

use std::sync::Arc;

use bsv_rs::wallet::*;
use identity_reveal_wallet::Counting;
use wallet_client_calls::{call_every_method, from, received};

#[tokio::test]
async fn a_client_is_a_wallet_and_every_call_reaches_the_bottom_with_its_originator() {
    for originator in [None, Some(""), Some("bottom.example")] {
        let wallet = Counting::new();
        let inner =
            WalletClient::with_substrate(Arc::new(wallet.clone()), originator.map(str::to_owned));
        let mut outer = WalletClient::with_substrate(Arc::new(inner), Some("outer.example".into()));

        call_every_method(&mut outer).await;

        assert_eq!(wallet.calls(), received());
        assert_eq!(
            wallet.originators(),
            vec![originator.map(str::to_owned); 28]
        );
    }
}

#[tokio::test]
async fn the_trait_keeps_its_status_shapes_and_the_clients_configured_originator() {
    let wallet = Counting::new();
    let client = WalletClient::with_substrate(Arc::new(wallet.clone()), None);
    let wallet_interface: &dyn WalletInterface = &client;
    let caller = Some("caller.example");

    assert!(
        wallet_interface
            .is_authenticated(caller)
            .await
            .unwrap()
            .authenticated
    );
    assert!(
        wallet_interface
            .wait_for_authentication(caller)
            .await
            .unwrap()
            .authenticated
    );
    assert_eq!(wallet_interface.get_height(caller).await.unwrap().height, 0);
    assert_eq!(
        wallet_interface.get_network(caller).await.unwrap().network,
        Network::Mainnet
    );
    assert_eq!(
        wallet_interface.get_version(caller).await.unwrap().version,
        format!("bsv-rs-{}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(wallet.originators(), vec![None; 5]);
}

#[tokio::test]
async fn the_trait_validates_internalize_before_forwarding_and_preserves_refusals() {
    let wallet = Counting::new();
    let client = WalletClient::with_substrate(Arc::new(wallet.clone()), None);
    let args = from(serde_json::json!({
        "tx": [1], "description": "invalid remittance", "outputs": [{
            "outputIndex": 0, "protocol": "basket insertion",
            "insertionRemittance": {"basket": "b"},
            "paymentRemittance": {
                "derivationPrefix": "", "derivationSuffix": "", "senderIdentityKey": ""
            }
        }]
    }));
    let error = WalletInterface::internalize_action(&client, args, None)
        .await
        .unwrap_err();
    assert!(matches!(error, bsv_rs::Error::WalletRefusal { .. }));
    assert!(wallet.calls().is_empty());

    let args =
        from(serde_json::json!({ "basket": "b", "output": format!("{}.0", "00".repeat(32)) }));
    let expected = WalletInterface::relinquish_output(&ProtoWallet::new(None), args, None)
        .await
        .unwrap_err();
    let args =
        from(serde_json::json!({ "basket": "b", "output": format!("{}.0", "00".repeat(32)) }));
    assert_eq!(
        WalletInterface::relinquish_output(&client, args, None)
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(wallet.calls(), ["relinquish_output"]);
}
