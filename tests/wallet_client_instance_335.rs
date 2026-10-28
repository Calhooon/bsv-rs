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
#![cfg(feature = "wallet")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/wallet_client_calls.rs"]
mod wallet_client_calls;

use std::sync::Arc;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::*;
use identity_reveal_wallet::Counting;
use serde_json::json;
use wallet_client_calls::{call_every_method, from, received};

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
    let client = WalletClient::with_substrate(Arc::new(wallet), None);

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
