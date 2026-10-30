//! #467: counts and caller-selected pages retain totals above u32::MAX.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::kvstore::{KVStoreConfig, KVStoreQuery, LocalKVStore};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use identity_reveal_wallet::Counting;
use serde_json::json;

fn wide_page(page: ListOutputsResult, total: u64) -> ListOutputsResult {
    let mut value = serde_json::to_value(page).unwrap();
    value["totalOutputs"] = json!(total);
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn kvstore_count_retains_wide_total_or_checks_platform_467() {
    let wallet = Counting::of_scalar(9);
    let store = LocalKVStore::new(wallet.clone(), KVStoreConfig::default()).unwrap();
    for total in [1_u64 << 32, (1 << 53) - 1] {
        *wallet.listed.lock().unwrap() =
            Some(serde_json::from_value(json!({"totalOutputs": total, "outputs": []})).unwrap());
        let result = store.count().await;
        match usize::try_from(total) {
            Ok(expected) => assert_eq!(result.unwrap(), expected),
            Err(_) => assert_eq!(
                result.unwrap_err(),
                bsv_rs::Error::KvStoreLocalError(
                    "Wallet KVStore output total exceeds the platform".into()
                )
            ),
        }
    }
}

#[tokio::test]
async fn kvstore_pages_with_wide_total_keep_each_requested_page_467() {
    let wallet = Counting::of_scalar(9);
    let store = LocalKVStore::new(
        wallet.clone(),
        KVStoreConfig {
            encrypt: false,
            ..Default::default()
        },
    )
    .unwrap();
    let key = PrivateKey::from_bytes(&[1; 32]).unwrap().public_key();
    let total = (1 << 32) + 1;
    for index in [0, 1] {
        // The existing convenience listing reads the legacy five-field token.
        let script = PushDrop::new(
            key.clone(),
            vec![
                b"kvstore".to_vec(),
                b"alpha".to_vec(),
                format!("page {index}").into_bytes(),
                key.to_compressed().to_vec(),
                vec![1],
            ],
        )
        .lock();
        let page = ListOutputsResult {
            total_outputs: 1,
            beef: None,
            outputs: vec![WalletOutput {
                outpoint: Outpoint::new([1; 32], index),
                satoshis: 1,
                locking_script: Some(script.to_binary()),
                spendable: true,
                custom_instructions: None,
                tags: None,
                labels: None,
            }],
        };
        wallet
            .list_answers
            .lock()
            .unwrap()
            .push_back(wide_page(page, total));
    }
    for skip in [0, 1] {
        let entries = store
            .list(Some(KVStoreQuery {
                limit: Some(1),
                skip: Some(skip),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "alpha");
        assert_eq!(entries[0].value, format!("page {skip}"));
    }
    let calls = wallet.list_args.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!((calls[0].limit, calls[0].offset), (Some(1), Some(0)));
    assert_eq!((calls[1].limit, calls[1].offset), (Some(1), Some(1)));
}
