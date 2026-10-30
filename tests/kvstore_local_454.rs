//! #454: full local pages and authentication before a read or a mutation.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_tokens_343.rs"]
mod support;
use support::{setup, Store};

#[tokio::test]
async fn local_set_reads_beyond_the_old_ten_output_page_454() {
    let h = setup(false, 11).await;
    *h.wallet.paginate.lock().unwrap() = true;
    h.store.set("two").await;
    assert_eq!(
        h.wallet.list_args.lock().unwrap().last().unwrap().limit,
        Some(10_000)
    );
    support::assert_spends(&h);
}

#[tokio::test]
async fn local_get_rejects_a_hidden_second_output_454() {
    let h = setup(false, 1).await;
    h.wallet
        .listed
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .total_outputs = 2;
    if let Store::Local(store) = &h.store {
        assert_eq!(
            store.get("alpha", "missing").await.unwrap_err().to_string(),
            "Multiple KVStore outputs make the current value ambiguous; call set to collapse them"
        );
    }
}

#[tokio::test]
async fn local_set_rejects_an_incomplete_collapse_page_454() {
    let h = setup(false, 2).await;
    h.wallet
        .listed
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .total_outputs = 3;
    if let Store::Local(store) = &h.store {
        assert_eq!(
            store
                .set("alpha", "two", None)
                .await
                .unwrap_err()
                .to_string(),
            "Wallet did not return every KVStore output needed for an atomic collapse"
        );
    }
}

#[tokio::test]
async fn every_local_output_is_authenticated_before_set_and_remove_454() {
    for remove in [false, true] {
        for corruption in [
            "signature",
            "key",
            "satoshis",
            "spendable",
            "script",
            "duplicate",
            "missing_beef",
        ] {
            let h = setup(false, 2).await;
            corrupt(&h, corruption);
            let Store::Local(store) = &h.store else {
                unreachable!()
            };
            let calls = h.wallet.creates.lock().unwrap().len();
            let error = if remove {
                store.remove("alpha", None).await.map(|_| ())
            } else {
                store.set("alpha", "two", None).await.map(|_| ())
            }
            .unwrap_err();
            assert!(
                error.to_string().contains(match corruption {
                    "signature" => "Signature is not valid",
                    "key" => "KVStore token locking key does not belong to the wallet",
                    "satoshis" | "script" => "KVStore BEEF does not match the listed output",
                    "spendable" => "Wallet returned invalid KVStore output metadata",
                    "duplicate" => "Wallet returned a duplicate KVStore output",
                    _ => "Wallet KVStore BEEF is invalid",
                }),
                "{corruption}: {error}"
            );
            assert_eq!(
                h.wallet.creates.lock().unwrap().len(),
                calls,
                "no action before authentication"
            );
        }
    }
}

fn corrupt(h: &support::Harness, kind: &str) {
    use bsv_rs::{primitives::PrivateKey, script::templates::PushDrop, transaction::Beef};
    let mut listing = h.wallet.listed.lock().unwrap();
    let list = listing.as_mut().unwrap();
    match kind {
        "signature" | "key" => {
            let mut tx = h.sources[0].0.clone();
            let index = h.sources[0].1 as usize;
            let mut token = PushDrop::decode(&tx.outputs[index].locking_script).unwrap();
            if kind == "signature" {
                token.fields[0] = b"forged".to_vec();
            } else {
                token.locking_public_key =
                    PrivateKey::from_hex(&"08".repeat(32)).unwrap().public_key();
            }
            tx.outputs[index].locking_script = token.lock();
            tx.invalidate_caches();
            list.outputs[0].outpoint =
                bsv_rs::wallet::Outpoint::from_string(&format!("{}.{index}", tx.id())).unwrap();
            list.outputs[0].locking_script = Some(tx.outputs[index].locking_script.to_binary());
            let mut beef = Beef::new();
            beef.merge_transaction(tx);
            beef.merge_transaction(h.sources[1].0.clone());
            list.beef = Some(beef.to_binary());
        }
        "satoshis" => list.outputs[0].satoshis += 1,
        "spendable" => list.outputs[0].spendable = false,
        "script" => list.outputs[0].locking_script = Some(vec![0x51]),
        "duplicate" => list.outputs[1] = list.outputs[0].clone(),
        _ => list.beef = None,
    }
}

#[tokio::test]
async fn local_authentication_uses_beef_when_listing_omits_the_script_454() {
    let h = setup(false, 1).await;
    h.wallet.listed.lock().unwrap().as_mut().unwrap().outputs[0].locking_script = None;
    if let Store::Local(store) = &h.store {
        assert_eq!(store.get("alpha", "missing").await.unwrap(), "one");
    }
}

#[tokio::test]
async fn local_remove_continues_until_the_reported_total_is_consumed_454() {
    let h = setup(false, 3).await;
    let complete = h.wallet.listed.lock().unwrap().clone().unwrap();
    let mut page = complete.clone();
    page.outputs.truncate(2);
    let mut tail = complete;
    tail.outputs.drain(..2);
    tail.total_outputs = 1;
    h.wallet.list_answers.lock().unwrap().extend([page, tail]);
    let mut wallet = h.wallet.clone();
    wallet.create_from_request = true;
    *wallet.sign_mode.lock().unwrap() = "valid";
    let store =
        bsv_rs::kvstore::LocalKVStore::new(wallet, bsv_rs::kvstore::KVStoreConfig::default())
            .unwrap();
    assert_eq!(store.remove("alpha", None).await.unwrap().len(), 2);
    let creates = h.wallet.creates.lock().unwrap();
    assert_eq!(creates[creates.len() - 2].inputs.as_ref().unwrap().len(), 2);
    assert_eq!(creates.last().unwrap().inputs.as_ref().unwrap().len(), 1);
    assert!(h
        .wallet
        .list_args
        .lock()
        .unwrap()
        .iter()
        .rev()
        .take(2)
        .all(|args| args.limit == Some(10_000)));
}

#[tokio::test]
async fn local_output_total_above_the_reference_bound_is_refused_454() {
    let h = setup(false, 1).await;
    h.wallet
        .listed
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .total_outputs = 10_001;
    let Store::Local(store) = &h.store else {
        unreachable!()
    };
    for result in [
        store.get("alpha", "missing").await.map(|_| ()),
        store.remove("alpha", None).await.map(|_| ()),
    ] {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Wallet returned an invalid KVStore output list"));
    }
}

#[tokio::test]
async fn local_removal_authenticates_without_decrypting_the_value_454() {
    use bsv_rs::primitives::from_hex;
    use bsv_rs::transaction::Transaction;
    use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
    let h = setup(false, 0).await;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap();
    let source = Transaction::from_beef(
        &from_hex(fixture["runs"][0]["sources"][0].as_str().unwrap()).unwrap(),
        None,
    )
    .unwrap();
    *h.wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: Some(source.to_beef(true).unwrap()),
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            satoshis: source.outputs[0].satoshis.unwrap(),
            locking_script: Some(source.outputs[0].locking_script.to_binary()),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: None,
        }],
    });
    *h.wallet.spending.lock().unwrap() = Some(source);
    let Store::Local(store) = &h.store else {
        unreachable!()
    };
    assert!(
        store.get("alpha", "missing").await.is_err(),
        "plaintext is not encrypted data"
    );
    assert!(
        store.remove("alpha", None).await.is_err(),
        "wallet deliberately omits signed result"
    );
    assert_eq!(
        h.wallet.signs.lock().unwrap().len(),
        1,
        "removal reaches signAction without decryption"
    );
}

#[tokio::test]
async fn local_removal_refuses_a_previously_consumed_page_454() {
    let h = setup(false, 2).await;
    let mut page = h.wallet.listed.lock().unwrap().clone().unwrap();
    page.total_outputs = 3;
    let mut repeated = page.clone();
    repeated.total_outputs = 2; // Pass #483's shrinking guard to test duplicate authentication.
    h.wallet
        .list_answers
        .lock()
        .unwrap()
        .extend([page, repeated]);
    let mut wallet = h.wallet.clone();
    wallet.create_from_request = true;
    *wallet.sign_mode.lock().unwrap() = "valid";
    let store =
        bsv_rs::kvstore::LocalKVStore::new(wallet, bsv_rs::kvstore::KVStoreConfig::default())
            .unwrap();
    assert_eq!(
        store.remove("alpha", None).await.unwrap_err().to_string(),
        "Wallet repeated a KVStore output after it was removed"
    );
    assert_eq!(h.wallet.signs.lock().unwrap().len(), 1);
}
