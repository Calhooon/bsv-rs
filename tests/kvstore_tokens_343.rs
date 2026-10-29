//! #343: every authenticated current token is consumed, with its own BEEF and signer.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_tokens_343.rs"]
mod support;
use support::{assert_spends, setup, Store};

#[tokio::test]
async fn global_set_spends_every_current_token_343() {
    let h = setup(true, 2).await;
    h.store.set("two").await;
    assert_spends(&h);
}

#[tokio::test]
async fn global_remove_spends_every_current_token_343() {
    let h = setup(true, 2).await;
    h.store.remove().await;
    assert_spends(&h);
}

#[tokio::test]
async fn local_set_spends_every_current_token_343() {
    let h = setup(false, 2).await;
    h.store.set("two").await;
    assert_spends(&h);
}

#[tokio::test]
async fn local_remove_spends_every_current_token_343() {
    let h = setup(false, 2).await;
    h.store.remove().await;
    assert_spends(&h);
}

#[tokio::test]
async fn a_single_current_token_keeps_one_input_and_unlocker_343() {
    for global in [false, true] {
        for remove in [false, true] {
            let h = setup(global, 1).await;
            if remove {
                h.store.remove().await
            } else {
                h.store.set("two").await
            }
            assert_spends(&h);
        }
    }
}

#[tokio::test]
async fn local_same_value_collapses_multiple_tokens_343() {
    let h = setup(false, 2).await;
    if let Store::Local(store) = &h.store {
        let _ = store.set("alpha", "one", None).await;
    }
    assert_spends(&h);
}

#[tokio::test]
async fn a_single_local_unchanged_value_keeps_its_outpoint_343() {
    let h = setup(false, 1).await;
    let calls = h.wallet.creates.lock().unwrap().len();
    if let Store::Local(store) = &h.store {
        let outpoint = store.set("alpha", "one", None).await.unwrap();
        assert_eq!(outpoint, format!("{}.0", h.sources[0].0.id()));
    }
    assert_eq!(h.wallet.creates.lock().unwrap().len(), calls);
}

#[tokio::test]
async fn global_mutations_only_spend_authenticated_exact_namespace_tokens_343() {
    for remove in [false, true] {
        let h = setup(true, 2).await;
        let unrelated = support::unrelated_tokens().await;
        h.lookup.lock().unwrap().extend(unrelated);
        let mut invalid = h.sources[0].0.clone();
        let script = &invalid.outputs[0].locking_script;
        let mut token = bsv_rs::script::templates::PushDrop::decode(script).unwrap();
        token.fields[2] = b"forged".to_vec();
        invalid.outputs[0].locking_script = token.lock();
        invalid.invalidate_caches();
        h.lookup
            .lock()
            .unwrap()
            .push(bsv_rs::overlay::OutputListItem {
                beef: invalid.to_beef(true).unwrap(),
                output_index: 0,
                context: None,
            });
        if remove {
            h.store.remove().await
        } else {
            h.store.set("two").await
        }
        assert_spends(&h);
    }
}

#[tokio::test]
async fn repeated_lookup_outpoints_have_one_input_and_unlocker_343() {
    for remove in [false, true] {
        let h = setup(true, 2).await;
        let duplicate = h.lookup.lock().unwrap()[0].clone();
        h.lookup.lock().unwrap().push(duplicate);
        if remove {
            h.store.remove().await
        } else {
            h.store.set("two").await
        }
        assert_spends(&h);
    }
}

#[tokio::test]
async fn global_tokens_use_the_reference_signing_key_and_fields_343() {
    let h = setup(true, 1).await;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("vectors/kvstore_tags_344.json")).unwrap();
    let created = h.wallet.created.lock().unwrap();
    let output = &created.as_ref().unwrap().outputs.as_ref().unwrap()[0];
    assert_eq!(
        bsv_rs::primitives::to_hex(&output.locking_script),
        fixture["cases"][0]["script"].as_str().unwrap()
    );
}

#[tokio::test]
async fn global_mutations_query_the_exact_reference_namespace_343() {
    let h = setup(true, 2).await;
    h.store.remove().await;
    let questions = h.questions.lock().unwrap();
    let question = questions.last().unwrap();
    assert_eq!(
        question.query,
        serde_json::json!({
            "key": "alpha", "controller": "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
            "protocolID": [1, "kvstore"]
        })
    );
}
