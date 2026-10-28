//! The key-value stores send signAction what the reference's send through
//! `completeBoundAction` (#326; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/completeBoundAction.ts:1111-1120`): the reference
//! as the wallet answered createAction, its base64 text, and the options
//! `{ acceptDelayedBroadcast, returnTXIDOnly: false, noSend, sendWith }`
//! carried from the createAction's, against
//! `tests/vectors/signaction_reference_326.json` (the reference's
//! `GlobalKVStore` and `LocalKVStore` updating and removing a key, recorded
//! by `tests/support/signaction_reference_326.mjs` under Node v22.18.0). The
//! four sites sent the hex of the reference's bytes and no options.
//!
//! This crate's stores send their createAction no options, so the carried
//! members are absent here where the reference's are its configuration's
//! (`acceptDelayedBroadcast: false`, the global store's `noSend: false`): a
//! stated difference, pinned below so a change to it is seen.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`)
//! lists the local store's token and answers createAction with a signable
//! transaction spending it; the global store's lookup is an injected
//! facilitator answering its token.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "kvstore")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreSetOptions, LocalKVStore};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use identity_reveal_wallet::Counting;
use serde_json::Value;
use signaction_reference_326::{assert_reference_sign, source_of, vector};
use std::sync::{Arc, Mutex};

/// Answers every lookup with the token's BEEF at output 0 once one is set,
/// an empty list before.
struct TokenLookup(Arc<Mutex<Option<Vec<u8>>>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for TokenLookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        let token = self.0.lock().unwrap().clone();
        let outputs = token.into_iter().map(|beef| OutputListItem {
            beef,
            output_index: 0,
            context: None,
        });
        Ok(LookupAnswer::OutputList {
            outputs: outputs.collect(),
        })
    }
}

/// The token output of the last createAction's first output, carried by a
/// source transaction the wallet's createAction then spends.
fn token_of(wallet: &Counting) -> Transaction {
    let created = wallet.created.lock().unwrap().take().unwrap();
    let output = &created.outputs.as_ref().unwrap()[0];
    let source = source_of(&output.locking_script, output.satoshis);
    *wallet.spending.lock().unwrap() = Some(source.clone());
    source
}

/// This crate's signAction against the reference's case, and the stated
/// difference: no createAction options here, so the options are
/// `returnTXIDOnly: false` alone. `spends_token`: whether this crate's
/// createAction spends the token, as the reference's always does; the global
/// store's `set` does not (its lookup asks for no token, so it finds none to
/// spend), a finding outside #326 pinned here.
fn assert_case(name: &str, case: &Value, wallet: &Counting, spends_token: bool) {
    let signed = wallet.signed.lock().unwrap().take().unwrap();
    let created = wallet.created.lock().unwrap().take().unwrap();
    let token = wallet.spending.lock().unwrap().clone().unwrap();
    let spent: Vec<String> = created
        .inputs
        .iter()
        .flatten()
        .map(|input| input.outpoint.to_string())
        .collect();
    let expected = spends_token.then(|| format!("{}.0", token.id()));
    assert_eq!(spent, Vec::from_iter(expected), "{name}: the inputs");
    assert_reference_sign(name, case, &signed, created.options.as_ref());
    assert!(created.options.is_none(), "{name}: the stated difference");
    assert_eq!(
        serde_json::to_value(signed.options.unwrap()).unwrap(),
        serde_json::json!({ "returnTXIDOnly": false }),
        "{name}"
    );
}

fn global_store(wallet: &Counting, token: Arc<Mutex<Option<Vec<u8>>>>) -> GlobalKVStore<Counting> {
    let config = KVStoreConfig::default();
    let mut host_overrides = std::collections::HashMap::new();
    host_overrides.insert(
        config.service_name.clone(),
        vec!["https://kvstore.overlay.invalid".to_string()],
    );
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(TokenLookup(token))),
        slap_trackers: Some(Vec::new()),
        host_overrides: Some(host_overrides),
        ..Default::default()
    });
    GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver)
}

/// A global store whose token is written (nothing found) and then found.
/// The token carries a tag as in the original #326 witness. The reader also
/// accepts untagged tokens since #344 (`kvstore_untagged_token_344.rs`).
async fn global_with_token() -> (GlobalKVStore<Counting>, Counting) {
    let wallet = Counting::of_scalar(9);
    let token = Arc::new(Mutex::new(None));
    let store = global_store(&wallet, token.clone());
    let tagged = KVStoreSetOptions::new().with_tags(vec!["t".to_string()]);
    store.set("alpha", "one", Some(tagged)).await.unwrap_err();
    let source = token_of(&wallet);
    *token.lock().unwrap() = Some(source.to_beef(true).unwrap());
    assert_eq!(
        store.get("alpha", None).await.unwrap().unwrap().value,
        "one",
        "the token is found"
    );
    (store, wallet)
}

#[tokio::test]
async fn the_global_update_signs_with_the_reference_text_and_the_bound_options() {
    let (store, wallet) = global_with_token().await;
    store.set("alpha", "two", None).await.unwrap_err();
    assert_case(
        "global set_update",
        &vector()["global"]["set_update"],
        &wallet,
        false,
    );
}

#[tokio::test]
async fn the_global_removal_signs_with_the_reference_text_and_the_bound_options() {
    let (store, wallet) = global_with_token().await;
    store.remove("alpha", None).await.unwrap_err();
    assert_case(
        "global remove",
        &vector()["global"]["remove"],
        &wallet,
        true,
    );
}

/// A local store whose token is written (nothing listed) and then listed.
async fn local_with_token() -> (LocalKVStore<Counting>, Counting) {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: Vec::new(),
        total_outputs: 0,
        beef: None,
    });
    let store = LocalKVStore::new(wallet.clone(), KVStoreConfig::default()).unwrap();
    store.set("alpha", "one", None).await.unwrap_err();
    let source = token_of(&wallet);
    let output = &source.outputs[0];
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![WalletOutput {
            satoshis: output.satoshis.unwrap(),
            locking_script: Some(output.locking_script.to_binary()),
            spendable: true,
            custom_instructions: None,
            tags: Some(vec!["alpha".to_string()]),
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            labels: None,
        }],
        total_outputs: 1,
        beef: Some(source.to_beef(true).unwrap()),
    });
    (store, wallet)
}

#[tokio::test]
async fn the_local_update_signs_with_the_reference_text_and_the_bound_options() {
    let (store, wallet) = local_with_token().await;
    store.set("alpha", "two", None).await.unwrap_err();
    assert_case(
        "local set_update",
        &vector()["local"]["set_update"],
        &wallet,
        true,
    );
}

#[tokio::test]
async fn the_local_removal_signs_with_the_reference_text_and_the_bound_options() {
    let (store, wallet) = local_with_token().await;
    store.remove("alpha", None).await.unwrap();
    assert_case("local remove", &vector()["local"]["remove"], &wallet, true);
}
