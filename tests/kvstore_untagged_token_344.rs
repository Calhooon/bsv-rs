//! #344: the public store reads the reference writer's five-field token.
//! Recorded by the extended #326 recorder at ts-stack@edf6e03; no live lookup.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreContext, KVStoreInterpreter};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::LockingScript;
use identity_reveal_wallet::Counting;
use serde_json::Value;
use std::sync::Arc;

fn cases() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("vectors/kvstore_tags_344.json")).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

fn script(case: &Value) -> LockingScript {
    LockingScript::from_hex(case["script"].as_str().unwrap()).unwrap()
}

struct TokenLookup(Vec<u8>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for TokenLookup {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        assert_eq!(url, "https://kvstore-344.invalid");
        Ok(LookupAnswer::OutputList {
            outputs: vec![OutputListItem {
                beef: self.0.clone(),
                output_index: 0,
                context: None,
            }],
        })
    }
}

fn store(case: &Value) -> GlobalKVStore<Counting> {
    let config = KVStoreConfig::default();
    let source = signaction_reference_326::source_of(&script(case).to_binary(), 1);
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        host_overrides: Some(std::collections::HashMap::from([(
            config.service_name.clone(),
            vec!["https://kvstore-344.invalid".to_owned()],
        )])),
        slap_trackers: Some(Vec::new()),
        facilitator: Some(Arc::new(TokenLookup(source.to_beef(true).unwrap()))),
        ..Default::default()
    });
    GlobalKVStore::with_resolver(
        Counting::of_scalar(9),
        config,
        NetworkPreset::Local,
        resolver,
    )
}

#[test]
fn an_untagged_reference_token_keeps_its_signature_out_of_tags() {
    let case = cases().remove(0);
    assert_eq!(case["writer"], "GlobalKVStore.set");
    assert_eq!(case["fields"].as_array().unwrap().len(), 5);
    let fields = KVStoreInterpreter::extract_fields(&script(&case)).unwrap();
    assert!(fields.tags.is_none(), "field 4 is the signature, not tags");
    assert_eq!(
        fields.signature,
        Some(from_hex(case["fields"][4].as_str().unwrap()).unwrap())
    );
    assert!(KVStoreInterpreter::verify_signature(
        &fields,
        "[1,\"kvstore\"]"
    ));
    assert!(KVStoreInterpreter::interpret_script(
        &script(&case),
        Some(&KVStoreContext::new("alpha", "another namespace"))
    )
    .is_none());
}

#[tokio::test]
async fn the_global_store_reads_the_reference_writers_untagged_token() {
    let case = cases().remove(0);
    assert_eq!(case["interpreted"], "one");
    let entry = store(&case).get("alpha", None).await.unwrap();
    assert_eq!(
        entry.as_ref().map(|e| e.value.as_str()),
        Some("one"),
        "the reference writer's untagged token must be readable"
    );
    assert!(entry.unwrap().tags.is_empty());
}

#[tokio::test]
async fn the_global_store_reads_the_reference_tag_boundaries() {
    for case in cases().into_iter().filter(|c| c["error"].is_null()) {
        let entry = store(&case)
            .get("alpha", None)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{}: the reference accepts this token", case["name"]));
        assert_eq!(entry.value, case["entry"]["value"].as_str().unwrap());
        let expected: Vec<String> = case["entry"]["tags"]
            .as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        assert_eq!(entry.tags, expected, "{}", case["name"]);
    }
}

#[test]
fn an_explicit_empty_tag_field_is_kept_and_signed() {
    let case = cases()
        .into_iter()
        .find(|c| c["name"] == "explicit_empty_tags")
        .unwrap();
    let fields = KVStoreInterpreter::extract_fields(&script(&case)).unwrap();
    assert_eq!(fields.tags.as_deref(), Some(b"[]".as_slice()));
    assert!(fields.has_tags());
    assert!(KVStoreInterpreter::verify_signature(
        &fields,
        "[1,\"kvstore\"]"
    ));
}

#[tokio::test]
async fn malformed_reference_tags_are_refused_by_both_reader_paths() {
    for case in cases().into_iter().filter(|c| !c["error"].is_null()) {
        assert!(case["entry"].is_null());
        assert!(case["interpreted"].is_null());
        assert!(
            KVStoreInterpreter::interpret_script(&script(&case), None).is_none(),
            "{}",
            case["name"]
        );
        assert!(
            KVStoreInterpreter::extract_fields(&script(&case)).is_none(),
            "{}",
            case["name"]
        );
        assert!(
            store(&case).get("alpha", None).await.unwrap().is_none(),
            "{}",
            case["name"]
        );
    }
}
