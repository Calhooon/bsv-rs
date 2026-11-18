//! GlobalKVStore selector queries enforce the query's controller, protocol and
//! tags against the overlay resolver's answer.
//!
//! An overlay lookup host is the untrusted-answer source of the GlobalKVStore
//! model (the token-authentication advisories): token fields are
//! controller-signed, so the host cannot forge a token, but it can answer a
//! selector query with any real, validly-signed token of any controller or
//! tags. The reference drops a returned entry that does not satisfy the query
//! before handing it to the caller (`ts-stack@edf6e03`
//! `packages/sdk/src/kvstore/GlobalKVStore.ts:601` guards the push with
//! `#entryMatchesQuery`, `:663-685`: a controller mismatch (case-insensitive),
//! a protocolID mismatch, or tags that do not satisfy the all/any mode).
//!
//! These tests inject such a host hermetically
//! (`GlobalKVStore::with_resolver` + a canned `OverlayLookupFacilitator` +
//! `host_overrides`, no network) and check that a non-matching entry is
//! dropped, an honest (matching) entry is kept, and a key-only `get` is
//! unchanged (a key-only query carries no controller selector).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code
#![cfg(feature = "kvstore")]

use std::collections::HashMap;
use std::sync::Arc;

use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionOutput};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
};
use bsv_rs::{Error, Result};

/// A lookup facilitator that returns whatever it is handed, standing in for a
/// malicious or compromised overlay host (the resolver asks it per host in the
/// `host_overrides` list; nothing is sent over the network).
struct CannedHost {
    outputs: Vec<OutputListItem>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for CannedHost {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.outputs.clone(),
        })
    }
}

/// The reference's signed GlobalKVStore token (#544): `[1, protocol]` as JSON,
/// the key, the value, the controller, the optional tags, then the
/// controller's signature over them for `anyone`, locked with its key for
/// `anyone`, as `GlobalKVStore.ts` writes it; the interpreter reads no other.
fn signed_token(
    protocol_id: &str,
    key: &str,
    value: &str,
    controller: &PrivateKey,
    tags: Option<Vec<String>>,
) -> LockingScript {
    let protocol = Protocol::new(SecurityLevel::App, protocol_id);
    let mut fields = vec![
        serde_json::to_vec(&(1, protocol_id)).unwrap(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.public_key().to_compressed().to_vec(),
    ];
    if let Some(tags) = tags {
        fields.push(serde_json::to_vec(&tags).unwrap());
    }
    let signature = ProtoWallet::new(Some(controller.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key.into(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = KeyDeriver::new(Some(controller.clone()))
        .derive_public_key(&protocol, key, &Counterparty::Anyone, true)
        .unwrap();
    PushDrop::new(lock, fields).lock()
}

/// Wrap a locking script as one atomic-BEEF output and its txid.
fn one_output(script: LockingScript) -> (Vec<u8>, String) {
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let beef = tx.to_beef(true).unwrap();
    (beef, tx.id())
}

/// Build a canned `OutputListItem` for one BEEF output. Its txid hint is the
/// BEEF's own subject so the resolver's merge keeps it; isolated here because
/// the struct's hint field is prerelease-only.
fn canned_item(beef: Vec<u8>, subject_txid: &str) -> OutputListItem {
    OutputListItem {
        beef,
        output_index: 0,
        context: None,
        txid: Some(subject_txid.to_string()),
    }
}

/// A store whose resolver asks only the canned host, for the kvstore service.
fn store_with(outputs: Vec<OutputListItem>) -> GlobalKVStore<ProtoWallet> {
    let config = KVStoreConfig::default();
    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        config.service_name.clone(),
        vec!["http://host.invalid".to_string()],
    );
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(CannedHost { outputs })),
        slap_trackers: Some(Vec::new()),
        host_overrides: Some(host_overrides),
        ..Default::default()
    });
    // The store's own wallet is the caller (alice); it is unused on the read path.
    let alice = ProtoWallet::new(Some(PrivateKey::from_bytes(&[1u8; 32]).unwrap()));
    GlobalKVStore::with_resolver(alice, config, NetworkPreset::Local, resolver)
}

fn alice_key() -> PrivateKey {
    PrivateKey::from_bytes(&[1u8; 32]).unwrap()
}

fn mallory_key() -> PrivateKey {
    PrivateKey::from_bytes(&[9u8; 32]).unwrap()
}

fn controller_hex(p: &PrivateKey) -> String {
    to_hex(&p.public_key().to_compressed())
}

// ===========================================================================
// get_by_controller — the controller selector
// ===========================================================================

#[tokio::test]
async fn get_by_controller_drops_a_host_injected_other_controller_token() {
    let alice = alice_key();
    let mallory = mallory_key();
    assert_ne!(controller_hex(&alice), controller_hex(&mallory));

    // Mallory's validly-signed token, answered to a query for Alice.
    let script = signed_token("kvstore", "config", "evil-mallory-value", &mallory, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_controller(&controller_hex(&alice))
        .await
        .unwrap();
    assert!(
        entries
            .iter()
            .all(|e| !e.controller.eq_ignore_ascii_case(&controller_hex(&mallory))),
        "get_by_controller(alice) must not return mallory's token; got {entries:?}"
    );
    assert!(
        entries.is_empty(),
        "the only answered token is mallory's, so alice's query returns nothing"
    );
}

#[tokio::test]
async fn get_by_controller_keeps_the_asked_controllers_token() {
    // An honest host answers the asked controller's own token: it is kept.
    let alice = alice_key();
    let script = signed_token("kvstore", "config", "alice-value", &alice, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_controller(&controller_hex(&alice))
        .await
        .unwrap();
    assert_eq!(entries.len(), 1, "alice's own token must be returned");
    assert!(entries[0]
        .controller
        .eq_ignore_ascii_case(&controller_hex(&alice)));
    assert_eq!(entries[0].value, "alice-value");
}

// ===========================================================================
// get_by_tags — the tags selector (all / any)
// ===========================================================================

#[tokio::test]
async fn get_by_tags_all_drops_a_token_missing_a_queried_tag() {
    let alice = alice_key();
    // The token carries only "red"; the query asks for "red" AND "blue".
    let script = signed_token(
        "kvstore",
        "config",
        "v",
        &alice,
        Some(vec!["red".to_string()]),
    );
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_tags(&["red".to_string(), "blue".to_string()], Some("all"))
        .await
        .unwrap();
    assert!(
        entries.is_empty(),
        "all-mode must drop a token missing a queried tag; got {entries:?}"
    );
}

#[tokio::test]
async fn get_by_tags_all_keeps_a_token_with_every_queried_tag() {
    let alice = alice_key();
    let script = signed_token(
        "kvstore",
        "config",
        "v",
        &alice,
        Some(vec!["red".to_string(), "blue".to_string()]),
    );
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_tags(&["red".to_string(), "blue".to_string()], Some("all"))
        .await
        .unwrap();
    assert_eq!(entries.len(), 1, "a token with every queried tag is kept");
}

#[tokio::test]
async fn get_by_tags_any_drops_a_token_with_none_of_the_queried_tags() {
    let alice = alice_key();
    let script = signed_token(
        "kvstore",
        "config",
        "v",
        &alice,
        Some(vec!["green".to_string()]),
    );
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_tags(&["red".to_string(), "blue".to_string()], Some("any"))
        .await
        .unwrap();
    assert!(
        entries.is_empty(),
        "any-mode must drop a token carrying none of the queried tags; got {entries:?}"
    );
}

#[tokio::test]
async fn get_by_tags_any_keeps_a_token_with_one_queried_tag() {
    let alice = alice_key();
    let script = signed_token(
        "kvstore",
        "config",
        "v",
        &alice,
        Some(vec!["red".to_string()]),
    );
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let entries = store
        .get_by_tags(&["red".to_string(), "blue".to_string()], Some("any"))
        .await
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "any-mode keeps a token with one queried tag"
    );
}

// ===========================================================================
// query{selector} — the protocol selector without a key
// ===========================================================================

#[tokio::test]
async fn query_with_a_protocol_selector_drops_a_token_of_another_protocol() {
    let alice = alice_key();
    // Token minted under protocol "kvstore"; the query asks for "otherproto".
    let script = signed_token("kvstore", "config", "v", &alice, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let query = KVStoreQuery::new().with_protocol_id("otherproto");
    let entries = store.query(query).await.unwrap();
    assert!(
        entries.is_empty(),
        "a protocol selector must drop a token of another protocol; got {entries:?}"
    );
}

#[tokio::test]
async fn query_with_a_matching_protocol_selector_keeps_the_token() {
    let alice = alice_key();
    let script = signed_token("kvstore", "config", "v", &alice, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let query = KVStoreQuery::new().with_protocol_id("kvstore");
    let entries = store.query(query).await.unwrap();
    assert_eq!(entries.len(), 1, "the matching protocol keeps the token");
}

// ===========================================================================
// get(key) — key-only: no controller selector, so unchanged by the fix.
// ===========================================================================

#[tokio::test]
async fn get_key_only_returns_any_controllers_token() {
    // A key-only `get` carries no controller selector, so a host's
    // any-controller token for the key is returned. This pins that the fix
    // does not over-reach onto the key-only door.
    let mallory = mallory_key();
    let script = signed_token("kvstore", "config", "mallory-value", &mallory, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    let got = store.get("config", None).await.unwrap();
    assert!(got.is_some(), "key-only get returns the matching-key token");
    assert_eq!(got.unwrap().value, "mallory-value");
}

// ===========================================================================
// the internal existing-token lookup (remove) — a wrong-controller token is
// not adopted. remove queries key+controller(=caller's own identity); a
// host's other-controller token must not be taken as the caller's existing
// token. (Reachable on the stable line, where the internal lookup has no
// post-filter; the prerelease line already post-filters the controller.)
// ===========================================================================

#[tokio::test]
async fn remove_does_not_adopt_a_host_injected_other_controller_token() {
    // The store's wallet is alice; remove("config") looks up alice's own
    // existing token. The host answers only mallory's (validly signed) token.
    let mallory = mallory_key();
    let script = signed_token("kvstore", "config", "mallory-value", &mallory, None);
    let (beef, txid) = one_output(script);
    let store = store_with(vec![canned_item(beef, &txid)]);

    // With the token dropped by the selector filter, remove finds no existing
    // token of the caller's and reports the key as not found, rather than
    // adopting mallory's token into a spend (which would reach create_action).
    let err = store
        .remove("config", None)
        .await
        .expect_err("remove must not adopt a wrong-controller token");
    assert!(
        matches!(err, Error::KvStoreKeyNotFound(_)),
        "expected KvStoreKeyNotFound, got {err:?}"
    );
}
