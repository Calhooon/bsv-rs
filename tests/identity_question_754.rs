//! #754: `IdentityClient::discover_certificates` asks `ls_identity`
//! `{ identityKey }`, a question the reference overlay's allowlist admits.
//! Until #754 it sent `{ identityKey, certificatesOnly: true }`, and the
//! reference's lookup service refuses the whole question for the
//! `certificatesOnly` key (no live overlay; the lines read at
//! `ts-stack@edf6e03`):
//!
//! `packages/overlays/topics/src/identity/IdentityLookupService.ts:74-82`:
//!
//! ```text
//! const rawQuery = requireLookupQuery(question, 'ls_identity', [
//!   'attributes',
//!   'certifiers',
//!   'identityKey',
//!   'certificateTypes',
//!   'serialNumber',
//!   'limit',
//!   'offset'
//! ])
//! ```
//!
//! `packages/overlays/topics/src/shared/queryValidation.ts:35-38`:
//!
//! ```text
//! const allowed = new Set(allowedKeys)
//! for (const key of Reflect.ownKeys(query)) {
//!   if (typeof key !== 'string' || unsafeKeys.has(key) || !allowed.has(key)) {
//!     invalid(`unexpected field ${String(key)}`)
//! ```
//!
//! The reference wallet's `discoverByIdentityKey`, the door this one stands
//! for, asks `{ identityKey: args.identityKey, certifiers }`
//! (`packages/wallet/wallet-toolbox/src/Wallet.ts:992,1004`), its certifiers
//! the wallet's trust settings (`WalletSettingsManager.ts:160-178`: Metanet
//! Trust Services and SocialCert by default). This crate has no trust
//! settings (the trust step unported, #739), so it names no certifier: the
//! key alone reaches `findByIdentityKey` with no certifier filter
//! (`IdentityLookupService.ts:144-145`, `IdentityStorageManager.ts:285-301`),
//! where naming SocialCert alone would drop the certificates of the
//! reference's other default certifier. The recording facilitator below (the
//! #752 file's) keeps every question it is asked and answers an empty list.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator,
};
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const KEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const TYPE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

/// The reference overlay's `ls_identity` allowlist (`IdentityLookupService.ts:74-82`).
const ALLOWED: [&str; 7] = [
    "attributes",
    "certifiers",
    "identityKey",
    "certificateTypes",
    "serialNumber",
    "limit",
    "offset",
];

/// A facilitator recording each question's query.
struct Recording(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        assert_eq!(question.service, "ls_identity");
        self.0.lock().unwrap().push(question.query.clone());
        Ok(LookupAnswer::OutputList { outputs: vec![] })
    }
}

/// A client whose one `ls_identity` host is `host`: the host reputation
/// tracker is process-wide and keyed by the URL, so each client of a test
/// binary takes a host of its own.
fn client(host: &str) -> (IdentityClient<ProtoWallet>, Arc<Mutex<Vec<Value>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording(asked.clone()))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec![format!("https://{host}.invalid")],
        )])),
        ..Default::default()
    }));
    (
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver),
        asked,
    )
}

/// The keys of `query` the reference overlay's allowlist refuses.
fn refused_by_the_reference_allowlist(query: &Value) -> Vec<String> {
    query
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| !ALLOWED.contains(&k.as_str()))
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_discovery_by_identity_key_asks_without_certificates_only_754() {
    let (client, asked) = client("discover");
    assert!(client.discover_certificates(KEY).await.unwrap().is_empty());
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked, vec![json!({ "identityKey": KEY })]);
    assert_eq!(
        refused_by_the_reference_allowlist(&asked[0]),
        Vec::<String>::new()
    );
}

/// Every lookup question of the identity client's by-key and by-type doors
/// is admitted by the reference allowlist (after #752 and #754); each door
/// on a client of its own, as the resolver backs a host off after an empty
/// answer.
#[tokio::test]
async fn every_by_key_question_is_admitted_by_the_reference_allowlist_754() {
    let mut asked = Vec::new();
    let (door, record) = client("census-discover");
    assert!(door.discover_certificates(KEY).await.unwrap().is_empty());
    asked.extend(record.lock().unwrap().clone());
    let (door, record) = client("census-by-type");
    assert!(door
        .discover_certificates_by_type(KEY, TYPE)
        .await
        .unwrap()
        .is_empty());
    asked.extend(record.lock().unwrap().clone());
    let (door, record) = client("census-resolve");
    assert!(door
        .resolve_by_identity_key(KEY, false)
        .await
        .unwrap()
        .is_none());
    asked.extend(record.lock().unwrap().clone());
    let (door, record) = client("census-query");
    let mut query = IdentityQuery::by_identity_key(KEY);
    query.certificate_type = Some(TYPE.to_string());
    query.limit = Some(5);
    query.offset = Some(2);
    assert!(door.query(query).await.unwrap().is_empty());
    asked.extend(record.lock().unwrap().clone());
    assert_eq!(asked.len(), 4);
    for question in &asked {
        assert_eq!(
            refused_by_the_reference_allowlist(question),
            Vec::<String>::new(),
            "{question}"
        );
    }
}
