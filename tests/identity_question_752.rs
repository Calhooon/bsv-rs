//! #752: `IdentityClient::query` and `discover_certificates_by_type` send the
//! certificate type to `ls_identity` as `certificateTypes`, an array, beside
//! `identityKey`, as the reference overlay reads it. Until #752 both sent
//! `certificateType`, a key the reference's lookup service refuses for the
//! whole question (no live overlay; the lines read at `ts-stack@edf6e03`):
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
//! and the types read only beside the key (`IdentityLookupService.ts:136`,
//! `} else if (identityKey !== undefined && certificateTypes !== undefined) {`,
//! then `findByCertificateType`, `IdentityStorageManager.ts:315-339`). The
//! recording facilitator below keeps every question it is asked and answers
//! an empty output list.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, IdentityQuery, DEFAULT_SOCIALCERT_CERTIFIER as SOCIALCERT};
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

fn client() -> (IdentityClient<ProtoWallet>, Arc<Mutex<Vec<Value>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording(asked.clone()))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    (
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver),
        asked,
    )
}

/// Every key the reference overlay's allowlist admits.
fn admitted_by_the_reference_allowlist(query: &Value) -> bool {
    query
        .as_object()
        .unwrap()
        .keys()
        .all(|k| ALLOWED.contains(&k.as_str()))
}

#[tokio::test]
async fn a_by_type_discovery_asks_certificate_types_beside_the_identity_key_752() {
    let (client, asked) = client();
    assert!(client
        .discover_certificates_by_type(KEY, TYPE)
        .await
        .unwrap()
        .is_empty());
    let asked = asked.lock().unwrap().clone();
    assert_eq!(
        asked,
        vec![json!({ "identityKey": KEY, "certificateTypes": [TYPE] })]
    );
    assert!(admitted_by_the_reference_allowlist(&asked[0]));
}

#[tokio::test]
async fn a_query_with_a_type_asks_certificate_types_as_an_array_752() {
    let (client, asked) = client();
    let mut query = IdentityQuery::by_identity_key(KEY);
    query.certificate_type = Some(TYPE.to_string());
    query.limit = Some(5);
    query.offset = Some(2);
    assert!(client.query(query).await.unwrap().is_empty());
    let asked = asked.lock().unwrap().clone();
    assert_eq!(
        asked,
        vec![json!({
            "identityKey": KEY,
            "certificateTypes": [TYPE],
            "certifiers": [SOCIALCERT],
            "limit": 5,
            "offset": 2,
        })]
    );
    assert!(admitted_by_the_reference_allowlist(&asked[0]));
}

/// Without a type the question carries no type key, as before #752.
#[tokio::test]
async fn a_query_without_a_type_asks_no_type_key_752() {
    let (client, asked) = client();
    assert!(client
        .query(IdentityQuery::by_identity_key(KEY))
        .await
        .unwrap()
        .is_empty());
    let asked = asked.lock().unwrap().clone();
    assert_eq!(
        asked,
        vec![json!({ "identityKey": KEY, "certifiers": [SOCIALCERT] })]
    );
}
