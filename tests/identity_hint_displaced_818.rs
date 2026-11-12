//! #818: a lying hint the resolver displaces is counted by the resolver
//! alone.
//!
//! Since #796 `LookupResolver::query`'s merge lets an agreeing copy of an
//! output displace a held copy whose `txid` hint disagrees with its BEEF's
//! subject, and counts every disagreeing copy it receives
//! (`LookupResolver::txid_hint_contradictions`). The identity parsers read
//! the merged answer, so on an `ls_identity` lookup answered by a liar and
//! then an honest host the evidence check (`identity::evidence::admit`,
//! #735) never sees the liar: `IdentityClient::txid_hint_contradictions`
//! reads 0 where it read 1 before #796, and the resolver's count reads 1. A
//! lying copy the merge keeps still reaches the parser and is counted by
//! both (the control below: the liar alone); one the merge drops behind a
//! copy it already holds is, like the displaced one, counted by the resolver
//! alone. A caller that watches the identity count alone reads 0 for a
//! displaced liar: the two counters are read together through one shared
//! resolver (`IdentityClient::with_resolver`; a client built by
//! `IdentityClient::new` has no door to its resolver's count).
//!
//! The reference drops a disagreeing copy at its merge (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:1104-1112`, the compare
//! at `:2229`, `:2235`) and refuses a disagreeing hint at its evidence check
//! (`packages/sdk/src/transaction/TransactionEvidence.ts:122-125`,
//! `invalid-evidence`); it counts neither. Both counters are this crate's
//! (the owner's word on #735, 2026-11-04 13:5xZ).
//!
//! The BEEF is this crate's writer's (#730's `proven_parent_absent_grandparent`,
//! `support/identity_evidence_730.rs`: the reference's revelation token on an
//! unproven subject over a proven parent). Every host is an `.invalid` name
//! answered by a scripted facilitator, never dialled; each run has hosts of
//! its own (the reputation tracker is one global keyed by URL).
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_730.rs"]
mod build;

use bsv_rs::identity::IdentityClient;
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::wallet::ProtoWallet;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// A facilitator answering each host with its scripted outputs.
struct ByHost(HashMap<String, Vec<OutputListItem>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> sdk::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.get(url).cloned().unwrap_or_default(),
        })
    }
}

/// The token's subject key (#553's vector).
fn subject_key() -> String {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    v["subject"].as_str().unwrap().to_string()
}

/// `resolve_by_identity_key` over `hosts` in rank order, each answering the
/// one output with its hint: the identities' keys, the resolver's count and
/// the identity client's.
async fn resolved(hosts: &[(&str, Option<String>)]) -> (Vec<String>, u64, u64) {
    let built = build::build("proven_parent_absent_grandparent", None);
    let mut answers = HashMap::new();
    let mut urls = Vec::new();
    for (name, hint) in hosts {
        let url = format!("https://{name}-818.invalid");
        answers.insert(
            url.clone(),
            vec![OutputListItem {
                beef: built.beef.clone(),
                output_index: 0,
                context: None,
                txid: hint.clone(),
            }],
        );
        urls.push(url);
    }
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(ByHost(answers))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([("ls_identity".to_string(), urls)])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver.clone());
    let identities = client
        .resolve_by_identity_key(&subject_key(), false)
        .await
        .unwrap();
    (
        identities.into_iter().map(|i| i.identity_key).collect(),
        resolver.txid_hint_contradictions(),
        client.txid_hint_contradictions(),
    )
}

#[tokio::test]
async fn a_displaced_liar_is_counted_by_the_resolver_alone_818() {
    let subject_txid = build::build("proven_parent_absent_grandparent", None).subject;
    let lie = Some("33".repeat(32));
    assert_ne!(lie.as_deref(), Some(subject_txid.as_str()));

    // The control: a lying copy the merge keeps (here the only copy) reaches
    // the parser, which reads it and counts it too.
    let (identities, resolver, identity) = resolved(&[("lone-liar", lie.clone())]).await;
    assert_eq!(identities, [subject_key()]);
    assert_eq!((resolver, identity), (1, 1), "a kept liar: both");

    // The liar ranked ahead, then the honest host: the merge displaces the
    // liar's copy, the parser reads the honest one.
    let (identities, resolver, identity) = resolved(&[
        ("displaced-liar", lie),
        ("displacing-honest", Some(subject_txid)),
    ])
    .await;
    assert_eq!(identities, [subject_key()], "the honest identity");
    assert_eq!(
        (resolver, identity),
        (1, 0),
        "a displaced liar: the resolver alone"
    );
}
