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
//!
//! #907 (the strength read's two blind spots and its inputs left): the
//! facilitator records the hosts in the order they were asked, and each
//! case asserts it, since the counts of a displaced liar are also the counts
//! of a liar dropped behind an honest copy merged ahead of it, so without
//! the order the displacement was reached through the rank's tie-break
//! unasserted; and the cases no test served: a hintless and an upper-case
//! honest copy displacing, the honest host ahead of the liar, two liars,
//! and the displacement under the four other doors.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_730.rs"]
mod build;

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::wallet::ProtoWallet;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A facilitator answering each host with its scripted outputs, the hosts
/// recorded in the order they were asked.
struct ByHost(
    HashMap<String, Vec<OutputListItem>>,
    Arc<Mutex<Vec<String>>>,
);

#[async_trait::async_trait]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> sdk::Result<LookupAnswer> {
        self.1.lock().unwrap().push(url.to_string());
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

/// A door of the identity client under test.
#[derive(Clone, Copy, Debug)]
enum Door {
    ResolveByIdentityKey,
    ResolveByAttributes,
    DiscoverCertificates,
    DiscoverCertificatesByType,
    Query,
}

/// What a lookup through a door showed: how many results it returned, the
/// hosts' names in the order asked, the resolver's count and the identity
/// client's.
#[derive(Debug, PartialEq)]
struct Seen {
    returned: usize,
    asked: Vec<String>,
    resolver: u64,
    identity: u64,
}

/// `resolve_by_identity_key` over `hosts` in rank order, each answering the
/// one output with its hint: the identities' keys, the resolver's count and
/// the identity client's.
async fn resolved(hosts: &[(&str, Option<String>)]) -> (Vec<String>, u64, u64) {
    let (identities, seen) = through(Door::ResolveByIdentityKey, hosts).await;
    (identities, seen.resolver, seen.identity)
}

/// `door` over `hosts` in rank order, each answering the one output with its
/// hint: the keys of the identities `resolve_by_identity_key` returned (none
/// for another door) and what the lookup showed.
async fn through(door: Door, hosts: &[(&str, Option<String>)]) -> (Vec<String>, Seen) {
    let built = build::build("proven_parent_absent_grandparent", None);
    let mut answers = HashMap::new();
    let mut urls = Vec::new();
    let asked = Arc::new(Mutex::new(Vec::new()));
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
        facilitator: Some(Arc::new(ByHost(answers, asked.clone()))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([("ls_identity".to_string(), urls)])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver.clone());
    let key = subject_key();
    let mut identities = Vec::new();
    let returned = match door {
        Door::ResolveByIdentityKey => {
            let found = client.resolve_by_identity_key(&key, false).await.unwrap();
            identities = found.into_iter().map(|i| i.identity_key).collect();
            identities.len()
        }
        Door::ResolveByAttributes => {
            let attributes = [("email".to_string(), "alice@example.com".to_string())];
            let found = client.resolve_by_attributes(attributes.into_iter().collect(), false);
            found.await.unwrap().len()
        }
        Door::DiscoverCertificates => client.discover_certificates(&key).await.unwrap().len(),
        Door::DiscoverCertificatesByType => client
            .discover_certificates_by_type(&key, REFERENCE_TYPE)
            .await
            .unwrap()
            .len(),
        Door::Query => client
            .query(IdentityQuery::by_identity_key(key))
            .await
            .unwrap()
            .len(),
    };
    let asked = asked
        .lock()
        .unwrap()
        .iter()
        .map(|url| {
            let name = url.strip_prefix("https://").unwrap();
            name.strip_suffix("-818.invalid").unwrap().to_string()
        })
        .collect();
    let seen = Seen {
        returned,
        asked,
        resolver: resolver.txid_hint_contradictions(),
        identity: client.txid_hint_contradictions(),
    };
    (identities, seen)
}

/// The type of #553's reference token.
const REFERENCE_TYPE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn seen(returned: usize, asked: &[&str], resolver: u64, identity: u64) -> Seen {
    Seen {
        returned,
        asked: asked.iter().map(|name| name.to_string()).collect(),
        resolver,
        identity,
    }
}

/// The liar is asked ahead of the honest host, so its copy is the one held
/// when the honest copy arrives: the order the displacement needs, read off
/// the facilitator and not taken from the rank's tie-break (#907, 5a).
#[tokio::test]
async fn the_displaced_liar_was_asked_ahead_of_the_host_that_displaces_it_907() {
    let subject_txid = build::build("proven_parent_absent_grandparent", None).subject;
    let hosts = [
        ("asked-liar", Some("33".repeat(32))),
        ("asked-honest", Some(subject_txid)),
    ];
    let (identities, shown) = through(Door::ResolveByIdentityKey, &hosts).await;
    assert_eq!(identities, [subject_key()]);
    assert_eq!(shown, seen(1, &["asked-liar", "asked-honest"], 1, 0));
}

/// The inputs the strength read left (#907, line 6): each copy that agrees
/// displaces a held liar whatever its hint's form, a liar behind a held
/// honest copy is dropped and counted by the resolver alone, and of two
/// liars the earlier is kept and read, both counted by the resolver and the
/// kept one by the parser.
#[tokio::test]
async fn a_hintless_or_upper_case_honest_copy_displaces_and_two_liars_keep_the_earlier_907() {
    let subject_txid = build::build("proven_parent_absent_grandparent", None).subject;
    let lie = || Some("33".repeat(32));
    let other_lie = || Some("44".repeat(32));

    let hosts = [("hintless-liar", lie()), ("hintless-honest", None)];
    let (_, shown) = through(Door::ResolveByIdentityKey, &hosts).await;
    assert_eq!(
        shown,
        seen(1, &["hintless-liar", "hintless-honest"], 1, 0),
        "a hintless copy displaces"
    );

    let upper = Some(subject_txid.to_ascii_uppercase());
    assert_ne!(upper.as_deref(), Some(subject_txid.as_str()));
    let hosts = [("upper-liar", lie()), ("upper-honest", upper)];
    let (_, shown) = through(Door::ResolveByIdentityKey, &hosts).await;
    assert_eq!(
        shown,
        seen(1, &["upper-liar", "upper-honest"], 1, 0),
        "an upper-case hint agrees and displaces"
    );

    let hosts = [
        ("ahead-honest", Some(subject_txid.clone())),
        ("behind-liar", lie()),
    ];
    let (_, shown) = through(Door::ResolveByIdentityKey, &hosts).await;
    assert_eq!(
        shown,
        seen(1, &["ahead-honest", "behind-liar"], 1, 0),
        "a liar behind a held honest copy: the resolver alone"
    );

    let hosts = [("earlier-liar", lie()), ("later-liar", other_lie())];
    let (_, shown) = through(Door::ResolveByIdentityKey, &hosts).await;
    assert_eq!(
        shown,
        seen(1, &["earlier-liar", "later-liar"], 2, 1),
        "two liars: both counted by the resolver, the kept one read"
    );
}

/// The displacement under the four other doors (#907, line 6): each reads
/// the merged answer, so a displaced liar is the resolver's count alone and
/// the honest copy's one certificate is returned.
#[tokio::test]
async fn a_displaced_liar_is_the_resolvers_count_alone_under_every_other_door_907() {
    let subject_txid = build::build("proven_parent_absent_grandparent", None).subject;
    for (door, name) in [
        (Door::ResolveByAttributes, "attributes"),
        (Door::DiscoverCertificates, "discover"),
        (Door::DiscoverCertificatesByType, "by-type"),
        (Door::Query, "query"),
    ] {
        let (liar, honest) = (format!("{name}-liar"), format!("{name}-honest"));
        let hosts = [
            (liar.as_str(), Some("33".repeat(32))),
            (honest.as_str(), Some(subject_txid.clone())),
        ];
        let (_, shown) = through(door, &hosts).await;
        assert_eq!(shown, seen(1, &[&liar, &honest], 1, 0), "{door:?}");
    }
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
