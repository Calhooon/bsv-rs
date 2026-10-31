//! #544, site 5: an advertisement is read as the reference reads it
//! (`ts-stack@edf6e03` `OverlayAdminTokenTemplate.ts`): the static decode's
//! checks in its words (`decodeAdvertisement`, `:162-196`, `:237-239`: the
//! canonical five-field envelope, the protocol, the canonical identity key,
//! the advertisement URI, the topic or service name, the signature's length
//! and canonical DER), and the author where the reference checks it
//! (`decodeAndVerifyOverlayAdvertisement`, `:198-215`), at the lookup
//! resolver's SLAP discovery (`LookupResolver.ts:2206`) and the SHIP
//! broadcaster's host discovery (`SHIPBroadcaster.ts:775`). Against the
//! overlay cases of `tests/vectors/token_envelope_544.json`
//! (`tests/support/token_envelope_544.mjs`, Node v22.18.0), with the
//! reference's verdicts on this crate's signed SHIP and SLAP advertisements.
//! Hermetic: in-process facilitators on `.invalid` hosts.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::{
    decode_and_verify_overlay_admin_token, decode_overlay_admin_token, LookupAnswer,
    LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator, Protocol,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::script::LockingScript;
use bsv_rs::Error;
use serde_json::Value;
use std::sync::Arc;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

fn script(case: &Value) -> LockingScript {
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

fn expected(case: &Value) -> Option<Protocol> {
    case["expected"].as_str().and_then(Protocol::parse)
}

fn verdict<T: std::fmt::Debug>(read: bsv_rs::Result<T>, words: &Value, name: &Value) {
    match words.as_str() {
        None => assert!(read.is_ok(), "{name}: {read:?}"),
        Some(words) => assert_eq!(
            read.unwrap_err(),
            Error::OverlayError(words.into()),
            "{name}"
        ),
    }
}

#[test]
fn an_advertisement_is_decoded_and_verified_in_the_reference_words_544() {
    let v = vector();
    let cases = v["overlay"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let lock = script(case);
        verdict(
            decode_overlay_admin_token(&lock),
            &case["decode_words"],
            &case["name"],
        );
        verdict(
            decode_and_verify_overlay_admin_token(&lock, expected(case)),
            &case["verify_words"],
            &case["name"],
        );
    }
}

#[test]
fn this_crates_advertisements_are_verified_by_the_reference_544() {
    let v = vector();
    let crate_tokens = v["overlay"]["crate"].as_array().unwrap();
    assert_eq!(crate_tokens.len(), 2);
    for token in crate_tokens {
        assert!(token["decode_words"].is_null(), "{}", token["name"]);
        assert!(token["verify_words"].is_null(), "{}", token["name"]);
        decode_and_verify_overlay_admin_token(&script(token), expected(token)).unwrap();
    }
}

/// A facilitator answering every question with one output carrying the
/// script (held as bytes).
struct Answering(Vec<u8>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![lock_position::output_of(
                LockingScript::from_binary(&self.0).unwrap(),
            )],
        })
    }
}

fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["overlay"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
}

#[tokio::test]
async fn the_slap_discovery_reads_only_an_authenticated_advertisement_544() {
    let v = vector();
    for (name, hosts) in [
        ("reference_slap", vec!["https://slap.example".to_string()]),
        ("slap_wrong_signer", vec![]),
        ("slap_wrong_lock_key", vec![]),
    ] {
        let resolver = LookupResolver::new(LookupResolverConfig {
            facilitator: Some(Arc::new(Answering(script(case(&v, name)).to_binary()))),
            slap_trackers: Some(vec![format!("https://{name}.tracker.invalid")]),
            ..Default::default()
        });
        assert_eq!(
            resolver.find_competent_hosts("ls_test").await.unwrap(),
            hosts,
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_ship_discovery_reads_only_an_authenticated_advertisement_544() {
    let v = vector();
    for (name, found) in [
        ("reference_ship", true),
        ("wrong_signer", false),
        ("wrong_lock_key", false),
    ] {
        let resolver = lock_position::answering("ls_ship", script(case(&v, name)));
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                resolver: Some(resolver),
                ..Default::default()
            },
        )
        .unwrap();
        let hosts = broadcaster.find_interested_hosts().await.unwrap();
        assert_eq!(
            hosts.contains_key("https://ship.example"),
            found,
            "{name}: {hosts:?}"
        );
    }
}
