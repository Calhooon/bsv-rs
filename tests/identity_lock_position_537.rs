//! #537, site 1: the identity client decodes an `ls_identity` output's token
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `IdentityClient.ts:773`, `PushDrop.decode` at its default position): a
//! lock-after token is skipped, as the reference's catch at `:823` skips it,
//! through both parsers (`resolve_by_attributes`, `discover_certificates`).
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::IdentityClient;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;

/// How many identities and certificates the two parsers return for `script`.
async fn read(script: LockingScript) -> (usize, usize) {
    let resolver = lock_position::answering("ls_identity", script);
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let certificates = client.discover_certificates("02aa").await.unwrap();
    (identities.len(), certificates.len())
}

#[tokio::test]
async fn a_lock_after_identity_token_is_skipped_as_the_reference_skips_it_537() {
    let cases = lock_position::cases("identity_client");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        assert_eq!(
            read(lock_position::script(case)).await,
            (0, 0),
            "{}",
            case["name"]
        );
    }
    // The same fields locked before were read by both parsers until #544;
    // since then the reference's authentication skips them too: the key and
    // the signature are not the subject's (`IdentityClient.ts:776-815`).
    let control = lock_position::relocked_before(&cases[0]);
    assert_eq!(read(control).await, (0, 0));
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, are skipped by both
/// parsers and by the revocation, as the reference's revocation skips them
/// (`IdentityClient.ts:773`, its canonical-script check `:130-147`, the catch
/// at `:823`): the revocation's words the reference's.
#[tokio::test]
async fn a_key_only_and_a_no_checksig_identity_token_are_skipped_as_the_reference_skips_them_618() {
    let old = lock_position::cases("identity_client");
    let cases = decode_618::cases("identity_client");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let script = decode_618::script(case, from_537(&old, case));
        assert_eq!(read(script.clone()).await, (0, 0), "{}", case["name"]);
        let resolver = lock_position::answering("ls_identity", script);
        let client =
            IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
        let serial =
            serde_json::from_str::<Value>(include_str!("vectors/certificate_field_value_261.json"))
                .unwrap()["reference_issued"]["certificate"]["serialNumber"]
                .as_str()
                .unwrap()
                .to_string();
        let words = client
            .revoke_certificate_revelation(&serial)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            words.ends_with(case["site_words"].as_str().unwrap()),
            "{}: {words}",
            case["name"]
        );
    }
}
