//! #544, site 2: the identity client's two `ls_identity` parsers run the
//! reference's checks on a revelation token before reading its certificate
//! (`ts-stack@edf6e03` `IdentityClient.ts:773-815`: exactly two fields, the
//! canonical signed envelope, the locking key, the field signature; the key
//! and the signature the subject's, as the toolbox's discovery reads a
//! published token, `identityUtils.ts:497-559`), a token that fails skipped
//! (`IdentityClient.ts:823`). Against `tests/vectors/token_envelope_544.json`
//! (`tests/support/token_envelope_544.mjs`, Node v22.18.0): the reference's
//! own token for a certificate of the subject 9 and five one-change tokens,
//! each with the reference's verdict from its revocation's lookup loop.
//! Hermetic: an in-process resolver on an `.invalid` host.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::IdentityClient;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

/// How many identities and certificates the two parsers return for `script`.
async fn read(script: LockingScript, subject: &str) -> (usize, usize) {
    let resolver = lock_position::answering("ls_identity", script);
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let certificates = client.discover_certificates(subject).await.unwrap();
    (identities.len(), certificates.len())
}

#[tokio::test]
async fn an_identity_token_is_read_only_when_the_reference_authenticates_it_544() {
    let v = vector();
    let subject = v["identity"]["certificate"]["subject"].as_str().unwrap();
    let cases = v["identity"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let expected = match case["outcome"].as_str().unwrap() {
            "authenticated" => (1, 1),
            "skipped" => (0, 0),
            other => panic!("unexpected outcome {other}"),
        };
        assert_eq!(
            read(script, subject).await,
            expected,
            "{}: {}",
            case["name"],
            case["words"]
        );
    }
    assert_eq!(cases[0]["name"], "reference");
    assert_eq!(cases[0]["outcome"], "authenticated");
}
