//! #537, site 1: the identity client decodes an `ls_identity` output's token
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `IdentityClient.ts:773`, `PushDrop.decode` at its default position): a
//! lock-after token is skipped, as the reference's catch at `:823` skips it,
//! through both parsers (`resolve_by_attributes`, `discover_certificates`).
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::IdentityClient;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;

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
