//! #537, site 3: the registry client decodes a definition token lock-before
//! alone, as its counterpart does (`ts-stack@edf6e03`
//! `registryTokenValidation.ts:28`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position): a lock-after token is
//! skipped by the three resolvers and by `list_own_registry_entries`, as the
//! reference's catches at `RegistryClient.ts:392` and `:445` skip it.
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;
#[path = "support/registry_token_fields_543.rs"]
mod token_fields;

use bsv_rs::registry::{
    decode_and_verify_registry_token, BasketQuery, CertificateQuery, DefinitionType, ProtocolQuery,
    RegistryClient, RegistryClientConfig,
};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use identity_reveal_wallet::Counting;
use serde_json::Value;

fn definition_type(case: &Value) -> DefinitionType {
    match case["definition_type"].as_str().unwrap() {
        "basket" => DefinitionType::Basket,
        "protocol" => DefinitionType::Protocol,
        _ => DefinitionType::Certificate,
    }
}

/// How many definitions the type's resolver and the wallet listing return
/// for `script`.
async fn read(kind: DefinitionType, script: LockingScript) -> (usize, usize) {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: None,
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", "22".repeat(32))).unwrap(),
            satoshis: 1,
            locking_script: Some(script.to_binary()),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: None,
        }],
    });
    let resolver = lock_position::answering(kind.lookup_service(), script);
    let client = RegistryClient::new(wallet, RegistryClientConfig::new().with_resolver(resolver));
    let resolved = match kind {
        DefinitionType::Basket => client
            .resolve_basket(BasketQuery::default())
            .await
            .unwrap()
            .len(),
        DefinitionType::Protocol => client
            .resolve_protocol(ProtocolQuery::default())
            .await
            .unwrap()
            .len(),
        DefinitionType::Certificate => client
            .resolve_certificate(CertificateQuery::default())
            .await
            .unwrap()
            .len(),
    };
    let listed = client.list_own_registry_entries(kind).await.unwrap().len();
    (resolved, listed)
}

#[tokio::test]
async fn a_lock_after_registry_token_is_skipped_as_the_reference_skips_it_537() {
    let cases = lock_position::cases("registry_client");
    assert_eq!(cases.len(), 6);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let kind = definition_type(case);
        assert_eq!(
            read(kind, lock_position::script(case)).await,
            (0, 0),
            "{}",
            case["name"]
        );
        if case["kind"] == "lock_after_not_a_point" {
            // The reference's own token of the type, lock-before and signed
            // (#543's vector; the unsigned relock of #537 is no token since
            // #543), is read by both paths.
            let control = token_fields::cases("tokens")
                .into_iter()
                .find(|token| token["definition_type"] == case["definition_type"])
                .unwrap();
            let control = token_fields::script(&control);
            assert_eq!(read(kind, control).await, (1, 1), "{}", case["name"]);
        }
    }
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, are refused by the
/// registry's reader in `decodeCanonicalPushDrop`'s words
/// (`registryTokenValidation.ts:28`, `PushDropValidation.ts:54-79`) and
/// skipped by the resolvers and the listing (`RegistryClient.ts:392,445`).
#[tokio::test]
async fn a_key_only_and_a_no_checksig_registry_token_are_skipped_as_the_reference_skips_them_618() {
    let old = lock_position::cases("registry_client");
    let cases = decode_618::cases("registry_client");
    assert_eq!(cases.len(), 6);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let from = from_537(&old, case);
        let kind = definition_type(from);
        let script = decode_618::script(case, from);
        let words = decode_and_verify_registry_token(kind, &script)
            .unwrap_err()
            .to_string();
        assert!(
            words.ends_with(case["site_words"].as_str().unwrap()),
            "{}: {words}",
            case["name"]
        );
        assert_eq!(read(kind, script).await, (0, 0), "{}", case["name"]);
    }
}
