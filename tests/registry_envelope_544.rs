//! #544, site 3: the registry client's definition reader already runs every
//! check of the reference's validator (`ts-stack@edf6e03`
//! `registryTokenValidation.ts:19-64`: the canonical envelope of the
//! type's field count plus the signature, the bounds, the operator-linked
//! locking key, the operator's signature over the data fields), since #543
//! (`decode_and_verify_registry_token`, `src/registry/token.rs`); this file
//! is the statement that it does, against the registry cases of
//! `tests/vectors/token_envelope_544.json` (`tests/support/token_envelope_544.mjs`,
//! Node v22.18.0): the reference's basket token and four one-change tokens,
//! each refused in the reference's words and skipped by `resolve_basket` as
//! `RegistryClient.resolve` skips it. Green on the base: nothing is RED,
//! as nothing is missing. Hermetic: an in-process resolver on an
//! `.invalid` host.
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::registry::{
    decode_and_verify_registry_token, BasketQuery, DefinitionType, RegistryClient,
    RegistryClientConfig,
};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

#[tokio::test]
async fn the_registry_reader_already_runs_the_reference_validator_544() {
    let v = vector();
    let cases = v["registry"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let read = decode_and_verify_registry_token(DefinitionType::Basket, &script);
        match case["words"].as_str() {
            None => assert!(read.is_ok(), "{}: {read:?}", case["name"]),
            Some(words) => assert_eq!(
                read.unwrap_err(),
                Error::RegistryError(words.into()),
                "{}",
                case["name"]
            ),
        }
        let resolver = lock_position::answering("ls_basketmap", script);
        let client = RegistryClient::new(
            ProtoWallet::new(None),
            RegistryClientConfig::new().with_resolver(resolver),
        );
        let resolved = client
            .resolve_basket(BasketQuery::default())
            .await
            .unwrap()
            .len();
        let expected = usize::from(case["outcome"] == "resolved");
        assert_eq!(resolved, expected, "{}", case["name"]);
    }
}
