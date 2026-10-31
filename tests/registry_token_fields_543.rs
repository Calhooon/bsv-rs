//! #543: the registry client reads and writes a definition token with the
//! reference's layout and locking key (`ts-stack@edf6e03`
//! `registryTokenValidation.ts:13-64`, `RegistryClient.ts:308-342,688-722`,
//! `PushDrop.ts:146-202`): the data fields (6 for a basket or a protocol, 7
//! for a certificate) and the operator's signature over them last, locked
//! with the operator's key linked to `anyone`. The reference's tokens are
//! recorded by `tests/support/registry_token_fields_543.mjs` from its own
//! `registerDefinition` with a `ProtoWallet` of the scalar 9; the resolvers
//! are injected (`.invalid` hosts, never dialled) and the wallet in process.
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;
#[path = "support/registry_token_fields_543.rs"]
mod token_fields;

use bsv_rs::primitives::to_hex;
use bsv_rs::registry::{
    BasketQuery, CertificateQuery, DefinitionData, DefinitionType, ProtocolQuery, RegistryClient,
    RegistryClientConfig,
};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, ListOutputsResult, Outpoint, Protocol, SecurityLevel, WalletOutput,
};
use identity_reveal_wallet::Counting;

/// The wallet of the reference's recording, listing `script` as its one
/// output when given one.
fn wallet_listing(script: Option<&LockingScript>) -> Counting {
    let wallet = Counting::of_scalar(9);
    let source = script.map(|script| lock_position::source_of(script.clone()));
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: u32::from(source.is_some()),
        beef: None,
        outputs: source
            .iter()
            .map(|tx| WalletOutput {
                outpoint: Outpoint::from_string(&format!("{}.0", tx.id())).unwrap(),
                satoshis: 1,
                locking_script: Some(tx.outputs[0].locking_script.to_binary()),
                spendable: true,
                tags: None,
                labels: None,
                custom_instructions: None,
            })
            .collect(),
    });
    wallet
}

/// What the type's resolver and the wallet listing read from `script`: each
/// definition as the data fields this crate writes for it.
async fn read(kind: DefinitionType, script: LockingScript) -> (Vec<Vec<Vec<u8>>>, usize) {
    let resolver = lock_position::answering(kind.lookup_service(), script.clone());
    let client = RegistryClient::new(
        wallet_listing(Some(&script)),
        RegistryClientConfig::new().with_resolver(resolver),
    );
    let resolved: Vec<DefinitionData> = match kind {
        DefinitionType::Basket => (client.resolve_basket(BasketQuery::default()).await)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect(),
        DefinitionType::Protocol => (client.resolve_protocol(ProtocolQuery::default()).await)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect(),
        DefinitionType::Certificate => (client
            .resolve_certificate(CertificateQuery::default())
            .await)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect(),
    };
    let listed = client.list_own_registry_entries(kind).await.unwrap().len();
    let fields = resolved
        .iter()
        .map(|d| d.to_pushdrop_fields(d.get_registry_operator()).unwrap())
        .collect();
    (fields, listed)
}

#[tokio::test]
async fn the_reference_definition_tokens_are_read_by_the_resolvers_and_the_listing_543() {
    let tokens = token_fields::cases("tokens");
    assert_eq!(tokens.len(), 3);
    for case in &tokens {
        let name = case["definition_type"].as_str().unwrap();
        assert_eq!(case["verdict"]["ok"], true, "{name}");
        assert_eq!(case["resolved"].as_array().unwrap().len(), 1, "{name}");
        let (resolved, listed) = read(
            token_fields::definition_type(case),
            token_fields::script(case),
        )
        .await;
        assert_eq!(resolved, vec![token_fields::fields(case)], "{name}");
        assert_eq!(listed, 1, "{name}");
    }
}

#[tokio::test]
async fn the_registry_client_writes_the_reference_definition_token_543() {
    let vector = token_fields::vector();
    for case in vector["tokens"].as_array().unwrap() {
        let name = case["definition_type"].as_str().unwrap();
        let kind = token_fields::definition_type(case);
        let wallet = wallet_listing(None);
        let client = RegistryClient::new(wallet.clone(), RegistryClientConfig::new());
        // The counting wallet answers createAction with no transaction.
        assert!(client
            .register_definition(token_fields::definition(case))
            .await
            .is_err());
        let created = wallet.created.lock().unwrap().clone().unwrap();
        let output = &created.outputs.as_ref().unwrap()[0];
        assert_eq!(
            to_hex(&output.locking_script),
            case["script"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            output.satoshis,
            case["satoshis"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(output.basket.as_deref(), case["basket"].as_str(), "{name}");

        // The reference's key: the wallet's for `anyone`, for itself.
        let (_, protocol) = kind.wallet_protocol();
        let keys = wallet.public_key_args.lock().unwrap().clone();
        let derived = keys.last().unwrap();
        assert!(keys[0].identity_key, "{name}");
        assert_eq!(
            derived.protocol_id,
            Some(Protocol::new(SecurityLevel::App, protocol))
        );
        assert_eq!(derived.key_id.as_deref(), Some("1"));
        assert_eq!(derived.counterparty, Some(Counterparty::Anyone));
        assert_eq!(derived.for_self, Some(true));
        assert_eq!(
            to_hex(&output.locking_script[1..34]),
            case["locking_point"].as_str().unwrap(),
            "{name}"
        );
        // The reference's signature: over the data fields, for `anyone`.
        let signatures = wallet.signature_args.lock().unwrap().clone();
        assert_eq!(signatures.len(), 1, "{name}");
        assert_eq!(
            signatures[0].data.as_deref().map(to_hex).as_deref(),
            case["signature_args"][0]["data"].as_str(),
            "{name}"
        );
        assert_eq!(signatures[0].counterparty, Some(Counterparty::Anyone));

        // updateDefinition writes the same token for the same definition.
        let script = token_fields::script(case);
        let wallet = wallet_listing(Some(&script));
        let client = RegistryClient::new(wallet.clone(), RegistryClientConfig::new());
        let records = client.list_own_registry_entries(kind).await.unwrap();
        assert_eq!(records.len(), 1, "{name}");
        let _ = client
            .update_definition(&records[0], token_fields::definition(case))
            .await;
        let created = wallet.created.lock().unwrap().clone().unwrap();
        assert_eq!(
            to_hex(&created.outputs.unwrap()[0].locking_script),
            case["script"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_pre_543_token_is_refused_as_the_reference_refuses_it_543() {
    let base = token_fields::cases("base_tokens");
    assert_eq!(base.len(), 3);
    for case in &base {
        let name = case["definition_type"].as_str().unwrap();
        // The reference's validator refuses this crate's 6/6/7-field token.
        assert_eq!(case["verdict"]["ok"], false, "{name}");
        assert_eq!(
            case["verdict"]["words"],
            "Unexpected PushDrop token field count"
        );
        assert_eq!(case["resolved"], 0, "{name}");
        let (resolved, listed) = read(
            token_fields::definition_type(case),
            token_fields::script(case),
        )
        .await;
        assert_eq!((resolved.len(), listed), (0, 0), "{name}");
    }
}

#[tokio::test]
async fn a_token_changed_in_one_respect_is_skipped_as_the_reference_skips_it_543() {
    let refusals = token_fields::cases("refusals");
    assert_eq!(refusals.len(), 30);
    for case in &refusals {
        let name = case["name"].as_str().unwrap();
        assert_eq!(case["verdict"]["ok"], false, "{name}");
        assert_eq!(case["resolved"], 0, "{name}");
        let (resolved, listed) = read(
            token_fields::definition_type(case),
            token_fields::script(case),
        )
        .await;
        assert_eq!((resolved.len(), listed), (0, 0), "{name}");
    }
}

#[tokio::test]
async fn an_operator_text_the_reference_counterparty_check_refuses_is_skipped_543() {
    let cases = token_fields::cases("counterparties");
    assert_eq!(cases.len(), 15);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let (resolved, listed) = read(
            token_fields::definition_type(case),
            token_fields::script(case),
        )
        .await;
        let expected = case["resolved"].as_u64().unwrap() as usize;
        assert_eq!((resolved.len(), listed), (expected, expected), "{name}");
    }
}

#[tokio::test]
async fn an_operator_beside_a_bad_signature_or_in_whitespace_is_skipped_543() {
    let cases = token_fields::cases("operator_orders");
    assert_eq!(cases.len(), 12);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        assert_eq!(case["resolved"], 0, "{name}");
        let (resolved, listed) = read(
            token_fields::definition_type(case),
            token_fields::script(case),
        )
        .await;
        assert_eq!((resolved.len(), listed), (0, 0), "{name}");
    }
}
