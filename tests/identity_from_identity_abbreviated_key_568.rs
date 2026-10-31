//! #568: a `DisplayableIdentity`'s `abbreviated_key` through
//! `Contact::from_identity` and back through `to_displayable_identity`, as the
//! reference carries it (the keeper's ruling (4) of 2026-10-31 17:1xZ at
//! `ts-stack@edf6e03` `packages/sdk/src/identity/`). The reference's contact
//! is its identity (`ContactsManager.ts:28`): `IdentityClient.saveContact`
//! (`IdentityClient.ts:974-979`) stores the identity's `abbreviatedKey` through
//! `validateContact` as given (`ContactsManager.ts:185`; the value is computed
//! only by `parseIdentity`, `IdentityClient.ts:1166`, `subject.substring(0,
//! 10)...`), and `resolveByIdentityKey` with contacts (`:575-576`) returns the
//! record read, its `abbreviatedKey` as stored. Until #568 `from_identity`
//! dropped the identity's value (the record carrying this crate's
//! `02abcd...wxyz` form) and `to_displayable_identity` answered that form
//! whatever was stored. Against
//! `tests/vectors/from_identity_abbreviated_key_568.json`, recorded by
//! `tests/support/from_identity_abbreviated_key_568.mjs` under Node v22.18.0:
//! three identities (the reference's `parseIdentity` of an email certificate,
//! another client's text, `""`), each saved by the reference's client (the
//! record its token carries) and resolved from that token.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 in process, and a resolver whose one
//! facilitator refuses every question; no network, no port.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::identity::{Contact, DisplayableIdentity, IdentityClient};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator,
};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, DecryptArgs, ListOutputsResult, Outpoint, Protocol, SecurityLevel,
    WalletInterface, WalletOutput,
};
use identity_reveal_wallet::Counting;
use serde_json::{json, Value};
use signaction_reference_326::source_of;
use std::collections::HashMap;
use std::sync::Arc;

fn cases() -> Vec<Value> {
    let v: Value = serde_json::from_str(include_str!(
        "vectors/from_identity_abbreviated_key_568.json"
    ))
    .unwrap();
    let cases = v["cases"].as_array().unwrap().clone();
    assert_eq!(cases.len(), 3);
    cases
}

/// A facilitator refusing every question: the contacts answer first.
struct Refusing;

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Refusing {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Err(bsv_rs::Error::OverlayError(
            "from_identity_abbreviated_key_568: no lookup".into(),
        ))
    }
}

fn client(wallet: Counting) -> IdentityClient<Counting> {
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Refusing)),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    IdentityClient::with_resolver(wallet, Default::default(), resolver)
}

/// The vector's identity (the reference's names) as this crate's type.
fn identity_of(i: &Value) -> DisplayableIdentity {
    let s = |k: &str| i[k].as_str().unwrap().to_string();
    DisplayableIdentity {
        name: s("name"),
        avatar_url: s("avatarURL"),
        identity_key: s("identityKey"),
        abbreviated_key: s("abbreviatedKey"),
        badge_icon_url: s("badgeIconURL"),
        badge_label: s("badgeLabel"),
        badge_click_url: s("badgeClickURL"),
    }
}

/// This crate's identity in the reference's names, to compare whole.
fn reference_names(i: &DisplayableIdentity) -> Value {
    json!({
        "name": i.name,
        "avatarURL": i.avatar_url,
        "abbreviatedKey": i.abbreviated_key,
        "identityKey": i.identity_key,
        "badgeIconURL": i.badge_icon_url,
        "badgeLabel": i.badge_label,
        "badgeClickURL": i.badge_click_url,
    })
}

/// The record the token of the wallet's last createAction carries,
/// decrypted under the wallet of 9.
async fn created_record(wallet: &Counting) -> Value {
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let output = created.outputs.unwrap().remove(0);
    let instructions: Value =
        serde_json::from_str(output.custom_instructions.as_deref().unwrap()).unwrap();
    let token =
        PushDrop::decode(&LockingScript::from_binary(&output.locking_script).unwrap()).unwrap();
    let plaintext = WalletInterface::decrypt(
        &Counting::of_scalar(9),
        DecryptArgs {
            ciphertext: token.fields[0].clone(),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "contact"),
            key_id: instructions["keyID"].as_str().unwrap().into(),
            counterparty: Some(Counterparty::Self_),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .plaintext;
    serde_json::from_slice(&plaintext).unwrap()
}

/// A wallet listing the reference's saved token of `case`.
fn listing(case: &Value) -> Counting {
    let script = from_hex(case["locking_script"].as_str().unwrap()).unwrap();
    let source = source_of(&script, 1);
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: Some(source.to_beef(true).unwrap()),
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            satoshis: 1,
            locking_script: Some(script),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: Some(case["custom_instructions"].as_str().unwrap().into()),
        }],
    });
    wallet
}

#[test]
fn from_identity_carries_the_identitys_abbreviated_key_568() {
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        // The reference's saved record keeps the identity's value.
        assert_eq!(
            case["saved"]["abbreviatedKey"], case["identity"]["abbreviatedKey"],
            "{name}"
        );
        let contact = Contact::from_identity(identity_of(&case["identity"]));
        assert_eq!(
            contact.abbreviated_key.as_deref(),
            case["saved"]["abbreviatedKey"].as_str(),
            "{name}"
        );
        // And back: the stored value, not this crate's computed form (the
        // other members compare through the token below: the reference's
        // `validateContact` normalizes a URL at the save, `safeNavigation`).
        assert_eq!(
            contact.to_displayable_identity().abbreviated_key,
            case["resolved"]["abbreviatedKey"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn an_identity_saved_as_a_contact_keeps_its_abbreviated_key_568() {
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        let wallet = Counting::of_scalar(9);
        client(wallet.clone())
            .save_contact(identity_of(&case["identity"]), None)
            .await
            .unwrap();
        assert_eq!(created_record(&wallet).await, case["saved"], "{name}");
    }
}

#[tokio::test]
async fn a_contact_resolved_as_an_identity_answers_its_stored_abbreviated_key_568() {
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        let key = case["identity"]["identityKey"].as_str().unwrap();
        let client = client(listing(&case));
        // This crate's resolver reads the contacts cache alone: load it first.
        assert_eq!(client.get_contacts(true).await.unwrap().len(), 1, "{name}");
        let resolved = client
            .resolve_by_identity_key(key, true)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{name}: the contact is read"));
        assert_eq!(reference_names(&resolved), case["resolved"], "{name}");
    }
}
