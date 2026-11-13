//! The contacts manager sends signAction what the reference's sends (#326):
//! the reference as the wallet answered createAction, its base64 text, and
//! no options (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/ContactsManager.ts:813-834`, `:981-1001`),
//! against `tests/vectors/signaction_reference_326.json` (the reference's
//! update and removal, recorded by `tests/support/signaction_reference_326.mjs`
//! under Node v22.18.0). The update sent the hex of the reference's bytes
//! with `acceptDelayedBroadcast: false`, the removal the same: the hex named
//! an action no wallet made.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`)
//! lists the contact's token and answers createAction with a signable
//! transaction spending it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use identity_reveal_wallet::Counting;
use signaction_reference_326::{
    assert_reference_sign_metadata as assert_reference_sign, source_of, vector,
};

/// #904: the recorded createAction options, aborts and stopping words of
/// the case, read beside the signAction (until #904 no test read them).
fn assert_reference_stop(
    name: &str,
    case: &serde_json::Value,
    wallet: &Counting,
    err: &bsv_rs::Error,
) {
    let created = wallet.created.lock().unwrap().clone().unwrap();
    assert_eq!(
        serde_json::to_value(created.options.as_ref().unwrap()).unwrap(),
        case["create_action_options"],
        "{name}: the reference's createAction options"
    );
    let aborts: Vec<_> = wallet
        .aborts
        .lock()
        .unwrap()
        .iter()
        .map(|a| serde_json::json!({ "reference": a.reference }))
        .collect();
    assert_eq!(
        serde_json::Value::Array(aborts),
        case["abort_action"],
        "{name}: the abort"
    );
    assert_eq!(
        err,
        &bsv_rs::Error::IdentityError(case["stopped"].as_str().unwrap().into()),
        "{name}: the reference's words"
    );
}

fn contact(name: &str) -> Contact {
    Contact::new(
        name,
        bsv_rs::primitives::PrivateKey::from_bytes(&[3u8; 32])
            .unwrap()
            .public_key()
            .to_hex(),
    )
    .with_added_at(1_700_000_000_000)
}

/// A manager whose contact is written (the create path: nothing listed), its
/// token then listed and spent by createAction.
async fn manager_with_listed_contact() -> (ContactsManager<Counting>, Counting) {
    let wallet = Counting::of_scalar(9);
    // #904: the create path needs a listing and a finished transaction,
    // the manager returning the wallet's failure where it swallowed it.
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![],
        total_outputs: 0,
        beef: None,
    });
    *wallet.create_finished.lock().unwrap() = true;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact("Bob Example")).await.unwrap();
    let created = wallet.created.lock().unwrap().take().unwrap();
    let output = &created.outputs.as_ref().unwrap()[0];
    let source = source_of(&output.locking_script, 1);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![WalletOutput {
            satoshis: 1,
            locking_script: None,
            spendable: true,
            custom_instructions: output.custom_instructions.clone(),
            tags: None,
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            labels: None,
        }],
        total_outputs: 1,
        beef: Some(source.to_beef(true).unwrap()),
    });
    *wallet.spending.lock().unwrap() = Some(source);
    (manager, wallet)
}

#[tokio::test]
async fn the_contact_update_signs_with_the_reference_text_and_no_options() {
    let (manager, wallet) = manager_with_listed_contact().await;
    // signAction answers no transaction: the update stops in the
    // reference's words, as the recorded reference stopped (#904; until
    // then a txid alone was taken as a finished update).
    let err = manager
        .add_contact(contact("Bob Updated"))
        .await
        .unwrap_err();
    assert_reference_stop(
        "contacts update",
        &vector()["contacts"]["update"],
        &wallet,
        &err,
    );
    let signed = wallet.signed.lock().unwrap().clone().unwrap();
    let requests = wallet.signature_args.lock().unwrap();
    assert!(
        requests.last().unwrap().hash_to_directly_sign.is_none(),
        "#454: PushDrop sends data"
    );
    assert_eq!(requests.last().unwrap().data.as_ref().unwrap().len(), 32);
    drop(requests);
    let created = wallet.created.lock().unwrap().clone().unwrap();
    assert_reference_sign(
        "contacts update",
        &vector()["contacts"]["update"],
        &signed,
        created.options.as_ref(),
    );
}

#[tokio::test]
async fn the_contact_removal_signs_with_the_reference_text_and_no_options() {
    let (manager, wallet) = manager_with_listed_contact().await;
    let err = manager
        .remove_contact(&contact("").identity_key)
        .await
        .unwrap_err();
    assert_reference_stop(
        "contacts remove",
        &vector()["contacts"]["remove"],
        &wallet,
        &err,
    );
    let signed = wallet.signed.lock().unwrap().clone().unwrap();
    let requests = wallet.signature_args.lock().unwrap();
    assert!(
        requests.last().unwrap().hash_to_directly_sign.is_none(),
        "#454: PushDrop sends data"
    );
    assert_eq!(requests.last().unwrap().data.as_ref().unwrap().len(), 32);
    drop(requests);
    let created = wallet.created.lock().unwrap().clone().unwrap();
    assert_reference_sign(
        "contacts remove",
        &vector()["contacts"]["remove"],
        &signed,
        created.options.as_ref(),
    );
}
