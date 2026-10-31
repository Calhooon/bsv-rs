//! #559: a contact's stored `abbreviatedKey` survives this crate's update, as
//! the reference keeps it (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/ContactsManager.ts`): `saveContact`
//! (`:527-528`) and `#encryptAndLock` (`:748-749`) write `validateContact`'s
//! record, its `abbreviatedKey` the caller's as given (`:185`); the reference
//! computes one only in `IdentityClient.parseIdentity` (`IdentityClient.ts:1044`,
//! `:1166`), never on the save path. Until #559 this crate's record writer
//! put `to_displayable_identity`'s `02abcd...wxyz` in its place, so an update
//! here replaced a reference record's own value. Against
//! `tests/vectors/contact_abbreviated_key_559.json`, recorded by
//! `tests/support/contact_abbreviated_key_559.mjs` under Node v22.18.0, three
//! stored values none of which is this crate's computed form (parseIdentity's
//! `02f9308a01...`, a caller's text, the empty string): the reference's
//! contact read here, its name changed and saved through `update_contact`,
//! the record written; the reference's reading of the tip's and the base's
//! tokens with its verdict.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 in process; no network, no port. The tests
//! name no new member of `Contact`, so they compile on the base and fail there.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::identity::{ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, DecryptArgs, ListOutputsResult, Outpoint, Protocol, SecurityLevel,
    SignActionResult, WalletInterface, WalletOutput,
};
use identity_reveal_wallet::Counting;
use serde_json::{json, Map, Value};
use signaction_reference_326::source_of;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contact_abbreviated_key_559.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A wallet listing the case's reference token, its source transaction in
/// the BEEF and spent by createAction, so a read and an update both reach it.
fn listing_reference_token(case: &Value) -> Counting {
    let save = &case["reference"]["save"];
    let script = from_hex(save["locking_script"].as_str().unwrap()).unwrap();
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
            custom_instructions: Some(save["custom_instructions"].as_str().unwrap().into()),
        }],
    });
    *wallet.spending.lock().unwrap() = Some(source);
    wallet
        .sign_answers
        .lock()
        .unwrap()
        .push_back(Ok(SignActionResult {
            txid: Some([0xab; 32]),
            tx: None,
            send_with_results: None,
        }));
    wallet
}

/// The token the wallet's last createAction carried: its key ID and script.
fn created_token(wallet: &Counting) -> (String, Vec<u8>) {
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let output = created.outputs.unwrap().remove(0);
    let instructions: Value =
        serde_json::from_str(output.custom_instructions.as_deref().unwrap()).unwrap();
    (
        instructions["keyID"].as_str().unwrap().into(),
        output.locking_script,
    )
}

/// The record a token of this crate carries, decrypted under the wallet of 9.
async fn record_in(key_id: &str, script: &[u8]) -> Value {
    let token = PushDrop::decode(&LockingScript::from_binary(script).unwrap()).unwrap();
    let plaintext = WalletInterface::decrypt(
        &Counting::of_scalar(9),
        DecryptArgs {
            ciphertext: token.fields[0].clone(),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "contact"),
            key_id: key_id.into(),
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

/// The case's reference contact read here, its name changed and saved
/// through `update_contact`: the token written.
async fn updated_token(case: &Value) -> (String, Vec<u8>) {
    let wallet = listing_reference_token(case);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(read.len(), 1, "the reference's token is read here");
    let mut updated = read[0].clone();
    updated.name = case["reference"]["updated"]["name"]
        .as_str()
        .unwrap()
        .into();
    let key = updated.identity_key.clone();
    manager.update_contact(&key, updated).await.unwrap();
    created_token(&wallet)
}

#[tokio::test]
async fn a_reference_contacts_stored_abbreviated_key_survives_the_ports_update_559() {
    let v = vector();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let stored = &case["reference"]["save"]["contact"]["abbreviatedKey"];
        // The stored value is not the form this crate computes, and the
        // reference reads its own token with it.
        assert_ne!(*stored, case["computed_here"], "{name}");
        assert_eq!(
            case["reference"]["save"]["read_back"]["contacts"][0]["abbreviatedKey"], *stored,
            "{name}"
        );
        let expected = &case["reference"]["updated"];
        assert_eq!(expected["abbreviatedKey"], *stored, "{name}");
        // The record this crate's update writes: the reference's, its name
        // changed, the stored abbreviatedKey kept.
        let (key_id, script) = updated_token(case).await;
        assert_eq!(
            record_in(&key_id, &script).await,
            *expected,
            "{name}: {}",
            to_hex(&script)
        );
    }
}

#[tokio::test]
async fn the_reference_reads_the_tips_update_with_its_stored_abbreviated_key_559() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = &case["reference"]["updated"];
        let tip = &v["crate"]["tip"][name];
        assert_eq!(tip["read_back"]["dropped"], json!([]), "{name}");
        assert_eq!(tip["read_back"]["contacts"][0], *expected, "{name}");
        assert_eq!(tip["equal"], true, "{name}");
        // The base's update: the reference reads it with the value this
        // crate computed in place of the stored one.
        let base = &v["crate"]["base"][name];
        assert_eq!(base["equal"], false, "{name}");
        let replaced = &base["read_back"]["contacts"][0];
        assert_eq!(replaced["abbreviatedKey"], case["computed_here"], "{name}");
        assert_eq!(replaced["name"], expected["name"], "{name}");
    }
}

/// The recorder's input: this crate's update token for each case, written
/// to `$CONTACT_ABBREVIATED_KEY_559_OUT`.
#[tokio::test]
#[ignore = "recorder: writes this crate's tokens for contact_abbreviated_key_559.mjs"]
async fn record_this_crates_tokens_559() {
    let v = vector();
    let mut record = Map::new();
    for case in v["cases"].as_array().unwrap() {
        let (key_id, script) = updated_token(case).await;
        record.insert(
            case["name"].as_str().unwrap().into(),
            json!({ "key_id": key_id, "locking_script": to_hex(&script) }),
        );
    }
    std::fs::write(
        std::env::var("CONTACT_ABBREVIATED_KEY_559_OUT").unwrap(),
        serde_json::to_string_pretty(&Value::Object(record)).unwrap(),
    )
    .unwrap();
}
