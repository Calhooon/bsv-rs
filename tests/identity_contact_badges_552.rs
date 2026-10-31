//! #552: `Contact` carries the reference's three badge fields through read
//! and write (the keeper's reading of 2026-10-31 12:1xZ at `ts-stack@edf6e03`
//! `packages/sdk/src/identity/ContactsManager.ts`): `validateContact`
//! (`:171-192`) takes `badgeIconURL`, `badgeLabel` and `badgeClickURL`
//! (`:35-43`) through `ownData` (`:47-53`) as strings, so a reference contact
//! carries them; until #552 this crate read them and dropped them, wrote
//! them empty, and a round trip through its update (read, change the name,
//! save) erased them. Against `tests/vectors/contact_badges_552.json`,
//! recorded by `tests/support/contact_badges_552.mjs` under Node v22.18.0:
//! the reference's contact with its badges, read here; this crate's update of
//! it and this crate's save of another contact with badges, each read back by
//! the reference's `getContacts` with its verdict (the tip's equal, the
//! base's the badges erased).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 in process; no network, no port. The tests
//! name no badge field of `Contact` (they read its JSON), so they compile on
//! the base and fail there.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, DecryptArgs, ListOutputsResult, Outpoint, Protocol, SecurityLevel,
    SignActionResult, WalletInterface, WalletOutput,
};
use identity_reveal_wallet::Counting;
use serde_json::{json, Value};
use signaction_reference_326::source_of;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contact_badges_552.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A wallet listing the reference's saved token, its source transaction in
/// the BEEF and spent by createAction, so a read and an update both reach it.
fn listing_reference_token(v: &Value) -> Counting {
    let save = &v["reference"]["save"];
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

/// The reference's contact read here, then its name changed and saved
/// through `update_contact`: the token written.
async fn updated_token(v: &Value) -> (Contact, (String, Vec<u8>)) {
    let wallet = listing_reference_token(v);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(read.len(), 1, "the reference's token is read here");
    let mut updated = read[0].clone();
    updated.name = v["reference"]["updated"]["name"].as_str().unwrap().into();
    let key = updated.identity_key.clone();
    manager.update_contact(&key, updated).await.unwrap();
    (read[0].clone(), created_token(&wallet))
}

/// The vector's reverse record as this crate's `Contact`, built from its
/// JSON (the type's own camelCase names) so the file compiles on the base.
fn reverse_contact(v: &Value) -> Contact {
    let r = &v["reverse"]["contact"];
    let mut contact = json!({
        "identityKey": r["identityKey"],
        "name": r["name"],
        "badgeIconUrl": r["badgeIconURL"],
        "badgeLabel": r["badgeLabel"],
        "badgeClickUrl": r["badgeClickURL"],
    });
    if r["avatarURL"] != "" {
        contact["avatarUrl"] = r["avatarURL"].clone();
    }
    serde_json::from_value(contact).unwrap()
}

/// This crate's save of the reverse contact, nothing listed: the token.
async fn saved_token(v: &Value) -> (String, Vec<u8>) {
    let wallet = Counting::of_scalar(9);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(reverse_contact(v)).await.unwrap();
    created_token(&wallet)
}

#[tokio::test]
async fn a_reference_contacts_badges_are_read_552() {
    let v = vector();
    let reference = &v["reference"]["save"]["contact"];
    // The reference reads its own token with the badges.
    assert_eq!(
        v["reference"]["save"]["read_back"]["contacts"][0],
        *reference
    );
    let (read, _) = updated_token(&v).await;
    let read = serde_json::to_value(read).unwrap();
    assert_eq!(read["badgeIconUrl"], reference["badgeIconURL"]);
    assert_eq!(read["badgeLabel"], reference["badgeLabel"]);
    assert_eq!(read["badgeClickUrl"], reference["badgeClickURL"]);
}

#[tokio::test]
async fn a_reference_contacts_badges_survive_the_ports_update_552() {
    let v = vector();
    let expected = &v["reference"]["updated"];
    assert_eq!(expected["badgeLabel"], "Verified by Example");
    // The record this crate's update writes: the reference's, its name
    // changed, the badges kept.
    let (_, (key_id, script)) = updated_token(&v).await;
    assert_eq!(
        record_in(&key_id, &script).await,
        *expected,
        "{}",
        to_hex(&script)
    );
    // The reference's reading of the recorded tokens: the tip's update the
    // record expected, the base's with the badges erased.
    let tip = &v["crate"]["tip"]["update"];
    assert_eq!(tip["read_back"]["dropped"], json!([]));
    assert_eq!(tip["read_back"]["contacts"][0], *expected);
    assert_eq!(tip["equal"], true);
    let base = &v["crate"]["base"]["update"];
    assert_eq!(base["equal"], false);
    let erased = &base["read_back"]["contacts"][0];
    assert_eq!(erased["name"], expected["name"]);
    for badge in ["badgeIconURL", "badgeLabel", "badgeClickURL"] {
        assert_eq!(erased[badge], "", "the base erased {badge}");
    }
}

#[tokio::test]
async fn a_contact_saved_here_carries_its_badges_to_the_reference_552() {
    let v = vector();
    let expected = &v["reverse"]["contact"];
    let (key_id, script) = saved_token(&v).await;
    assert_eq!(
        record_in(&key_id, &script).await,
        *expected,
        "{}",
        to_hex(&script)
    );
    let tip = &v["crate"]["tip"]["save"];
    assert_eq!(tip["read_back"]["contacts"][0], *expected);
    assert_eq!(tip["equal"], true);
    let base = &v["crate"]["base"]["save"];
    assert_eq!(base["equal"], false);
    assert_eq!(base["read_back"]["contacts"][0]["badgeLabel"], "");
}

/// The recorder's input: this crate's update and save tokens, written to
/// `$CONTACT_BADGES_552_OUT`.
#[tokio::test]
#[ignore = "recorder: writes this crate's tokens for contact_badges_552.mjs"]
async fn record_this_crates_tokens_552() {
    let v = vector();
    let (_, (update_key, update_script)) = updated_token(&v).await;
    let (save_key, save_script) = saved_token(&v).await;
    let record = json!({
        "update": { "key_id": update_key, "locking_script": to_hex(&update_script) },
        "save": { "key_id": save_key, "locking_script": to_hex(&save_script) },
    });
    std::fs::write(
        std::env::var("CONTACT_BADGES_552_OUT").unwrap(),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}
