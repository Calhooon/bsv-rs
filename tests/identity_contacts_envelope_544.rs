//! #544, site 1: the contacts manager's token and record are the reference's
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts`; the
//! keeper's words of 2026-10-31 09:1xZ): the token the signed two-field
//! PushDrop `#encryptAndLock` writes (`:748-772`), read through
//! `#authenticateContactScript` (`:431-466`: exactly two fields, the bounds,
//! the canonical five chunks, the lock the wallet's key for the key ID, the
//! signature over the ciphertext), the plaintext `validateContact`'s record
//! (`:171-209`: the seven display fields and an optional `metadata`, any other
//! member refused). Against `tests/vectors/token_envelope_544.json`, recorded
//! by `tests/support/token_envelope_544.mjs` under Node v22.18.0: the
//! reference's own token read here, nine one-change tokens dropped as the
//! reference drops them, the reference's verdicts on this crate's base and tip
//! tokens, and `saveContact`'s refusals before any wallet call.
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 in process; no network, no port.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, DecryptArgs, ListOutputsResult, Outpoint, Protocol, SecurityLevel,
    VerifySignatureArgs, WalletInterface, WalletOutput,
};
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use serde_json::Value;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/token_envelope_544.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The contacts manager over the ProtoWallet of 9, listing `script` with
/// `instructions`, its contacts loaded.
async fn loaded(script: &str, instructions: &str) -> Vec<Contact> {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: None,
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", "22".repeat(32))).unwrap(),
            satoshis: 1,
            locking_script: Some(from_hex(script).unwrap()),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: Some(instructions.into()),
        }],
    });
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
    manager.list_contacts_with_refresh(true).await.unwrap()
}

/// The vector's contact and metadata as this crate's `Contact`.
fn contact(v: &Value) -> Contact {
    let plaintext: Value =
        serde_json::from_str(v["contacts"]["write"]["plaintext"].as_str().unwrap()).unwrap();
    Contact {
        identity_key: plaintext["identityKey"].as_str().unwrap().into(),
        name: plaintext["name"].as_str().unwrap().into(),
        avatar_url: Some(plaintext["avatarURL"].as_str().unwrap().into()),
        added_at: 1_700_000_000_000,
        notes: Some(plaintext["metadata"]["notes"].as_str().unwrap().into()),
        tags: vec![plaintext["metadata"]["tags"][0].as_str().unwrap().into()],
        metadata: None,
    }
}

/// The token this crate writes for the vector's contact, nothing listed.
async fn written(v: &Value) -> (String, Vec<u8>) {
    let wallet = Counting::of_scalar(9);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact(v)).await.unwrap();
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let output = created.outputs.unwrap().remove(0);
    let instructions: Value =
        serde_json::from_str(output.custom_instructions.as_deref().unwrap()).unwrap();
    (
        instructions["keyID"].as_str().unwrap().into(),
        output.locking_script,
    )
}

#[tokio::test]
async fn the_reference_contact_token_is_authenticated_and_read_here_544() {
    let v = vector();
    let write = &v["contacts"]["write"];
    assert_eq!(
        write["fields"], 2,
        "the reference's token carries its signature"
    );
    let read = loaded(
        write["locking_script"].as_str().unwrap(),
        write["custom_instructions"].as_str().unwrap(),
    )
    .await;
    assert_eq!(read.len(), 1);
    let expected = contact(&v);
    assert_eq!(read[0].identity_key, expected.identity_key);
    assert_eq!(read[0].name, expected.name);
    // The reference's spellings: `avatarURL`, and `notes` and `tags` in
    // `metadata`; the saved-at time is not in the token.
    assert_eq!(read[0].avatar_url, expected.avatar_url);
    assert_eq!(read[0].notes, expected.notes);
    assert_eq!(read[0].tags, expected.tags);
    assert_eq!(read[0].metadata, None);
    assert_eq!(read[0].added_at, 0);
}

#[tokio::test]
async fn a_changed_contact_token_is_dropped_as_the_reference_drops_it_544() {
    let v = vector();
    let instructions = v["contacts"]["write"]["custom_instructions"]
        .as_str()
        .unwrap();
    let changed = v["contacts"]["changed"].as_array().unwrap();
    assert_eq!(changed.len(), 9);
    for case in changed {
        assert_eq!(
            case["read_back"]["contacts"],
            serde_json::json!([]),
            "{}",
            case["name"]
        );
        assert_eq!(
            loaded(case["locking_script"].as_str().unwrap(), instructions)
                .await
                .len(),
            0,
            "{}: dropped by the reference with {}",
            case["name"],
            case["read_back"]["dropped"][0]
        );
    }
    // A key ID that is not base64 of 32 bytes (`#readKeyID`, `:414-429`).
    let bad = &v["contacts"]["bad_key_id"];
    assert_eq!(bad["contacts"], serde_json::json!([]));
    let script = v["contacts"]["write"]["locking_script"].as_str().unwrap();
    let instructions = serde_json::json!({ "keyID": "not base64" }).to_string();
    assert!(loaded(script, &instructions).await.is_empty());
}

#[tokio::test]
async fn this_crates_contact_token_is_read_by_the_reference_544() {
    let v = vector();
    let crate_tokens = &v["contacts"]["crate"];
    // Base: one field, dropped by the reference before it decrypts.
    assert_eq!(crate_tokens["base"]["fields"], 1);
    assert_eq!(
        crate_tokens["base"]["read_back"]["dropped"][0],
        "Invalid contact PushDrop field count"
    );
    // Tip: the reference authenticates, decrypts and validates it.
    let tip = &crate_tokens["tip"];
    assert_eq!(tip["fields"], 2);
    assert_eq!(tip["read_back"]["dropped"], serde_json::json!([]));
    let read = &tip["read_back"]["contacts"][0];
    let expected = contact(&v);
    assert_eq!(read["identityKey"], expected.identity_key.as_str());
    assert_eq!(read["avatarURL"], expected.avatar_url.as_deref().unwrap());
    assert_eq!(
        read["metadata"]["notes"],
        expected.notes.as_deref().unwrap()
    );
    assert_eq!(read["metadata"]["tags"][0], expected.tags[0].as_str());
    assert!(read.get("addedAt").is_none());

    // And the token this crate writes now is that shape: two fields, the
    // signature the wallet's over the ciphertext, the plaintext the record.
    let (key_id, script) = written(&v).await;
    let token = PushDrop::decode(&LockingScript::from_binary(&script).unwrap()).unwrap();
    assert_eq!(token.fields.len(), 2, "{}", to_hex(&script));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "contact");
    let wallet = Counting::of_scalar(9);
    let verified = WalletInterface::verify_signature(
        &wallet,
        VerifySignatureArgs {
            data: Some(token.fields[0].clone()),
            signature: token.fields[1].clone(),
            protocol_id: protocol.clone(),
            key_id: key_id.clone(),
            counterparty: Some(Counterparty::Self_),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    assert!(verified.valid);
    let plaintext = WalletInterface::decrypt(
        &wallet,
        DecryptArgs {
            ciphertext: token.fields[0].clone(),
            protocol_id: protocol,
            key_id,
            counterparty: Some(Counterparty::Self_),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .plaintext;
    let record: Value = serde_json::from_slice(&plaintext).unwrap();
    let mut members: Vec<&str> = record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "abbreviatedKey",
            "avatarURL",
            "badgeClickURL",
            "badgeIconURL",
            "badgeLabel",
            "identityKey",
            "metadata",
            "name"
        ]
    );
}

#[tokio::test]
async fn the_writer_refuses_a_record_the_reference_refuses_544() {
    let v = vector();
    let refusals = v["contacts"]["save_refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 5);
    for case in refusals {
        assert_eq!(case["wallet_called"], false, "{}", case["name"]);
        let mut record = contact(&v);
        record.notes = None;
        record.tags = Vec::new();
        let given = &case["contact"];
        record.name = given["name"].as_str().unwrap().into();
        record.identity_key = given["identityKey"].as_str().unwrap().into();
        record.avatar_url = Some(given["avatarURL"].as_str().unwrap().into());
        record.metadata = (!case["metadata"].is_null()).then(|| case["metadata"].clone());
        let wallet = Counting::of_scalar(9);
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let refused = manager.add_contact(record).await.unwrap_err();
        assert_eq!(
            refused,
            Error::IdentityError(case["words"].as_str().unwrap().into()),
            "{}",
            case["name"]
        );
        assert!(
            wallet.calls().is_empty(),
            "{}: {:?}",
            case["name"],
            wallet.calls()
        );
    }
}

/// The recorder's input: this crate's contact token for the vector's
/// contact and its SHIP and SLAP advertisements, written to `$TOKENS_544_OUT`.
#[tokio::test]
#[ignore = "recorder: writes this crate's tokens for token_envelope_544.mjs"]
async fn record_this_crates_tokens_544() {
    let v = vector();
    let (key_id, script) = written(&v).await;
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    let root = bsv_rs::primitives::PrivateKey::from_bytes(&scalar).unwrap();
    let advert = |protocol, domain, name| {
        to_hex(
            &bsv_rs::overlay::create_signed_overlay_admin_token(&root, protocol, domain, name)
                .to_binary(),
        )
    };
    let record = serde_json::json!({
        "contacts": { "key_id": key_id, "locking_script": to_hex(&script) },
        "overlay_ship": advert(bsv_rs::overlay::Protocol::Ship, "https://ship.example", "tm_test"),
        "overlay_slap": advert(bsv_rs::overlay::Protocol::Slap, "https://slap.example", "ls_test"),
    });
    std::fs::write(
        std::env::var("TOKENS_544_OUT").unwrap(),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}
