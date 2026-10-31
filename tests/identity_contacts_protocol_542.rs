//! #542: the contacts manager derives every contact key under the reference's
//! protocol `[2, 'contact']`, counterparty self (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/ContactsManager.ts:30`; the identity tag's HMAC
//! `:572-583`, the encryption and lock `:748-772`, the decryption `:494-501`,
//! the spend `:821-830`), as `ContactsManagerConfig::protocol_id` holds it,
//! where it derived them at security level 1. Against
//! `tests/vectors/contacts_protocol_542.json`, recorded by
//! `tests/support/contacts_protocol_542.mjs` under Node v22.18.0: the
//! reference's contact written by its own `saveContact` on the ProtoWallet of
//! the scalar 9, and its verdicts on this crate's token from the base and the
//! tip (recorded by `record_this_crates_contact_token_542` below).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 in process; no network, no port.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, sha256, to_hex, PrivateKey, PublicKey, Signature};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, CreateActionArgs, DecryptArgs, GetPublicKeyArgs, ListOutputsResult, Outpoint,
    ProtoWallet, Protocol, SecurityLevel, WalletInterface, WalletOutput,
};
use identity_reveal_wallet::Counting;
use serde_json::Value;
use signaction_reference_326::source_of;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contacts_protocol_542.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The reference's protocol as the vector records it.
fn reference_protocol(v: &Value) -> Protocol {
    assert_eq!(v["protocol"]["counterparty"], "self");
    let level = match v["protocol"]["security_level"].as_u64().unwrap() {
        2 => SecurityLevel::Counterparty,
        other => panic!("unexpected level {other}"),
    };
    Protocol::new(level, v["protocol"]["protocol"].as_str().unwrap())
}

/// The ProtoWallet of the scalar 9: the recorder's wallet.
fn proto() -> ProtoWallet {
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    ProtoWallet::new(Some(PrivateKey::from_bytes(&scalar).unwrap()))
}

async fn locking_key(protocol: &Protocol, key_id: &str) -> String {
    WalletInterface::get_public_key(
        &proto(),
        GetPublicKeyArgs {
            protocol_id: Some(protocol.clone()),
            key_id: Some(key_id.into()),
            counterparty: Some(Counterparty::Self_),
            for_self: Some(true),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .public_key
}

fn contact(v: &Value) -> Contact {
    Contact {
        identity_key: v["contact"]["identityKey"].as_str().unwrap().into(),
        name: v["contact"]["name"].as_str().unwrap().into(),
        avatar_url: None,
        added_at: 1_700_000_000_000,
        notes: None,
        tags: Vec::new(),
        metadata: None,
    }
}

/// The token this crate writes for the vector's contact, nothing listed.
async fn written_token(v: &Value) -> (CreateActionArgs, Counting) {
    let wallet = Counting::of_scalar(9);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact(v)).await.unwrap();
    let created = wallet.created.lock().unwrap().clone().unwrap();
    (created, wallet)
}

fn key_id_of(instructions: &str) -> String {
    let parsed: Value = serde_json::from_str(instructions).unwrap();
    parsed["keyID"].as_str().unwrap().into()
}

/// The reference's token listed as one output at `<source txid>.0`, its
/// source transaction the BEEF.
fn listing(v: &Value) -> (ListOutputsResult, bsv_rs::transaction::Transaction) {
    let script = from_hex(v["write"]["locking_script"].as_str().unwrap()).unwrap();
    let source = source_of(&script, 1);
    let listed = ListOutputsResult {
        total_outputs: 1,
        beef: Some(source.to_beef(true).unwrap()),
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            satoshis: 1,
            locking_script: Some(script),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: Some(v["write"]["custom_instructions"].as_str().unwrap().into()),
        }],
    };
    (listed, source)
}

#[tokio::test]
async fn the_reference_contact_record_is_read_here_542() {
    let v = vector();
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(listing(&v).0);
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
    let contacts = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(
        contacts.len(),
        1,
        "the reference's ciphertext decrypts under [2, 'contact']"
    );
    assert_eq!(contacts[0].identity_key, v["contact"]["identityKey"]);
    assert_eq!(contacts[0].name, v["contact"]["name"]);
    // The reference reads its own record back, and refuses it under level 1.
    assert_eq!(v["write"]["read_back"]["contacts"], 1);
    assert_eq!(
        v["write"]["under_level_one"]["decrypt"]["error"],
        "Decryption failed!"
    );
}

#[tokio::test]
async fn the_identity_tag_is_the_reference_hmac_542() {
    let v = vector();
    let (created, wallet) = written_token(&v).await;
    let tag = v["write"]["tag"].as_str().unwrap();
    let asked = wallet.list_args.lock().unwrap()[0].tags.clone().unwrap();
    assert_eq!(asked, vec![tag.to_string()], "the lookup's tag");
    let output = &created.outputs.unwrap()[0];
    assert_eq!(
        output.tags.clone().unwrap(),
        vec![tag.to_string()],
        "the token's tag"
    );
}

#[tokio::test]
async fn the_token_is_locked_and_encrypted_under_the_reference_protocol_542() {
    let v = vector();
    let protocol = reference_protocol(&v);
    // The reference's lock is the ProtoWallet's derivation under the protocol.
    assert_eq!(
        locking_key(&protocol, v["write"]["key_id"].as_str().unwrap()).await,
        v["write"]["locking_public_key"].as_str().unwrap()
    );
    let (created, _) = written_token(&v).await;
    let output = &created.outputs.unwrap()[0];
    let key_id = key_id_of(output.custom_instructions.as_deref().unwrap());
    let token =
        PushDrop::decode(&LockingScript::from_binary(&output.locking_script).unwrap()).unwrap();
    assert_eq!(
        token.locking_public_key.to_hex(),
        locking_key(&protocol, &key_id).await,
        "this crate's token is locked to the key the reference derives"
    );
    let plaintext = WalletInterface::decrypt(
        &proto(),
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
    .expect("this crate's ciphertext decrypts under the reference's protocol")
    .plaintext;
    let read: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(read["identityKey"], v["contact"]["identityKey"]);
}

#[tokio::test]
async fn the_reference_verdicts_on_this_crates_tokens_542() {
    let v = vector();
    let base = &v["crate"]["base"];
    let tip = &v["crate"]["tip"];
    // Base: locked to another key, the reference's decrypt refuses it.
    assert_ne!(
        base["token_locking_public_key"],
        base["under_contact_protocol"]["locking_public_key"]
    );
    assert_eq!(
        base["under_contact_protocol"]["decrypt"]["error"],
        "Decryption failed!"
    );
    // Tip: the key the reference derives, its decrypt reads the record.
    assert_eq!(
        tip["token_locking_public_key"],
        tip["under_contact_protocol"]["locking_public_key"]
    );
    let read: Value = serde_json::from_str(
        tip["under_contact_protocol"]["decrypt"]["value"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(read["identityKey"], v["contact"]["identityKey"]);
    // Both: the reference's manager drops a one-field token (no field
    // signature, ContactsManager.ts:433) before it decrypts; not #542's.
    for token in [base, tip] {
        assert_eq!(token["token_fields"], 1);
        assert_eq!(token["read_back"]["contacts"], 0);
        assert_eq!(
            token["read_back"]["dropped"][0],
            "ContactsManager: Failed to decrypt contact output: Invalid contact PushDrop field count"
        );
    }
}

#[tokio::test]
async fn the_spend_of_a_reference_token_is_signed_by_its_locking_key_542() {
    let v = vector();
    let (listed, source) = listing(&v);
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(listed);
    *wallet.spending.lock().unwrap() = Some(source);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact(&v)).await.unwrap();
    let signed = wallet.signed.lock().unwrap().clone().unwrap();
    let unlocking = &signed.spends[&0].unlocking_script;
    let push = usize::from(unlocking[0]);
    let der = &unlocking[1..push]; // the sighash byte last
    let data = wallet
        .signature_args
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .data
        .clone()
        .unwrap();
    let key = PublicKey::from_hex(v["write"]["locking_public_key"].as_str().unwrap()).unwrap();
    assert!(
        key.verify(&sha256(&data), &Signature::from_der(der).unwrap()),
        "the spend verifies under the reference's lock: {}",
        to_hex(unlocking)
    );
}

/// The recorder's input: this crate's token for the vector's contact, written
/// to `$CONTACTS_542_OUT` (run on the base and on the tip).
#[tokio::test]
#[ignore = "recorder: writes this crate's contact token for contacts_protocol_542.mjs"]
async fn record_this_crates_contact_token_542() {
    let v = vector();
    let (created, _) = written_token(&v).await;
    let output = &created.outputs.unwrap()[0];
    let record = serde_json::json!({
        "key_id": key_id_of(output.custom_instructions.as_deref().unwrap()),
        "locking_script": to_hex(&output.locking_script),
    });
    std::fs::write(
        std::env::var("CONTACTS_542_OUT").unwrap(),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}
