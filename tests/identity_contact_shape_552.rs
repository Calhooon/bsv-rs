//! #552's fold: `Contact` closed as the keeper's word of 2026-10-31 13:1xZ
//! shapes it (`#[non_exhaustive]`, as #527 closed `WorkBudget`):
//! `Contact::new(name, identity_key)`, the two members the reference's
//! `validateContact` requires non-empty (`ts-stack@edf6e03`
//! `ContactsManager.ts:183`, `:186`), and a `with_` setter for each optional
//! member. A literal from outside the crate no longer builds (the
//! `compile_fail` doc test on `Contact`); here: the setters set their
//! fields, `new` judges nothing (the reference validates at the save, so
//! `add_contact` refuses in its words before any wallet call), and the
//! record a contact built by `new` and the setters writes is the lane's
//! vector's (`tests/vectors/contact_badges_552.json`, `reverse.contact`).
//!
//! Hermetic: the counting wallet of #318, a ProtoWallet of the scalar 9 in
//! process; no network, no port.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::to_hex;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Counterparty, DecryptArgs, Protocol, SecurityLevel, WalletInterface};
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use serde_json::{json, Value};

const KEY: &str = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contact_badges_552.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn new_and_the_setters_set_their_fields_552() {
    let bare = Contact::new("Bob", KEY);
    assert_eq!(
        (bare.name.as_str(), bare.identity_key.as_str()),
        ("Bob", KEY)
    );
    assert_eq!(bare.avatar_url, None);
    assert_eq!(bare.added_at, 0);
    assert_eq!(bare.notes, None);
    assert!(bare.tags.is_empty());
    assert_eq!(bare.metadata, None);
    assert_eq!(bare.badge_icon_url, "");
    assert_eq!(bare.badge_label, "");
    assert_eq!(bare.badge_click_url, "");

    let full = Contact::new("Bob", KEY)
        .with_avatar_url("https://example.com/bob.png")
        .with_added_at(1_700_000_000_000)
        .with_notes("met at the conference")
        .with_tags(["work", "friend"])
        .with_metadata(json!({ "source": "import" }))
        .with_badge_icon_url("https://example.com/bob-badge.png")
        .with_badge_label("Met in person")
        .with_badge_click_url("https://example.com/bob");
    assert_eq!(
        full.avatar_url.as_deref(),
        Some("https://example.com/bob.png")
    );
    assert_eq!(full.added_at, 1_700_000_000_000);
    assert_eq!(full.notes.as_deref(), Some("met at the conference"));
    assert_eq!(full.tags, ["work", "friend"]);
    assert_eq!(full.metadata, Some(json!({ "source": "import" })));
    assert_eq!(full.badge_icon_url, "https://example.com/bob-badge.png");
    assert_eq!(full.badge_label, "Met in person");
    assert_eq!(full.badge_click_url, "https://example.com/bob");
}

#[tokio::test]
async fn new_holds_its_values_and_add_contact_refuses_them_552() {
    let manager = ContactsManager::new(Counting::of_scalar(9), ContactsManagerConfig::default());
    let cases = [
        (
            Contact::new("", KEY),
            "Invalid contact: name is empty, oversized, or contains control characters",
        ),
        (
            Contact::new("Bob", "02abc123"),
            "Invalid contact: identityKey must be a canonical compressed public key",
        ),
    ];
    for (contact, words) in cases {
        assert_eq!(
            manager.add_contact(contact).await,
            Err(Error::IdentityError(words.into()))
        );
    }
}

#[tokio::test]
async fn a_contact_built_by_new_writes_the_vectors_record_552() {
    let v = vector();
    let r = &v["reverse"]["contact"];
    assert_eq!(r["avatarURL"], "", "the vector's contact has no avatar");
    let contact = Contact::new(
        r["name"].as_str().unwrap(),
        r["identityKey"].as_str().unwrap(),
    )
    .with_badge_icon_url(r["badgeIconURL"].as_str().unwrap())
    .with_badge_label(r["badgeLabel"].as_str().unwrap())
    .with_badge_click_url(r["badgeClickURL"].as_str().unwrap());

    let wallet = Counting::of_scalar(9);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact).await.unwrap();
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
    let record: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(record, *r, "{}", to_hex(&output.locking_script));
}
