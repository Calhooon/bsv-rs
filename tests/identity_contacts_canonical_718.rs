//! #718: the identity and contacts sites' canonical PushDrop checks against
//! their reference counterparts at `ts-stack@edf6e03`, none of which calls
//! `decodeCanonicalPushDrop`: each reads with `PushDrop.decode` at its
//! default position and runs its own count, bounds and envelope. Against
//! `tests/vectors/identity_contacts_canonical_718.json` (written by
//! `tests/support/identity_contacts_canonical_718.mjs`, Node v22.18.0), on
//! ten token shapes built by this crate's PushDrop writer and pinned by the
//! SHA-256 the reference recorded:
//! - the revocation (`IdentityClient.ts:768-829`): every shape skipped, the
//!   run refused in `No authenticated revelation output matches the
//!   requested certificate.`, here as there;
//! - the two `ls_identity` parsers, the counterparts of the toolbox's
//!   `decodeIdentityOutput` (`identityUtils.ts:497-559`, every refusal under
//!   its `try` a `null`, read and not run): every shape skipped;
//! - the contacts listing (`getContacts`, `ContactsManager.ts:475-514`):
//!   every shape dropped. The words of the drop are the unit test
//!   `identity::contacts::auth::canonical_718_tests`'s, RED before #718.
//!
//! Hermetic: in-process wallets, resolvers on `.invalid` hosts.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::{ContactsManager, ContactsManagerConfig, IdentityClient};
use bsv_rs::primitives::{from_hex, sha256, to_hex, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, ScriptChunk};
use bsv_rs::wallet::{ListOutputsResult, Outpoint, ProtoWallet, WalletOutput};
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use indexmap::IndexMap;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_contacts_canonical_718.json")).unwrap()
}

/// The case's token by this crate's writer: `PushDrop::lock` of the key and
/// the fields, its first chunk and its second as the case names them.
fn token(v: &Value, case: &Value) -> LockingScript {
    let key = PublicKey::from_hex(v["key"].as_str().unwrap()).unwrap();
    let byte = v["field_byte"].as_u64().unwrap() as u8;
    let fields: Vec<Vec<u8>> = case["field_lengths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|length| vec![byte; length.as_u64().unwrap() as usize])
        .collect();
    let mut chunks = PushDrop::new(key, fields).lock().chunks();
    match case["second_op"].as_u64() {
        Some(op) => chunks[1] = ScriptChunk::new_opcode(op as u8),
        None => {
            chunks.remove(1);
        }
    }
    match case["first"].as_str().unwrap() {
        "key" => {}
        "bad_key" => {
            let bad = from_hex(v["bad_key"].as_str().unwrap()).unwrap();
            chunks[0] = ScriptChunk::new(bad.len() as u8, Some(bad));
        }
        "nop" => chunks[0] = ScriptChunk::new_opcode(0x61),
        "none" => {
            chunks.remove(0);
        }
        other => panic!("no first chunk {other}"),
    }
    let script = LockingScript::from_chunks(chunks);
    assert_eq!(
        to_hex(&sha256(&script.to_binary())),
        case["script_sha256"].as_str().unwrap(),
        "{}",
        case["name"]
    );
    script
}

fn cases(v: &Value) -> Vec<Value> {
    let cases = v["cases"].as_array().unwrap().clone();
    assert_eq!(cases.len(), 10);
    cases
}

#[tokio::test]
async fn the_revocation_skips_every_shape_as_the_reference_does_718() {
    let v = vector();
    for case in cases(&v) {
        let resolver = lock_position::answering("ls_identity", token(&v, &case));
        let client =
            IdentityClient::with_resolver(Counting::of_scalar(9), Default::default(), resolver);
        let words = case["revocation_words"].as_str().unwrap();
        assert_eq!(
            client
                .revoke_certificate_revelation(v["serial_number"].as_str().unwrap())
                .await,
            Err(Error::IdentityError(words.into())),
            "{}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn the_identity_parsers_skip_every_shape_as_the_reference_discovery_does_718() {
    let v = vector();
    let subject = v["key"].as_str().unwrap();
    for case in cases(&v) {
        let resolver = lock_position::answering("ls_identity", token(&v, &case));
        let client =
            IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
        let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
        let identities = client
            .resolve_by_attributes(attributes, false)
            .await
            .unwrap();
        let certificates = client.discover_certificates(subject).await.unwrap();
        assert_eq!(
            (identities.len(), certificates.len()),
            (0, 0),
            "{}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn the_contacts_listing_drops_every_shape_as_the_reference_does_718() {
    let v = vector();
    let instructions = serde_json::json!({ "keyID": v["key_id"] }).to_string();
    for case in cases(&v) {
        assert_eq!(case["contacts"]["contacts"], 0, "{}", case["name"]);
        let wallet = Counting::of_scalar(9);
        *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
            total_outputs: 1,
            beef: None,
            outputs: vec![WalletOutput {
                outpoint: Outpoint::from_string(&format!("{}.0", "22".repeat(32))).unwrap(),
                satoshis: 1,
                locking_script: Some(token(&v, &case).to_binary()),
                spendable: true,
                tags: None,
                labels: None,
                custom_instructions: Some(instructions.clone()),
            }],
        });
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
        let contacts = manager.list_contacts_with_refresh(true).await.unwrap();
        assert!(contacts.is_empty(), "{}", case["name"]);
    }
}
