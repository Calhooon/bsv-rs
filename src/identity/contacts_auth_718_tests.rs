#![cfg(test)]
//! #718: `authenticate_contact` reads a listed token as the reference's
//! `#authenticateContactScript` does (`ts-stack@edf6e03`
//! `ContactsManager.ts:431-466`): `PushDrop.decode` at its default position,
//! which never reads the second chunk (`PushDrop.ts:63-121`), then the field
//! count, the ciphertext's and the signature's bounds, the canonical five
//! chunks, the lock. Until #718 the read was the canonical lock-before decode,
//! which refuses an empty script, a key alone, a key without `OP_CHECKSIG`
//! second and a `05` key in its own words before any of the site's checks.
//! Against `tests/vectors/identity_contacts_canonical_718.json`, written by
//! `tests/support/identity_contacts_canonical_718.mjs` under Node v22.18.0:
//! each shape's words as the reference's `getContacts` drops the output. The
//! tokens are built by this crate's PushDrop writer and pinned by the SHA-256
//! the reference recorded for the same shape. The refusal surfaces nowhere
//! else: every caller drops the output or replaces the words, as the
//! reference's do (its `cause` aside).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::ContactsManager;
use crate::identity::ContactsManagerConfig;
use crate::primitives::{from_hex, sha256, to_hex, PrivateKey, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::{LockingScript, ScriptChunk};
use crate::wallet::ProtoWallet;
use crate::Error;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/vectors/identity_contacts_canonical_718.json"
    ))
    .unwrap()
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
    let mut chunks = PushDrop::new(key, fields).lock().chunks().to_vec();
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
    let bytes = script.to_binary();
    assert_eq!(bytes.len() as u64, case["script_bytes"].as_u64().unwrap());
    assert_eq!(
        to_hex(&sha256(&bytes)),
        case["script_sha256"].as_str().unwrap(),
        "{}",
        case["name"]
    );
    script
}

#[tokio::test]
async fn a_contact_token_is_refused_in_the_reference_read_order_and_words_718() {
    let v = vector();
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    let wallet = ProtoWallet::new(Some(PrivateKey::from_bytes(&scalar).unwrap()));
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
    let key_id = v["key_id"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let dropped = case["contacts"]["dropped"].as_array().unwrap();
        assert_eq!(case["contacts"]["contacts"], 0, "{}", case["name"]);
        assert_eq!(dropped.len(), 1, "{}", case["name"]);
        let words = dropped[0].as_str().unwrap();
        let script = token(&v, case);
        assert_eq!(
            manager.authenticate_contact(&script, key_id).await,
            Err(Error::IdentityError(words.into())),
            "{}",
            case["name"]
        );
    }
}
