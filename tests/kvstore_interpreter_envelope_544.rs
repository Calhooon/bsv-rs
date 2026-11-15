//! The interpreter returns an entry only for a token its controller signed
//! and its writer locked (the stable line's port of #544's interpreter
//! site): `KVStoreInterpreter::interpret` and `interpret_script` on tokens
//! of this crate's writer (`GlobalKVStore::set`: the raw protocol ID, the
//! key ID `kvstore-token`, locked with the controller's key) and of the
//! canonical form (the protocol ID as JSON `[level, name]`, the entry's key
//! as key ID, locked with the controller's key for `anyone`), each honest
//! with and without tags, and each refused unsigned, signed by another key,
//! locked with another key, or naming its controller by a 65-byte key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "kvstore")]

use bsv_rs::kvstore::{KVStoreContext, KVStoreEntry, KVStoreInterpreter};
use bsv_rs::primitives::{to_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
};

#[derive(Clone, Copy)]
enum Form {
    /// `GlobalKVStore::set`'s token.
    Crate,
    /// The canonical token: `[1, protocol]` as JSON, the key as key ID.
    Canonical,
}

/// The data fields of a token for `controller`.
fn data(form: Form, key: &str, value: &str, controller: &PublicKey, tags: bool) -> Vec<Vec<u8>> {
    let protocol = match form {
        Form::Crate => b"kvstore".to_vec(),
        Form::Canonical => br#"[1,"kvstore"]"#.to_vec(),
    };
    let mut fields = vec![
        protocol,
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.to_compressed().to_vec(),
    ];
    if tags {
        fields.push(br#"["t","u"]"#.to_vec());
    }
    fields
}

/// `signer`'s signature over the fields, in the form's protocol and key ID.
fn sign(form: Form, key: &str, signer: &PrivateKey, fields: &[Vec<u8>]) -> Vec<u8> {
    let key_id = match form {
        Form::Crate => "kvstore-token",
        Form::Canonical => key,
    };
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::App, "kvstore"),
            key_id: key_id.to_string(),
            counterparty: Some(Counterparty::Anyone),
        })
        .unwrap()
        .signature
}

/// The key the form's writer locks a token of `owner`'s with.
fn writer_lock(form: Form, key: &str, owner: &PrivateKey) -> PublicKey {
    match form {
        Form::Crate => owner.public_key(),
        Form::Canonical => KeyDeriver::new(Some(owner.clone()))
            .derive_public_key(
                &Protocol::new(SecurityLevel::App, "kvstore"),
                key,
                &Counterparty::Anyone,
                true,
            )
            .unwrap(),
    }
}

fn token(fields: Vec<Vec<u8>>, signature: Vec<u8>, lock: PublicKey) -> LockingScript {
    let mut fields = fields;
    fields.push(signature);
    PushDrop::new(lock, fields).lock()
}

fn honest(form: Form, controller: &PrivateKey, tags: bool) -> LockingScript {
    let fields = data(form, "k", "v", &controller.public_key(), tags);
    let signature = sign(form, "k", controller, &fields);
    token(fields, signature, writer_lock(form, "k", controller))
}

fn in_a_transaction(script: &LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script.clone()))
        .unwrap();
    tx
}

fn context(form: Form) -> KVStoreContext {
    match form {
        Form::Crate => KVStoreContext::new("k", "kvstore"),
        Form::Canonical => KVStoreContext::new("k", r#"[1,"kvstore"]"#),
    }
}

/// The three reads of a token: `interpret_script` with and without a
/// matching context, and `interpret` of the output in a transaction.
fn reads(form: Form, script: &LockingScript) -> [Option<KVStoreEntry>; 3] {
    let ctx = context(form);
    [
        KVStoreInterpreter::interpret_script(script, None),
        KVStoreInterpreter::interpret_script(script, Some(&ctx)),
        KVStoreInterpreter::interpret(&in_a_transaction(script), 0, Some(&ctx)),
    ]
}

/// How many of the three reads return an entry.
fn read_count(form: Form, script: &LockingScript) -> usize {
    reads(form, script)
        .iter()
        .filter(|read| read.is_some())
        .count()
}

#[test]
fn an_unsigned_token_naming_a_controller_is_no_entry_544() {
    for form in [Form::Crate, Form::Canonical] {
        for tags in [false, true] {
            let controller = PrivateKey::random();
            let fields = data(form, "k", "v", &controller.public_key(), tags);
            for junk in [vec![0x30, 0x01, 0x02], vec![0u8; 64], vec![]] {
                let forged = token(fields.clone(), junk, writer_lock(form, "k", &controller));
                assert_eq!(read_count(form, &forged), 0);
            }
        }
    }
}

#[test]
fn a_token_signed_by_another_key_than_its_controller_is_no_entry_544() {
    for form in [Form::Crate, Form::Canonical] {
        for tags in [false, true] {
            let controller = PrivateKey::random();
            let stranger = PrivateKey::random();
            let fields = data(form, "k", "v", &controller.public_key(), tags);
            let signature = sign(form, "k", &stranger, &fields);
            for lock in [
                writer_lock(form, "k", &controller),
                writer_lock(form, "k", &stranger),
            ] {
                let forged = token(fields.clone(), signature.clone(), lock);
                assert_eq!(read_count(form, &forged), 0);
            }
        }
    }
}

#[test]
fn a_signed_token_locked_with_another_key_is_no_entry_544() {
    for form in [Form::Crate, Form::Canonical] {
        for tags in [false, true] {
            let controller = PrivateKey::random();
            let stranger = PrivateKey::random();
            let fields = data(form, "k", "v", &controller.public_key(), tags);
            let signature = sign(form, "k", &controller, &fields);
            for lock in [
                stranger.public_key(),
                writer_lock(form, "k", &stranger),
                // the other form's lock of the controller
                match form {
                    Form::Crate => writer_lock(Form::Canonical, "k", &controller),
                    Form::Canonical => controller.public_key(),
                },
            ] {
                let moved = token(fields.clone(), signature.clone(), lock);
                assert_eq!(read_count(form, &moved), 0);
            }
        }
    }
}

#[test]
fn a_token_its_controller_signed_reads_to_its_entry_with_and_without_tags_544() {
    for form in [Form::Crate, Form::Canonical] {
        for tags in [false, true] {
            let controller = PrivateKey::random();
            let script = honest(form, &controller, tags);
            let protocol_id = match form {
                Form::Crate => "kvstore",
                Form::Canonical => r#"[1,"kvstore"]"#,
            };
            let expected = KVStoreEntry::new(
                "k",
                "v",
                to_hex(&controller.public_key().to_compressed()),
                protocol_id,
            )
            .with_tags(if tags {
                vec!["t".to_string(), "u".to_string()]
            } else {
                Vec::new()
            });
            for read in reads(form, &script) {
                let read = read.expect("an honest token reads");
                assert_eq!(
                    (
                        &read.key,
                        &read.value,
                        &read.controller,
                        &read.protocol_id,
                        &read.tags
                    ),
                    (
                        &expected.key,
                        &expected.value,
                        &expected.controller,
                        &expected.protocol_id,
                        &expected.tags
                    )
                );
            }
        }
    }
}

/// A controller field holding the controller's key uncompressed (65 bytes)
/// is no entry, though the controller signed the token and its writer locked
/// it: the controller is read as a 33-byte key alone.
#[test]
fn a_controller_field_of_65_bytes_is_no_entry_544() {
    for form in [Form::Crate, Form::Canonical] {
        for tags in [false, true] {
            let controller = PrivateKey::random();
            let mut fields = data(form, "k", "v", &controller.public_key(), tags);
            fields[3] = controller.public_key().to_uncompressed().to_vec();
            let signature = sign(form, "k", &controller, &fields);
            let script = token(fields, signature, writer_lock(form, "k", &controller));
            assert_eq!(read_count(form, &script), 0);
        }
    }
}

#[test]
fn a_field_changed_after_signing_is_no_entry_544() {
    for form in [Form::Crate, Form::Canonical] {
        let controller = PrivateKey::random();
        let fields = data(form, "k", "v", &controller.public_key(), true);
        let signature = sign(form, "k", &controller, &fields);
        for index in [2, 4] {
            let mut changed = fields.clone();
            changed[index] = match index {
                2 => b"w".to_vec(),
                _ => br#"["x"]"#.to_vec(),
            };
            let script = token(
                changed,
                signature.clone(),
                writer_lock(form, "k", &controller),
            );
            assert_eq!(read_count(form, &script), 0);
        }
    }
}

/// The kvstore cases of `tests/vectors/token_envelope_544.json`
/// (`tests/support/token_envelope_544.mjs`) this port judges: the canonical
/// writer's token with and without tags reads to its value; the raw-protocol
/// variant (its signature no longer covers its fields), the unsigned, the
/// wrongly locked and the wrongly signed ones are no entry.
/// `noncanonical_envelope` is an envelope's form, not a token's author: the
/// stable line reads it as it did, and it is outside this file.
#[test]
fn the_vectors_signed_tokens_read_and_their_unauthenticated_variants_do_not_544() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let key = v["kvstore"]["context"]["key"].as_str().unwrap();
    let ctx = KVStoreContext::new(key, r#"[1,"kvstore"]"#);
    let judged = [
        "reference",
        "reference_tags",
        "raw_protocol",
        "unsigned",
        "wrong_lock_key",
        "bad_signature",
    ];
    let mut seen = 0;
    for case in v["kvstore"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if !judged.contains(&name) {
            continue;
        }
        seen += 1;
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let expected = case["value"].as_str();
        for read in [
            KVStoreInterpreter::interpret_script(&script, None),
            KVStoreInterpreter::interpret_script(&script, Some(&ctx)),
            KVStoreInterpreter::interpret(&in_a_transaction(&script), 0, Some(&ctx)),
        ] {
            assert_eq!(read.map(|entry| entry.value).as_deref(), expected, "{name}");
        }
    }
    assert_eq!(seen, judged.len());
}
