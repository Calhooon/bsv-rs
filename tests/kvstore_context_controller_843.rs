//! The KVStore interpreter matches a token's controller against its context,
//! as the reference's does (#843, closing #544's residue).
//!
//! The reference's `KVContext` carries `key`, `protocolID` and `controller`
//! (`kvStoreInterpreter.ts:6-10` at `ts-stack@edf6e03`, the same at its head
//! `11faa7d16`), and its interpreter answers a value only for a token whose
//! key, protocol and controller are the context's, the controller compared in
//! lower case (`:39-46`). Until #843 `KVStoreContext` had no controller, so a
//! context read a token of any controller.
//!
//! The reference's recording is `vectors/token_envelope_544.json`'s `kvstore`
//! group: its context names the controller the cases' values were recorded
//! under. The other controller is the reference's own test's
//! (`__tests/kvStoreInterpreter.test.ts:259-267`, `03` and `11` thirty-two
//! times). The second test builds its token with this crate's own signer and
//! writer.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::kvstore::{KVStoreContext, KVStoreInterpreter};
use bsv_rs::primitives::{sha256, PrivateKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionOutput};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel,
};
use serde_json::Value;

/// The reference's own test's other controller.
fn other_controller() -> String {
    format!("03{}", "11".repeat(32))
}

fn holding(script: LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    tx
}

#[test]
fn the_interpreter_matches_the_controller_as_the_reference_does_843() {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let kvstore = &vector["kvstore"];
    let key = kvstore["context"]["key"].as_str().unwrap();
    let controller = kvstore["context"]["controller"].as_str().unwrap();
    let cases = kvstore["cases"].as_array().unwrap();
    let mut read = 0;
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let tx = holding(script);
        let answer = |controller: String| {
            let ctx = KVStoreContext::new(key, "kvstore", controller);
            KVStoreInterpreter::interpret(&tx, 0, Some(&ctx)).map(|entry| entry.value)
        };
        let name = &case["name"];
        // The recorded context: the reference's value, or none.
        assert_eq!(
            answer(controller.to_string()).as_deref(),
            case["value"].as_str(),
            "{name}"
        );
        // Compared in lower case on both sides (`:43`).
        assert_eq!(
            answer(controller.to_uppercase()).as_deref(),
            case["value"].as_str(),
            "{name}, the controller in upper case"
        );
        // Another controller's context reads no value (`:43-45`).
        assert_eq!(answer(other_controller()), None, "{name}");
        // A context naming no controller reads none either (`:35`, where the
        // reference answers nothing for a null controller).
        assert_eq!(answer(String::new()), None, "{name}");
        read += usize::from(case["value"].is_string());
    }
    assert_eq!((cases.len(), read), (7, 2), "the recording's census");
}

/// A token in the reference's form (#544), built by this crate's signer and
/// writer: `[1, "kvstore"]`, the key, the value, the controller, then the
/// controller's signature for `anyone`, locked with its key for `anyone`.
fn token(controller: &PrivateKey, key: &str, value: &str) -> LockingScript {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let protocol = Protocol::new(SecurityLevel::App, "kvstore");
    let mut fields = vec![
        br#"[1,"kvstore"]"#.to_vec(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.public_key().to_compressed().to_vec(),
    ];
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key.to_owned(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = wallet
        .key_deriver()
        .derive_public_key(&protocol, key, &Counterparty::Anyone, true)
        .unwrap();
    PushDrop::new(lock, fields).lock()
}

#[test]
fn a_context_reads_its_own_controllers_token_alone_843() {
    let seeded = |label: &str| PrivateKey::from_bytes(&sha256(label.as_bytes())).unwrap();
    let (ours, theirs) = (seeded("controller 843 a"), seeded("controller 843 b"));
    let script = token(&ours, "k1", "v");
    let context = |key: &str, protocol: &str, controller: &PrivateKey| {
        KVStoreContext::new(key, protocol, controller.public_key().to_hex())
    };
    let read = |ctx: &KVStoreContext| {
        KVStoreInterpreter::interpret_script(&script, Some(ctx)).map(|entry| entry.value)
    };
    assert_eq!(read(&context("k1", "kvstore", &ours)).as_deref(), Some("v"));
    // Each member alone decides: another key, protocol or controller reads none.
    assert_eq!(read(&context("k2", "kvstore", &ours)), None);
    assert_eq!(read(&context("k1", "another store", &ours)), None);
    assert_eq!(read(&context("k1", "kvstore", &theirs)), None);
    // The context is its three members, and its cache key holds all three,
    // the controller in lower case as the match reads it.
    let ctx = KVStoreContext::new("k1", "kvstore", "02AB");
    assert_eq!(
        (
            ctx.key.as_str(),
            ctx.protocol_id.as_str(),
            ctx.controller.as_str()
        ),
        ("k1", "kvstore", "02AB")
    );
    assert_eq!(ctx.cache_key(), "kvstore:k1:02ab");
    assert_ne!(
        context("k1", "kvstore", &ours).cache_key(),
        context("k1", "kvstore", &theirs).cache_key()
    );
    // No context: any token is read (this crate's own door, stated: the
    // reference's interpreter answers nothing without a context).
    assert_eq!(
        KVStoreInterpreter::interpret_script(&script, None).map(|entry| entry.value),
        Some("v".to_string())
    );
}
