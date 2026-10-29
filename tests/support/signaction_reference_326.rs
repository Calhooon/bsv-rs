//! The #326 comparison: a client's signAction arguments against the
//! reference's (`tests/vectors/signaction_reference_326.json`, recorded by
//! `tests/support/signaction_reference_326.mjs` at `ts-stack@edf6e03`).
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_base64, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{CreateActionOptions, SignActionArgs};
use serde_json::{json, Map, Value};

pub fn signature_requests(args: &[bsv_rs::wallet::CreateSignatureArgs]) -> Value {
    Value::Array(args.iter().map(|a| {
        let mut request = json!({
            "protocolID": [a.protocol_id.security_level as u8, a.protocol_id.protocol_name],
            "keyID": a.key_id,
            "counterparty": match a.counterparty.as_ref().unwrap() { bsv_rs::wallet::Counterparty::Self_ => "self".into(), bsv_rs::wallet::Counterparty::Anyone => "anyone".into(), bsv_rs::wallet::Counterparty::Other(key) => key.to_hex() },
        });
        if let Some(data) = &a.data { request["data"] = json!(data); }
        if let Some(hash) = a.hash_to_directly_sign { request["hashToDirectlySign"] = json!(hash); }
        request
    }).collect())
}

pub fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/signaction_reference_326.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A token's source: one made-up input, output 0 the token.
pub fn source_of(lock: &[u8], satoshis: u64) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.add_input(input).unwrap();
    let lock = LockingScript::from_binary(lock).unwrap();
    tx.add_output(TransactionOutput::new(satoshis, lock))
        .unwrap();
    tx
}

/// `completeBoundAction`'s signAction options from a createAction's options
/// as JSON (`completeBoundAction.ts:1111-1116`): the three carried members
/// where present, `returnTXIDOnly` false.
fn carried(create: &Value) -> Value {
    let mut out = Map::new();
    for member in ["acceptDelayedBroadcast", "noSend", "sendWith"] {
        if let Some(v) = create.get(member) {
            out.insert(member.to_string(), v.clone());
        }
    }
    out.insert("returnTXIDOnly".to_string(), json!(false));
    Value::Object(out)
}

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

/// The reference's case `case` against this crate's signAction `ours` and
/// the options of the createAction it completed (`create`): the reference
/// the text the wallet answered, the members and the spend indexes the
/// reference's, each spend's unlocking script aside; the options the
/// reference's rule applied to each side's own createAction.
pub fn assert_reference_sign_metadata(
    name: &str,
    case: &Value,
    ours: &SignActionArgs,
    create: Option<&CreateActionOptions>,
) {
    let text = vector()["signable_reference"].as_str().unwrap().to_string();
    let theirs: Value = serde_json::from_str(case["sign_action_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        theirs["reference"],
        json!(text),
        "{name}: the reference's own"
    );

    assert_eq!(
        ours.reference, text,
        "{name}: the reference as the wallet answered it, its base64 text"
    );
    assert_ne!(
        ours.reference,
        to_hex(&from_base64(&text).unwrap()),
        "{name}: not the hex of its bytes"
    );

    let mut mine = serde_json::to_value(ours).unwrap();
    assert_eq!(
        sorted_keys(&mine),
        sorted_keys(&theirs),
        "{name}: the members"
    );
    assert_eq!(
        sorted_keys(&mine["spends"]),
        sorted_keys(&theirs["spends"]),
        "{name}: the spend indexes"
    );
    for (index, spend) in theirs["spends"].as_object().unwrap() {
        assert_eq!(
            sorted_keys(&mine["spends"][index]),
            sorted_keys(spend),
            "{name}: spend {index}'s members"
        );
        mine["spends"][index]["unlockingScript"] = spend["unlockingScript"].clone();
    }

    match theirs.get("options") {
        None => {
            assert!(
                ours.options.is_none(),
                "{name}: no options, as the reference"
            );
            assert_eq!(mine, theirs, "{name}: member by member");
        }
        Some(their_options) => {
            let their_create = &case["create_action_options"];
            assert_eq!(
                *their_options,
                carried(their_create),
                "{name}: the reference's options carried from its createAction's"
            );
            let our_create = create
                .map(|o| serde_json::to_value(o).unwrap())
                .unwrap_or_else(|| json!({}));
            assert_eq!(
                mine["options"],
                carried(&our_create),
                "{name}: the options carried from this crate's createAction's"
            );
            let members: Vec<&str> = case["sign_action_option_members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap())
                .collect();
            for member in sorted_keys(&mine["options"]) {
                assert!(members.contains(&member.as_str()), "{name}: {member}");
            }
            mine["options"] = their_options.clone();
            assert_eq!(mine, theirs, "{name}: member by member, the options aside");
        }
    }
}

/// Compare signatures as well when both wallets spend the recorded transaction.
pub fn assert_reference_sign(
    name: &str,
    case: &Value,
    ours: &SignActionArgs,
    create: Option<&CreateActionOptions>,
) {
    assert_eq!(
        serde_json::to_value(&ours.spends).unwrap(),
        case["sign_action"]["spends"],
        "{name}: unlocking scripts byte for byte"
    );
    assert_reference_sign_metadata(name, case, ours, create);
}
