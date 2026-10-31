//! #548: the registry client unlocks a definition token on revoke and update
//! as the reference does (`ts-stack@edf6e03` `RegistryClient.ts:540-548`,
//! `:630-639`): `PushDrop.unlock(protocol, '1', 'anyone', 'all', false,
//! satoshis, lockingScript)` (`PushDrop.ts:217-262`), one push of the
//! wallet's signature over the spend under SIGHASH_ALL | FORKID, keyed by the
//! token's index in the signable transaction; an empty script before #548.
//! The reference's scripts are recorded by
//! `tests/support/registry_unlocking_548.mjs` from its own `removeDefinition`
//! and `updateDefinition` with a `ProtoWallet` of the scalar 9 (RFC 6979: the
//! bytes compared), each spend valid in the reference's interpreter; the
//! wallet in process answers createAction with the recorded signable
//! transaction (the token at input 1, a funding input at 0) and signAction
//! with no transaction, so nothing is broadcast.
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/registry_token_fields_543.rs"]
mod token_fields;

use bsv_rs::primitives::bsv::sighash::parse_transaction;
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::registry::{RegistryClient, RegistryClientConfig, RegistryRecord, TokenData};
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::transaction::{Beef, Transaction};
use bsv_rs::wallet::{Counterparty, Protocol, SecurityLevel, SignableTransaction};
use identity_reveal_wallet::Counting;
use serde_json::{json, Value};

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/registry_unlocking_548.json")).unwrap()
}

/// The record the reference was given: its definition, the operator its
/// wallet's identity key, the token at output 0 of the recorded source.
fn record(case: &Value, operator: &str) -> RegistryRecord {
    let mut definition = token_fields::definition(case);
    definition.set_registry_operator(operator.to_string());
    let source = Transaction::from_hex(case["source_tx"].as_str().unwrap()).unwrap();
    let mut beef = Beef::new();
    beef.merge_transaction(source);
    let token = TokenData::with_beef(
        case["txid"].as_str().unwrap().to_string(),
        0,
        1,
        case["locking_script"].as_str().unwrap().to_string(),
        beef.to_binary(),
    );
    RegistryRecord::new(definition, token)
}

/// The spends and the last createSignature this crate's client sends for
/// the case's operation over the recorded signable transaction.
async fn spend(case: &Value, operator: &str) -> (Vec<(u32, String)>, Counting) {
    let mut wallet = Counting::of_scalar(9);
    wallet.signable = Some(SignableTransaction {
        tx: from_hex(case["signable_tx"].as_str().unwrap()).unwrap(),
        reference: vec![0x52; 8],
    });
    let client = RegistryClient::new(wallet.clone(), RegistryClientConfig::new());
    let record = record(case, operator);
    let stopped = match case["operation"].as_str().unwrap() {
        "revoke" => client.revoke_own_registry_entry(&record).await.map(|_| ()),
        _ => {
            let updated = json!({
                "definition_type": case["definition_type"],
                "definition": case["updated"],
            });
            (client.update_definition(&record, token_fields::definition(&updated)))
                .await
                .map(|_| ())
        }
    };
    // signAction answers no transaction: the client stops before a broadcast.
    assert!(stopped.is_err());
    let signs = wallet.signs.lock().unwrap().clone();
    assert_eq!(signs.len(), 1);
    let mut spends: Vec<_> = signs[0]
        .spends
        .iter()
        .map(|(index, spend)| (*index, to_hex(&spend.unlocking_script)))
        .collect();
    spends.sort();
    (spends, wallet)
}

#[tokio::test]
async fn a_revoke_and_an_update_unlock_the_definition_token_as_the_reference_does_548() {
    let vector = vector();
    let operator = vector["operator"].as_str().unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name = format!("{} {}", case["definition_type"], case["operation"]);
        assert_eq!(case["reference_verdict"]["valid"], true, "{name}");
        let (spends, wallet) = spend(case, operator).await;
        let expected = vec![(
            case["spend_index"].as_u64().unwrap() as u32,
            case["unlocking_script"].as_str().unwrap().to_string(),
        )];
        assert_eq!(spends, expected, "{name}");

        // The unlocker's createSignature, the reference's arguments.
        let asked = &case["create_signature"];
        let signature = wallet
            .signature_args
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let level = asked["protocolID"][0].as_u64().unwrap();
        assert_eq!(level, 1, "{name}");
        let protocol = Protocol::new(SecurityLevel::App, asked["protocolID"][1].as_str().unwrap());
        assert_eq!(signature.protocol_id, protocol, "{name}");
        assert_eq!(signature.key_id, asked["keyID"].as_str().unwrap(), "{name}");
        assert_eq!(asked["counterparty"], "anyone", "{name}");
        assert_eq!(signature.counterparty, Some(Counterparty::Anyone), "{name}");
        assert_eq!(
            to_hex(signature.data.as_ref().unwrap()),
            asked["data"].as_str().unwrap(),
            "{name}"
        );
    }
}

/// The spend this crate signs is valid under the node's block word after
/// Chronicle, as the reference's interpreter judges the recorded one.
#[tokio::test]
async fn the_spend_this_crate_signs_unlocks_the_token_548() {
    let vector = vector();
    let operator = vector["operator"].as_str().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = format!("{} {}", case["definition_type"], case["operation"]);
        let (spends, _) = spend(case, operator).await;
        let (index, script) = &spends[0];
        let signable = from_hex(case["signable_tx"].as_str().unwrap()).unwrap();
        let tx = parse_transaction(
            &Transaction::from_atomic_beef(&signable)
                .unwrap()
                .to_binary(),
        )
        .unwrap();
        let index = *index as usize;
        let input = &tx.inputs[index];
        let mut node = Spend::new(SpendParams {
            source_txid: input.txid,
            source_output_index: input.output_index,
            source_satoshis: 1,
            locking_script: LockingScript::from_hex(case["locking_script"].as_str().unwrap())
                .unwrap(),
            transaction_version: tx.version,
            other_inputs: (tx.inputs.iter().enumerate())
                .filter(|(i, _)| *i != index)
                .map(|(_, input)| input.clone())
                .collect(),
            outputs: tx.outputs.clone(),
            input_index: index,
            unlocking_script: UnlockingScript::from_hex(script).unwrap(),
            input_sequence: input.sequence,
            lock_time: tx.locktime,
            memory_limit: None,
            work_limit: None,
        });
        node.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        assert!(matches!(node.validate(), Ok(true)), "{name}");
    }
}

/// signAction carries the signable transaction's reference as the base64
/// text the wallet answered (`completeBoundAction.ts:1044-1051`, `:1118`;
/// BRC-100's `Base64String`), as the key-value stores and the contacts
/// manager send it; the UTF-8 reading of its bytes before #548's review.
#[tokio::test]
async fn a_revoke_and_an_update_send_sign_action_the_base64_reference_548() {
    let vector = vector();
    let operator = vector["operator"].as_str().unwrap();
    let expected = vector["signable_reference"].as_str().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = format!("{} {}", case["definition_type"], case["operation"]);
        let (_, wallet) = spend(case, operator).await;
        let signs = wallet.signs.lock().unwrap().clone();
        assert_eq!(signs[0].reference, expected, "{name}");
    }
}
