//! The contacts manager's update and removal sign over the output they
//! authenticated, at the input the wallet bound, and send the reference's
//! requests (#904), against `tests/vectors/contacts_listed_spend.json`
//! (`tests/support/signaction_reference_326.mjs --contacts-listed`, the
//! reference's `ContactsManager` at `ts-stack@edf6e03` under Node v22.18.0).
//!
//! The reference reads the listed output's transaction by the outpoint's
//! txid (`#readListedSource`, `ContactsManager.ts:633-659`), finds the one
//! input of the signable transaction at that outpoint (`#findBoundInput`,
//! `:689-697`), signs it over the source's satoshis and script and keys the
//! spend by that index (`:819-838`, `:987-1005`). Until #904 this crate
//! signed over the BEEF's leading entry at the listed index, at input 0,
//! keyed 0: a contact not yet mined is listed with its ancestors ahead of it
//! (`Transaction::to_beef`, the parent ahead of it), so the update and the removal
//! signed the parent's output, or answered `Unable to update contact` where
//! the parent had no output at the token's index.
//!
//! Three shapes, each listed to the #318 counting wallet of the scalar 9 as
//! the reference's wallet listed it: the token's transaction C after its
//! parent P (P's output 0 the token's own lock at 1000 satoshis, so a
//! verdict against it is the signature's), the token at C's output 1 with P
//! of one output, and the contact's input at index 1 of the signable
//! transaction behind a funding input. Each unlocking script judged by the
//! node's block word against C's output; the removal's requests, signable
//! transaction and unlocking script the reference's byte for byte; the
//! update's the same save the new token's script (its ciphertext drawn
//! here) and the signature over it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, to_hex, PrivateKey};
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{CreateActionArgs, ListOutputsResult, Outpoint, WalletOutput};
use identity_reveal_wallet::Counting;
use serde_json::Value;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contacts_listed_spend.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn contact(name: &str) -> Contact {
    Contact::new(
        name,
        PrivateKey::from_bytes(&{
            let mut k = [0u8; 32];
            k[31] = 3;
            k
        })
        .unwrap()
        .public_key()
        .to_hex(),
    )
    .with_avatar_url("https://example.com/bob.png")
}

/// The listing the reference's wallet answered for `shape`, and the token's
/// transaction read from its BEEF by its txid.
fn listing(shape: &Value) -> (ListOutputsResult, Transaction) {
    let v = vector();
    let beef = from_hex(shape["beef"].as_str().unwrap()).unwrap();
    let txid = shape["txid"].as_str().unwrap();
    let vout = shape["vout"].as_u64().unwrap();
    let child = Transaction::from_beef(&beef, Some(txid)).unwrap();
    assert_eq!(child.id(), txid);
    let listed = ListOutputsResult {
        outputs: vec![WalletOutput {
            satoshis: 1,
            locking_script: None,
            spendable: true,
            custom_instructions: v["token"]["custom_instructions"]
                .as_str()
                .map(str::to_string),
            tags: None,
            outpoint: Outpoint::from_string(&format!("{txid}.{vout}")).unwrap(),
            labels: None,
        }],
        total_outputs: 1,
        beef: Some(beef),
    };
    (listed, child)
}

/// A wallet answering the shape's listing: createAction spends the requested
/// outpoint of the BEEF's transaction (behind the funding input when the
/// shape has one), signAction answers the signed transaction.
fn wallet_for(name: &str) -> (Counting, Transaction, u32) {
    let v = vector();
    let shape = &v["shapes"][name];
    let (listed, child) = listing(shape);
    let vout = shape["vout"].as_u64().unwrap() as u32;
    let mut wallet = Counting::of_scalar(9);
    match shape["funding"].as_str() {
        Some(funding) => {
            let funding = Transaction::from_binary(&from_hex(funding).unwrap()).unwrap();
            // `spending_many` writes its sources in reverse: the funding
            // input at index 0, the contact's at index 1.
            *wallet.spending_many.lock().unwrap() = vec![(child.clone(), vout), (funding, 0)];
        }
        None => wallet.create_from_request = true,
    }
    *wallet.listed.lock().unwrap() = Some(listed);
    *wallet.sign_mode.lock().unwrap() = "signed";
    (wallet, child, vout)
}

/// The node's verdict, under the block word after Chronicle, on input
/// `index` of `spend` spending an output of `satoshis` locked by `lock`.
fn node_verdict(
    spend: &Transaction,
    index: usize,
    lock: &LockingScript,
    satoshis: u64,
    unlock: &[u8],
) -> Result<bool, String> {
    let raw = spend.to_binary();
    let tx = bsv_rs::primitives::bsv::sighash::parse_transaction(&raw).unwrap();
    let input = &tx.inputs[index];
    let other_inputs = tx
        .inputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != index)
        .map(|(_, i)| i.clone())
        .collect();
    let mut node = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: satoshis,
        locking_script: lock.clone(),
        transaction_version: tx.version,
        other_inputs,
        outputs: tx
            .outputs
            .iter()
            .map(|o| bsv_rs::primitives::bsv::sighash::TxOutput {
                satoshis: o.satoshis,
                script: o.script.clone(),
            })
            .collect(),
        input_index: index,
        unlocking_script: UnlockingScript::from_binary(unlock).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    node.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    node.validate().map_err(|e| format!("{e:?}"))
}

/// The spend signAction received: its key and unlocking script, judged
/// against the token's own output in the signable transaction the wallet
/// handed out; the message names the verdict against the parent's output
/// 0 too, the output the base signed.
fn assert_spends_the_token(name: &str, wallet: &Counting, child: &Transaction, vout: u32) {
    let signs = wallet.signs.lock().unwrap().clone();
    assert_eq!(signs.len(), 1, "{name}: one signAction");
    let signable = Transaction::from_atomic_beef(&wallet.pending().unwrap().tx).unwrap();
    let bound = signable
        .inputs()
        .iter()
        .position(|input| {
            input.get_source_txid().unwrap() == child.id() && input.source_output_index == vout
        })
        .unwrap();
    let spends = &signs[0].spends;
    assert_eq!(
        spends.keys().copied().collect::<Vec<_>>(),
        vec![bound as u32],
        "{name}: the spend keyed by the input bound to the outpoint"
    );
    let unlock = &spends[&(bound as u32)].unlocking_script;
    let source = &child.outputs()[vout as usize];
    let verdict = node_verdict(
        &signable,
        bound,
        &source.locking_script,
        source.satoshis.unwrap(),
        unlock,
    );
    let parent = child.inputs()[0].source_transaction.as_ref().map(|p| {
        let output = &p.outputs()[0];
        node_verdict(
            &signable,
            bound,
            &output.locking_script,
            output.satoshis.unwrap(),
            unlock,
        )
    });
    assert_eq!(
        verdict,
        Ok(true),
        "{name}: the unlocking script spends the token's output (against the parent's output 0: {parent:?})"
    );
}

/// createAction's arguments as the reference's JSON, `inputBEEF` as hex.
fn request(args: &CreateActionArgs) -> Value {
    let mut value = serde_json::to_value(args).unwrap();
    if let Some(beef) = value.get("inputBEEF").cloned() {
        let bytes: Vec<u8> = serde_json::from_value(beef).unwrap();
        value["inputBEEF"] = Value::String(to_hex(&bytes));
    }
    value
}

/// The update's request without the new token's script, drawn here.
fn without_new_script(mut value: Value) -> Value {
    for output in value["outputs"].as_array_mut().into_iter().flatten() {
        output.as_object_mut().unwrap().remove("lockingScript");
    }
    value
}

async fn update(name: &str) {
    let (wallet, child, vout) = wallet_for(name);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact("Bob Updated")).await.unwrap();
    assert_spends_the_token(&format!("{name} update"), &wallet, &child, vout);
    let case = &vector()["cases"][format!("{name}_update")];
    assert_eq!(case["outcome"], serde_json::json!({ "ok": true }));
    let creates = wallet.creates.lock().unwrap().clone();
    assert_eq!(
        without_new_script(request(creates.last().unwrap())),
        without_new_script(case["create_action"][0].clone()),
        "{name} update: the reference's createAction"
    );
}

async fn remove(name: &str) {
    let (wallet, child, vout) = wallet_for(name);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager
        .remove_contact(&contact("").identity_key)
        .await
        .unwrap();
    assert_spends_the_token(&format!("{name} remove"), &wallet, &child, vout);
    let case = &vector()["cases"][format!("{name}_remove")];
    assert_eq!(case["outcome"], serde_json::json!({ "ok": true }));
    let creates = wallet.creates.lock().unwrap().clone();
    assert_eq!(
        request(creates.last().unwrap()),
        case["create_action"][0],
        "{name} remove: the reference's createAction"
    );
    // The two doubles write the Atomic BEEF in their own versions (V2 here,
    // V1 there); the transaction the signature binds is the same.
    let theirs =
        Transaction::from_atomic_beef(&from_hex(case["signable"][0].as_str().unwrap()).unwrap())
            .unwrap();
    let ours = Transaction::from_atomic_beef(&wallet.pending().unwrap().tx).unwrap();
    assert_eq!(
        ours.to_hex(),
        theirs.to_hex(),
        "{name} remove: the reference's signable transaction"
    );
    let signs = wallet.signs.lock().unwrap().clone();
    let ours = serde_json::to_value(&signs[0]).unwrap();
    assert_eq!(
        ours["spends"], case["sign_action"][0]["spends"],
        "{name} remove: the reference's unlocking script byte for byte"
    );
    assert_eq!(ours["reference"], case["sign_action"][0]["reference"]);
    assert!(ours.get("options").is_none_or(Value::is_null));
    assert!(case["sign_action"][0].get("options").is_none());
}

#[tokio::test]
async fn an_update_of_a_token_listed_after_its_parent_signs_the_token_output_contacts() {
    update("token_at_0").await;
}

#[tokio::test]
async fn a_removal_of_a_token_listed_after_its_parent_signs_the_token_output_contacts() {
    remove("token_at_0").await;
}

#[tokio::test]
async fn an_update_of_a_token_at_output_1_over_a_one_output_parent_signs_it_contacts() {
    update("token_at_1").await;
}

#[tokio::test]
async fn a_removal_of_a_token_at_output_1_over_a_one_output_parent_signs_it_contacts() {
    remove("token_at_1").await;
}

#[tokio::test]
async fn an_update_signs_the_contact_input_where_the_wallet_bound_it_at_index_1_contacts() {
    update("input_at_1").await;
}

#[tokio::test]
async fn a_removal_signs_the_contact_input_where_the_wallet_bound_it_at_index_1_contacts() {
    remove("input_at_1").await;
}

/// The create path's request is the reference's (`ContactsManager.ts:865-881`):
/// `Add Contact`, `Contact: <name>`, no label, no `signAndProcess`; the
/// token's script and key ID are drawn on each side, so they are left out.
#[tokio::test]
async fn the_create_request_is_the_references_contacts() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![],
        total_outputs: 0,
        beef: None,
    });
    *wallet.create_finished.lock().unwrap() = true;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact("Bob Example")).await.unwrap();
    let create = &vector()["create"];
    assert_eq!(create["outcome"], serde_json::json!({ "ok": true }));
    let strip = |mut value: Value| {
        for output in value["outputs"].as_array_mut().into_iter().flatten() {
            let output = output.as_object_mut().unwrap();
            output.remove("lockingScript");
            output.remove("customInstructions");
        }
        value
    };
    let creates = wallet.creates.lock().unwrap().clone();
    assert_eq!(
        strip(request(&creates[0])),
        strip(create["create_action"][0].clone())
    );
    assert!(manager
        .get_contact(&contact("").identity_key)
        .await
        .unwrap()
        .is_some());
}
