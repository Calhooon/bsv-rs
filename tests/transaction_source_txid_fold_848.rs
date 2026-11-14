//! #848's fold, on the cells `support/source_txid_mismatch_848.mjs` records
//! beside #848's (Node v22.18.0, `ts-stack@edf6e03`), every fixture built here
//! by this crate's own writers, its bytes the recording's.
//!
//! `templates`: the reference's fourth comparison, its stock templates'
//! `resolveSourceDetails` (`script/templates/SignatureUtils.ts:94-106`), which
//! refuses an input whose `sourceTXID` is not its linked source's id, a
//! descriptor without inputs included, at P2PKH, PushDrop, RPuzzle and the
//! overlay admin template. This crate's `sign` signs such a descriptor (the
//! input `add_input_from` and `add_inputs_from_utxos` build, and `from_ef`'s):
//! stated, held cell by cell. Its signature is the one the reference makes
//! for the named outpoint handed to the template with no source
//! (`named_alone`), byte for byte.
//!
//! `verify_fold`: `Transaction::verify` refuses, in the reference's words, an
//! input that links no source (`Transaction.ts:1396-1400`), whatever another
//! input links, and an amount absent or past 21e14 and a total past 21e14
//! (`requireSatoshiAmount`, `addSatoshiAmount`; `:1414-1418`, `:1464-1474`),
//! the outputs read before the inputs (`:1367`). Until the fold the unlinked
//! input was judged against another input's source when one was reachable,
//! `Ok(true)`, and an absent amount was read as 0.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bsv_rs::primitives::{from_hex, to_hex, BigNumber, PrivateKey};
use bsv_rs::script::templates::{PushDrop, RPuzzle, P2PKH};
use bsv_rs::script::{
    LockingScript, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, UnlockingScript,
};
use bsv_rs::transaction::{
    AlwaysValidChainTracker, Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput,
    TransactionOutput,
};
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/source_txid_mismatch_848.json");
const MAX: u64 = 2_100_000_000_000_000;

fn doc() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn other() -> String {
    "ab".repeat(32)
}

fn empty() -> Option<UnlockingScript> {
    Some(UnlockingScript::from_binary(&[]).unwrap())
}

fn one(sats: u64) -> TransactionOutput {
    TransactionOutput::new(sats, LockingScript::from_binary(&[0x51]).unwrap())
}

fn bump(txid: &str) -> MerklePath {
    MerklePath::new(
        100,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// The recorder's `root`: one input naming `fill` repeated, `outs` outputs,
/// proven by a path of its own.
fn root(fill: &str, sats: u64, outs: usize) -> Transaction {
    let mut t = Transaction::new();
    let mut i = TransactionInput::new(fill.repeat(32).parse().unwrap(), 0);
    i.unlocking_script = empty();
    t.add_input(i).unwrap();
    for _ in 0..outs {
        t.add_output(one(sats)).unwrap();
    }
    t.merkle_path = Some(bump(&t.id()));
    t
}

/// An input linking `src` at `vout` and naming `named` (its id when `None`).
fn link(src: Transaction, named: Option<String>, vout: u32) -> TransactionInput {
    let named = named.unwrap_or_else(|| src.id());
    let mut i = TransactionInput::with_source_transaction(src, vout);
    i.source_txid = Some(named.parse().unwrap());
    i.unlocking_script = empty();
    i
}

/// The recorder's `middle`: a complete unproven source spending `src`'s
/// output 0.
fn middle(src: Transaction, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    t.add_input(link(src, None, 0)).unwrap();
    t.add_output(one(sats)).unwrap();
    t
}

fn child(inputs: Vec<TransactionInput>) -> Transaction {
    let mut t = Transaction::new();
    for i in inputs {
        t.add_input(i).unwrap();
    }
    t.add_output(one(5)).unwrap();
    t
}

fn tracker() -> AlwaysValidChainTracker {
    AlwaysValidChainTracker::new(1000)
}

fn verify(tx: &Transaction) -> Result<bool, String> {
    futures::executor::block_on(tx.verify(&tracker(), None, None)).map_err(|e| e.to_string())
}

fn sign(tx: &mut Transaction) -> Result<(), String> {
    futures::executor::block_on(tx.sign()).map_err(|e| e.to_string())
}

/// The recorded answer as this crate writes it: an error in the reference's
/// words behind `TransactionError`'s prefix.
fn recorded(answer: &Value) -> Result<Value, String> {
    match answer.get("error") {
        Some(words) => Err(format!("transaction error: {}", words.as_str().unwrap())),
        None => Ok(answer["ok"].clone()),
    }
}

// ---- the templates' cells -------------------------------------------------

fn key() -> PrivateKey {
    PrivateKey::from_hex(doc()["templates"]["key_hex"].as_str().unwrap()).unwrap()
}

fn lock() -> LockingScript {
    P2PKH::new().lock(&key().public_key().hash160()).unwrap()
}

/// The source the recorder's `completeSource` builds: spends a proven root,
/// output 0 empty, the claimed output at 1.
fn complete_source() -> Transaction {
    let mut t = Transaction::new();
    t.add_input(link(root("11", 1000, 1), None, 0)).unwrap();
    t.add_output(TransactionOutput::new(0, LockingScript::new()))
        .unwrap();
    t.add_output(TransactionOutput::new(900, lock())).unwrap();
    t
}

/// The template a recorded name stands for. The overlay admin template has
/// no twin here (it signs through PushDrop over a wallet): a counting
/// template stands for it, so its cell holds `sign`'s own answer.
fn template(name: &str, calls: &Arc<AtomicUsize>) -> ScriptTemplateUnlock {
    match name {
        "P2PKH" => P2PKH::unlock(&key(), SignOutputs::All, false),
        "PushDrop" => {
            let derived = KeyDeriver::new(Some(key()))
                .derive_private_key(
                    &Protocol::new(SecurityLevel::Counterparty, "source txid test"),
                    "1",
                    &Counterparty::Self_,
                )
                .unwrap();
            PushDrop::unlock(&derived, SignOutputs::All, false)
        }
        "RPuzzle" => RPuzzle::unlock(&BigNumber::from_u64(12345), &key(), SignOutputs::All, false),
        "OverlayAdminTokenTemplate" => {
            let calls = calls.clone();
            ScriptTemplateUnlock::new(
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(UnlockingScript::from_binary(&[]).unwrap())
                },
                || 0,
            )
        }
        other => panic!("template {other} recorded"),
    }
}

/// A template cell built here, before any template is set (the recording's
/// `built`, an empty unlocking script on input 0).
fn build_template_cell(cell: &Value) -> Transaction {
    let mut t = match cell["cell"].as_str().unwrap() {
        "descriptor" => {
            // The input `add_input_from` builds: a source with no input,
            // output 0 empty, the claimed output at 1.
            let mut t = Transaction::new();
            t.add_input_from(
                &other(),
                1,
                &lock(),
                900,
                P2PKH::unlock(&key(), SignOutputs::All, false),
            )
            .unwrap();
            t.add_output(one(5)).unwrap();
            t
        }
        "complete" => child(vec![link(complete_source(), Some(other()), 1)]),
        "from_ef" => {
            Transaction::from_ef(&from_hex(cell["built"]["ef"].as_str().unwrap()).unwrap()).unwrap()
        }
        "named_alone" => {
            let mut i = TransactionInput::new(other().parse().unwrap(), 1);
            i.unlocking_script = empty();
            child(vec![i])
        }
        other => panic!("cell {other} recorded"),
    };
    t.inputs_mut()[0].unlocking_script = empty();
    t.inputs_mut()[0].unlocking_script_template = None;
    t
}

fn template_cells() -> Vec<Value> {
    doc()["templates"]["cells"].as_array().unwrap().clone()
}

#[test]
fn every_template_cell_is_built_here_byte_for_byte_848() {
    let cells = template_cells();
    assert_eq!(
        cells.len(),
        14,
        "four templates, three cells each, two controls"
    );
    for cell in &cells {
        let t = build_template_cell(cell);
        let name = format!("{} {}", cell["template"], cell["cell"]);
        assert_eq!(cell["built"]["hex"].as_str().unwrap(), t.to_hex(), "{name}");
        match cell["built"]["ef"].as_str() {
            Some(ef) => assert_eq!(ef, to_hex(&t.to_ef().unwrap()), "{name}"),
            None => assert!(t.to_ef().is_err(), "{name}: no source, no EF"),
        }
    }
}

#[test]
fn the_reference_stock_templates_refuse_a_descriptor_source_this_crate_signs_stated_848() {
    // The reference's words at its four templates, a descriptor (the
    // `add_input_from` input) and a `fromEF` transaction alike; this crate's
    // `sign` signs both: `SigningContext` reads no linked source, and the
    // descriptor is how this crate hands a template a claimed outpoint's
    // amount and script.
    let template_words = "The input sourceTXID does not match the input sourceTransaction.";
    let mut held = 0;
    for cell in template_cells() {
        let kind = cell["cell"].as_str().unwrap();
        if kind != "descriptor" && kind != "from_ef" {
            continue;
        }
        let name = cell["template"].as_str().unwrap();
        assert_eq!(
            cell["sign"]["error"], template_words,
            "{name} {kind}: the reference refuses"
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let mut t = build_template_cell(&cell);
        t.inputs_mut()[0].set_unlocking_script_template(template(name, &calls));
        assert_eq!(sign(&mut t), Ok(()), "{name} {kind}: signed here (stated)");
        if name == "OverlayAdminTokenTemplate" {
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{kind}: the template ran");
        } else {
            let unlocking = t.inputs()[0].unlocking_script.as_ref().unwrap();
            assert!(
                !unlocking.to_binary().is_empty(),
                "{name} {kind}: a signature"
            );
        }
        held += 1;
    }
    assert_eq!(held, 8);
}

#[test]
fn a_descriptor_signed_here_is_the_reference_signature_for_the_named_outpoint_alone_848() {
    // The reference signs a claimed outpoint with no linked source, the amount
    // and script handed to the template (`named_alone`); this crate signs the
    // same outpoint through `add_input_from`'s descriptor. The unlocking
    // scripts are the same bytes: the preimage is the named outpoint's.
    let mut held = 0;
    for control in template_cells()
        .iter()
        .filter(|c| c["cell"] == "named_alone")
    {
        let name = control["template"].as_str().unwrap();
        let expected = control["sign"]["ok"].as_str().unwrap();
        let descriptor = template_cells()
            .into_iter()
            .find(|c| c["template"] == name && c["cell"] == "descriptor")
            .unwrap();
        let mut t = build_template_cell(&descriptor);
        t.inputs_mut()[0].set_unlocking_script_template(template(name, &Arc::default()));
        sign(&mut t).unwrap();
        let unlocking = t.inputs()[0].unlocking_script.as_ref().unwrap().to_binary();
        assert_eq!(to_hex(&unlocking), expected, "{name}");
        held += 1;
    }
    assert_eq!(held, 2, "P2PKH and PushDrop take the amount and script");
}

#[test]
fn a_complete_source_under_another_txid_is_refused_before_any_template_as_the_reference_does_848() {
    let mut held = 0;
    for cell in template_cells().iter().filter(|c| c["cell"] == "complete") {
        let name = cell["template"].as_str().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut t = build_template_cell(cell);
        t.inputs_mut()[0].set_unlocking_script_template(template(name, &calls));
        assert_eq!(
            sign(&mut t).map(|_| Value::Null),
            recorded(&cell["sign"]),
            "{name}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{name}");
        held += 1;
    }
    assert_eq!(held, 4);
}

#[test]
fn a_named_outpoint_without_a_source_is_not_signed_here_stated_848() {
    // The reference's `named_alone` signs (the amount and script are the
    // template's arguments); a template here takes a `SigningContext`, whose
    // amount and script `sign` reads from the linked source.
    for control in template_cells()
        .iter()
        .filter(|c| c["cell"] == "named_alone")
    {
        let name = control["template"].as_str().unwrap();
        assert!(
            control["sign"]["ok"].is_string(),
            "{name}: the reference signs"
        );
        let mut t = build_template_cell(control);
        t.inputs_mut()[0].set_unlocking_script_template(template(name, &Arc::default()));
        assert_eq!(
            sign(&mut t),
            Err("transaction error: Input 0 is missing source satoshis for signing".to_string()),
            "{name}"
        );
    }
}

// ---- verify's two refusals ------------------------------------------------

/// The recorder's `verify_fold` cells, by name.
fn build_verify_cell(cell: &str) -> Transaction {
    let complete = || middle(root("11", 1000, 1), 900);
    match cell {
        "unlinked_named_reachable" => {
            let b = root("22", 1000, 2);
            let mut unlinked = TransactionInput::new(b.txid(), 0);
            unlinked.unlocking_script = empty();
            child(vec![unlinked, link(b, None, 1)])
        }
        "unlinked_unreachable" => {
            let mut unlinked = TransactionInput::new(other().parse().unwrap(), 0);
            unlinked.unlocking_script = empty();
            child(vec![unlinked])
        }
        "absent_source_amount" => {
            let mut s = complete();
            s.outputs_mut()[0].satoshis = None;
            child(vec![link(s, None, 0)])
        }
        "source_amount_past_max" => {
            let mut s = middle(root("11", MAX, 1), 900);
            s.outputs_mut()[0].satoshis = Some(MAX + 1);
            child(vec![link(s, None, 0)])
        }
        "input_total_past_max" => {
            let s = middle(root("11", MAX, 1), MAX);
            let r = middle(root("22", MAX, 1), 1);
            child(vec![link(s, None, 0), link(r, None, 0)])
        }
        "absent_output_amount" => {
            let mut t = child(vec![link(complete(), None, 0)]);
            t.outputs_mut()[0].satoshis = None;
            t
        }
        "output_amount_past_max" => {
            let mut t = child(vec![link(complete(), None, 0)]);
            t.outputs_mut()[0].satoshis = Some(MAX + 1);
            t
        }
        "output_total_past_max" => {
            let mut t = child(vec![link(complete(), None, 0)]);
            t.outputs_mut()[0].satoshis = Some(MAX);
            t.add_output(one(1)).unwrap();
            t
        }
        "absent_output_amount_and_mismatch" => {
            let mut t = child(vec![link(complete(), Some(other()), 0)]);
            t.outputs_mut()[0].satoshis = None;
            t
        }
        "absent_source_amount_and_mismatch" => {
            let mut s = complete();
            s.outputs_mut()[0].satoshis = None;
            child(vec![link(s, Some(other()), 0)])
        }
        other => panic!("cell {other} recorded"),
    }
}

fn verify_cell(name: &str) -> Value {
    doc()["verify_fold"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cell"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("cell {name} recorded"))
}

fn assert_verify_cell(name: &str) {
    let cell = verify_cell(name);
    let t = build_verify_cell(name);
    assert_eq!(
        cell["built"]["hex"].as_str().unwrap(),
        t.to_hex(),
        "{name}: the bytes"
    );
    assert_eq!(
        verify(&t).map(Value::Bool),
        recorded(&cell["verify_tracker"]),
        "{name}"
    );
}

#[test]
fn every_verify_fold_cell_is_recorded_and_answered_as_the_reference_answers_848() {
    let cells = doc()["verify_fold"].as_array().unwrap().clone();
    assert_eq!(cells.len(), 10);
    for cell in cells {
        assert_verify_cell(cell["cell"].as_str().unwrap());
    }
}

#[test]
fn an_input_that_links_nothing_is_refused_though_its_txid_is_another_inputs_source_848() {
    // Until the fold `Ok(true)`: input 0 names B, links nothing, and was judged
    // against the B input 1 links.
    assert_verify_cell("unlinked_named_reachable");
    let t = build_verify_cell("unlinked_named_reachable");
    assert_eq!(
        verify(&t),
        Err(format!(
            "transaction error: Verification failed because the input at index 0 of transaction {} \
             is missing an associated source transaction. This source transaction is required for \
             transaction verification because there is no merkle proof for the transaction spending \
             a UTXO it contains.",
            t.id()
        ))
    );
    // `Input 0 has no source transaction` until the fold.
    assert_verify_cell("unlinked_unreachable");
}

#[test]
fn an_absent_source_or_output_amount_is_refused_at_verify_where_it_was_read_as_zero_848() {
    for name in [
        "absent_source_amount",
        "absent_output_amount",
        "absent_output_amount_and_mismatch",
        "absent_source_amount_and_mismatch",
    ] {
        assert_verify_cell(name);
    }
}

#[test]
fn an_amount_or_a_total_past_21e14_is_refused_at_verify_in_the_reference_words_848() {
    for name in [
        "source_amount_past_max",
        "input_total_past_max",
        "output_amount_past_max",
        "output_total_past_max",
    ] {
        assert_verify_cell(name);
    }
}

#[test]
fn the_mismatch_sentence_names_input_1_at_input_1_848() {
    // The strength read's pin: the index in `verify`'s sentence at a non-zero
    // input, by equality.
    let complete = || middle(root("11", 1000, 1), 900);
    let t = child(vec![
        link(complete(), None, 0),
        link(middle(root("22", 1000, 1), 900), Some(other()), 0),
    ]);
    assert_eq!(
        verify(&t),
        Err(format!(
            "transaction error: Verification failed because input 1 of transaction {} does not \
             reference its supplied source transaction.",
            t.id()
        ))
    );
}

#[test]
fn a_beef_spending_one_parent_twice_links_every_input_and_still_verifies_848() {
    // The survey of what reaches the unlinked refusal: `from_beef` links every
    // input whose source the BEEF holds, the second spend of one parent by a
    // stub of the same id, so the copy `verify` judges has every input linked
    // and the refusal moves no verdict on a BEEF the readers accept.
    let p = middle(root("11", 1000, 1), 900);
    let mut p2 = Transaction::new();
    p2.add_input(link(p.clone(), None, 0)).unwrap();
    p2.add_output(one(400)).unwrap();
    p2.add_output(one(400)).unwrap();
    let t = child(vec![link(p2.clone(), None, 0), link(p2, None, 1)]);
    let beef = t.to_beef(false).unwrap();
    let read = Transaction::from_beef(&beef, None).unwrap();
    // The second spend of `p2` links a stub of `p2`'s id (its own inputs
    // unlinked); `verify` judges `p2` by the copy whose inputs are linked, so
    // the refusal of an unlinked input is never reached here.
    let stub = read.inputs()[1].source_transaction.as_deref().unwrap();
    assert_eq!(
        stub.id(),
        read.inputs()[0].source_transaction.as_deref().unwrap().id()
    );
    assert_eq!(verify(&read), Ok(true));
    let mut parsed = Beef::from_binary(&beef).unwrap();
    assert!(parsed.verify_valid(false).valid);
}
