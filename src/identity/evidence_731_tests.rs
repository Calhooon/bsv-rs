#![cfg(test)]
//! #731: an Atomic subject written twice, judged by its later entry. Each
//! BEEF of `tests/vectors/identity_evidence_731.json` (recorded under Node
//! v22.18.0 by `tests/support/identity_evidence_731.mjs`) rebuilt by this
//! crate's writer (`tests/support/identity_evidence_731.rs`) to the
//! recorded SHA-256: an Atomic prefix naming X, X written raw and txid-only
//! in both orders, X proven by its own BUMP or unproven over a proven
//! parent. The reference keeps every entry in the order written
//! (`ts-stack@edf6e03` `Beef.ts:1263-1265`), indexes them by `Map.set` in
//! order, the later entry of a txid winning (`#rebuildTxIndexes`,
//! `:516-524`), and loads the atomic txid through `findAtomicTransaction`
//! (`:639-645`; `TransactionEvidence.ts:118-121`): raw then txid-only is
//! `invalid-evidence` at `:120-121`, the output skipped; txid-only then raw
//! reads X. Here `Beef::from_binary`'s collect mode pushes each element as
//! yielded (`beef/collect.rs`, `push_tx` setting the txid's index to the new
//! position, `beef.rs`), so the same. A refactor keeping the earlier entry,
//! picking the raw one for the target, or reordering a repeated txid's
//! entries in the collect mode swaps these verdicts or the wire order.

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};

#[path = "../../tests/support/identity_evidence_731.rs"]
mod build;

/// The shape `name` rebuilt to the recorded bytes.
fn rebuilt(name: &str) -> (Vec<u8>, String, serde_json::Value) {
    let case = build::case(name);
    let built = build::build(name);
    assert_eq!(
        (built.beef.len() as u64, to_hex(&sha256(&built.beef))),
        (
            case["beef_bytes"].as_u64().unwrap(),
            case["beef_sha256"].as_str().unwrap().to_string()
        ),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        built.beef,
        crate::primitives::from_hex(case["beef"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        built.subject,
        case["subject_txid"].as_str().unwrap(),
        "{name}"
    );
    (built.beef, built.subject, case)
}

/// A parsed entry in the recorder's `wire_order` words.
fn entry_words(entry: &BeefTx) -> String {
    let v = build::vector();
    let txid = entry.txid();
    let name = ["alone", "parent", "subject"]
        .into_iter()
        .find(|n| v[format!("{n}_txid")].as_str() == Some(txid.as_str()))
        .map(str::to_string)
        .unwrap_or(txid);
    let only = if entry.is_txid_only() {
        " (txid only)"
    } else {
        ""
    };
    let bump = entry
        .bump_index()
        .map(|i| format!(" (BUMP {i})"))
        .unwrap_or_default();
    format!("{name}{only}{bump}")
}

/// One shape: the entries held in the written order, the later entry of X
/// the index's, `parse_evidence` and `admit` the reference's verdict.
fn judged_as_recorded(name: &str) {
    let (beef, x, case) = rebuilt(name);
    let parsed = sdk::transaction::Beef::from_binary(&beef).unwrap();
    assert_eq!(parsed.atomic_txid.as_deref(), Some(x.as_str()), "{name}");
    let wire: Vec<String> = parsed.txs.iter().map(entry_words).collect();
    let recorded: Vec<String> = case["wire_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        wire, recorded,
        "{name}: both entries of X, in the written order"
    );
    let held = parsed.find_txid(&x).unwrap();
    let index_entry = if held.is_txid_only() {
        "txid only"
    } else {
        "raw"
    };
    assert_eq!(
        index_entry,
        case["index_entry"].as_str().unwrap(),
        "{name}: the index's entry"
    );
    let later = parsed.txs.iter().rev().find(|e| e.txid() == x).unwrap();
    assert_eq!(
        held.is_txid_only(),
        later.is_txid_only(),
        "{name}: the later entry"
    );

    let selected = case["selected_txid"].as_str().unwrap();
    match parse_evidence(&beef, 0) {
        Ok(tx) => {
            assert_eq!(tx.id(), selected, "{name}");
            assert_eq!(tx.id(), x, "{name}");
            assert!(case["refused_at"].is_null(), "{name}");
        }
        Err(r) => {
            assert_eq!(
                format!("refused: Transaction evidence: {}", r.code.as_str()),
                selected,
                "{name}"
            );
            assert_eq!(r, invalid("TransactionEvidence.ts:120-121"), "{name}");
            let refused_at = case["refused_at"].as_str().unwrap();
            assert_eq!(
                refused_at,
                format!("{}: findAtomicTransaction({x}) is undefined", r.site),
                "{name}"
            );
        }
    }
    let output = OutputListItem {
        beef,
        output_index: case["output_index"].as_u64().unwrap() as u32,
        context: None,
        txid: None,
    };
    let expected = match case["outcome"].as_str().unwrap() {
        "read" => Some(x),
        "skipped" => None,
        other => panic!("{name}: unexpected outcome {other}"),
    };
    assert_eq!(
        admit(&output, &Default::default()).map(|t| t.map(|t| t.id())),
        Ok(expected),
        "{name}"
    );
}

#[test]
fn the_vector_holds_the_four_shapes_731() {
    assert_eq!(
        build::names(),
        [
            "proven_subject_raw_then_txid_only",
            "proven_subject_txid_only_then_raw",
            "unproven_subject_raw_then_txid_only",
            "unproven_subject_txid_only_then_raw",
        ]
    );
}

#[test]
fn an_atomic_subject_written_raw_then_txid_only_is_skipped_by_its_later_entry_731() {
    judged_as_recorded("proven_subject_raw_then_txid_only");
}

#[test]
fn an_atomic_subject_written_txid_only_then_raw_is_read_by_its_later_entry_731() {
    judged_as_recorded("proven_subject_txid_only_then_raw");
}

#[test]
fn an_unproven_atomic_subject_written_raw_then_txid_only_is_skipped_by_its_later_entry_731() {
    judged_as_recorded("unproven_subject_raw_then_txid_only");
}

#[test]
fn an_unproven_atomic_subject_written_txid_only_then_raw_is_read_by_its_later_entry_731() {
    judged_as_recorded("unproven_subject_txid_only_then_raw");
}
