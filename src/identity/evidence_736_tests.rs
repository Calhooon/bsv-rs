#![cfg(test)]
//! #736: the evidence check's graph-wide pins. Each BEEF of
//! `tests/vectors/identity_evidence_736.json` rebuilt by this crate's writer
//! (`tests/support/identity_evidence_736.rs`) to the recorded SHA-256 and
//! judged by [`parse_evidence`] to the reference `parseEvidence`'s code and
//! line (`ts-stack@edf6e03` `TransactionEvidence.ts`, recorded under Node
//! v22.18.0 by `tests/support/identity_evidence_736.mjs`), or to its
//! selected txid: the inputs and script-bytes bounds as running sums over
//! the visited graph (`:166-171`, a proven transaction's scripts and inputs
//! counted before its proof ends the branch at `:173`), and one parent
//! written raw and txid-only, the later entry the index's on both sides
//! (`Beef.#rebuildTxIndexes`, `Beef.ts:516-524`; `Beef::rebuild_index`).
//! A refactor counting per transaction, or an index keeping the earlier
//! entry, reads the over-bound shapes or swaps the two orders' verdicts.

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};

#[path = "../../tests/support/identity_evidence_736.rs"]
mod build;

/// The recorded code, or `None` for a read.
fn code_of(case: &serde_json::Value) -> Option<Code> {
    match case["code"].as_str() {
        None => None,
        Some("invalid-evidence") => Some(Code::InvalidEvidence),
        Some("limit") => Some(Code::Limit),
        Some(other) => panic!("unknown code {other}"),
    }
}

/// `parse_evidence`'s answer as the vector writes it: the code and line, or
/// the selected txid.
fn judged(bytes: &[u8], output_index: u32) -> (Option<Code>, Option<String>, String) {
    match parse_evidence(bytes, output_index) {
        Ok(tx) => (None, None, tx.id()),
        Err(r) => (
            Some(r.code),
            Some(r.site.to_string()),
            format!("refused: Transaction evidence: {}", r.code.as_str()),
        ),
    }
}

/// The shape `name` rebuilt to the recorded bytes.
fn rebuilt(name: &str) -> (Vec<u8>, serde_json::Value) {
    let case = build::case(name);
    let built = build::build(name, case["size"].as_u64().map(|n| n as usize));
    assert_eq!(
        (built.beef.len() as u64, to_hex(&sha256(&built.beef))),
        (
            case["beef_bytes"].as_u64().unwrap(),
            case["beef_sha256"].as_str().unwrap().to_string()
        ),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        built.subject,
        case["subject_txid"].as_str().unwrap(),
        "{name}"
    );
    (built.beef, case)
}

#[test]
fn each_736_shape_is_judged_as_the_reference_parse_evidence_judges_it_736() {
    let v = build::vector();
    let shapes = v["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 6);
    for case in shapes {
        let name = case["name"].as_str().unwrap();
        let (beef, _) = rebuilt(name);
        let index = case["output_index"].as_u64().unwrap() as u32;
        let (code, site, selected) = judged(&beef, index);
        assert_eq!(code, code_of(case), "{name}: the code");
        assert_eq!(site.as_deref(), case["site"].as_str(), "{name}: the line");
        assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
    }
}

/// Every transaction of the BEEF inside both bounds alone, so only the
/// running sum crosses them: the sums over all of them.
fn each_alone_within_bounds(beef: &[u8]) -> (usize, usize) {
    let parsed = sdk::transaction::Beef::from_binary(beef).unwrap();
    let (mut inputs, mut scripts) = (0, 0);
    for entry in &parsed.txs {
        let tx = entry.tx().unwrap();
        assert!(tx.inputs.len() <= INPUTS, "{}: inputs alone", tx.id());
        assert!(
            graph_script_bytes(tx) <= SCRIPT_BYTES,
            "{}: script bytes alone",
            tx.id()
        );
        inputs += tx.inputs.len();
        scripts += graph_script_bytes(tx);
    }
    (inputs, scripts)
}

/// 2048 inputs at the unproven subject and 2049 at its unproven parent
/// (the proven grandparent has none): 4097 over the graph refuses at the
/// parent (`:170-171`, `limit`); 2048 and 2048 read. Neither transaction
/// crosses 4096 alone.
#[test]
fn the_inputs_bound_is_a_sum_over_the_unconfirmed_graph_736() {
    for (name, total) in [
        ("graph_inputs_over_bound", INPUTS + 1),
        ("graph_inputs_at_bound", INPUTS),
    ] {
        let (beef, case) = rebuilt(name);
        assert_eq!(each_alone_within_bounds(&beef).0, total, "{name}");
        let refused = parse_evidence(&beef, 0).err();
        assert_eq!(refused.map(|r| r.code), code_of(&case), "{name}");
    }
}

/// The unproven subject's scripts 131072 bytes, its PROVEN parent's 131073
/// (131072): the parent's scripts count (`graphScriptBytes` over every
/// visited transaction, `:168`), so the sum 262145 refuses and 262144
/// reads. Neither transaction crosses 262144 alone.
#[test]
fn a_proven_parent_s_scripts_count_toward_the_script_bytes_bound_736() {
    for (name, total) in [
        ("graph_script_bytes_over_bound", SCRIPT_BYTES + 1),
        ("graph_script_bytes_at_bound", SCRIPT_BYTES),
    ] {
        let (beef, case) = rebuilt(name);
        let parsed = sdk::transaction::Beef::from_binary(&beef).unwrap();
        let parent = parsed.txs.iter().find(|e| e.bump_index().is_some());
        assert!(parent.is_some(), "{name}: the parent proven");
        assert_eq!(each_alone_within_bounds(&beef).1, total, "{name}");
        let refused = parse_evidence(&beef, 0).err();
        assert_eq!(refused.map(|r| r.code), code_of(&case), "{name}");
    }
}

/// One parent written raw and txid-only: the BEEF holds both entries, the
/// index the later one, as the reference's `#rebuildTxIndexes` keeps it.
/// Raw then txid-only leaves the subject's input without a source (`:143`,
/// skipped); txid-only then raw links it (read).
#[test]
fn a_parent_written_twice_is_read_by_its_later_entry_736() {
    let parent = build::vector()["twice_parent_txid"]
        .as_str()
        .unwrap()
        .to_string();
    for (name, raw_wins) in [
        ("parent_raw_then_txid_only", false),
        ("parent_txid_only_then_raw", true),
    ] {
        let (beef, case) = rebuilt(name);
        let parsed = sdk::transaction::Beef::from_binary(&beef).unwrap();
        let held: Vec<bool> = parsed
            .txs
            .iter()
            .filter(|e| e.txid() == parent)
            .map(|e| e.tx().is_some())
            .collect();
        assert_eq!(held.len(), 2, "{name}: both entries held");
        assert_eq!(
            parsed.find_txid(&parent).unwrap().tx().is_some(),
            raw_wins,
            "{name}: the index's entry"
        );
        let output = OutputListItem {
            beef,
            output_index: 0,
            context: None,
            txid: None,
        };
        let expected = match case["outcome"].as_str().unwrap() {
            "read" => Some(case["subject_txid"].as_str().unwrap().to_string()),
            _ => None,
        };
        assert_eq!(
            admit(&output, &Default::default()).map(|t| t.map(|t| t.id())),
            Ok(expected),
            "{name}"
        );
    }
}
